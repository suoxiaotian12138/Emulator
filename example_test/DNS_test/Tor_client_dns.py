import asyncio
from queue import Queue
from typing import Literal, Any
from dataclasses import dataclass
import ipaddress
import time
import contextlib
import uuid
from collections import deque
from tools.Log.stream_tracker import StreamTracker
from tools.Log.utils import HopTimer, classify_exception, FailReason

from network_src.TorCore.Tor_base import Tor_base
from network_src.TorCore.Tor_Circuit import Tor_CircuitsList
from network_src.TorCore.Tor_Consensus import Tor_Consensus
from network_src.TorCore.Tor_Router import Tor_Router
from network_src.TorCore.Tor_Socket import Tor_Socket
from network_src.TorCore.Tor_Cell import *

from network_src.TorCore.Tor_Circuit import CircuitManager, MAX_CIRCUIT_AGE_S, \
    MAX_STREAMS_PER_CIRCUIT, IDLE_TIMEOUT_S, PREBUILD_OPEN, compute_isolation_key
from tools.Network_Management.bandwidth_env import get_limiter
from tools.Network_Management.delay_env import get_args


@dataclass(frozen=True)
class ResolvedAnswer:
    answer_type: int
    value: Any
    ttl: int


@dataclass(frozen=True)
class ResolveResult:
    query: str
    answers: tuple[ResolvedAnswer, ...]

    @property
    def ipv4(self) -> tuple[ResolvedAnswer, ...]:
        return tuple(a for a in self.answers if a.answer_type == CellRelayResolved.TYPE_IPV4)

    @property
    def ipv6(self) -> tuple[ResolvedAnswer, ...]:
        return tuple(a for a in self.answers if a.answer_type == CellRelayResolved.TYPE_IPV6)

    @property
    def hostnames(self) -> tuple[ResolvedAnswer, ...]:
        return tuple(a for a in self.answers if a.answer_type == CellRelayResolved.TYPE_HOSTNAME)


class TorResolveError(RuntimeError):
    def __init__(self, hostname: str, *, transient: bool, message: str = "Error resolving hostname"):
        super().__init__(message)
        self.hostname = hostname
        self.transient = bool(transient)


@dataclass
class _PendingResolve:
    request_id: str
    hostname: str
    channel_id: str
    circuit: Any
    stream_id: int
    future: asyncio.Future
    created_at: float
    record: dict[str, Any]

class Tor_Client(Tor_base):
    def __init__(self, name: str, host: str, port: int, model: Literal["sim", "real"] = "sim", sim_ip: str | None = None):
        super().__init__(name, host, port, model)
        self.output_buffer = Queue()

        self.consensus = Tor_Consensus(model, self.dire_ip, self.dire_port)
        self.guard = None

        self.circuit_list = Tor_CircuitsList()
        self.ready_to_send = asyncio.Event()
        self.stream_tracker = StreamTracker()     # ★ 新增
        self._sid2uid: dict[tuple[int, int], str] = {}
        self._pending_resolves: dict[tuple[int, int], _PendingResolve] = {}
        self._resolve_records: dict[str, dict[str, Any]] = {}
        self._resolve_record_order = deque(maxlen=10000)
        self.resolve_metrics = {
            "unmatched_response_count": 0,
            "duplicate_response_count": 0,
            "stream_id_conflict_count": 0,
            "unexpected_teardown_count": 0,
        }
        self._locally_closing_circuits: set[int] = set()
        self.circuit_mgr = CircuitManager(self, isolation_enabled=True)

        self.sim_ip = sim_ip or "9.9.9.9"

    def _register_task(self, name: str, coro):
        task = self._spawn_bg_task(coro, name=name)
        self.tasks[name] = task
        task.add_done_callback(lambda _t, key=name: self.tasks.pop(key, None))

    async def start_protocol(self):
        try:
            self.print("[Start] start_protocol begin")
            self._register_task(f"{self.name}.listener", self.monitor_tor_socket())
            await self.consensus_init()

            # self._register_task(f"{self.name}.prebuild", self.circuit_mgr.maintain_prebuild())
            self._register_task(f"{self.name}.housekeeping", self._circuit_housekeeping())

            await asyncio.gather(*self.tasks.values())
        except asyncio.CancelledError:
            # 让 stop_protocol 来做最终清理也行，但这里至少不要吞
            raise
        finally:
            # ★确保退出时真正清理
            with contextlib.suppress(Exception):
                await self.stop_protocol()

    async def _circuit_housekeeping(self):
        while True:
            self.circuit_mgr.tick()
            await asyncio.sleep(1.0)

    async def consensus_init(self):
        await self.consensus.consus_init_async()
        guard = self.consensus.get_random_guard_node()
        self.guard = Tor_Router(guard)

        desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
        self.guard.set_descriptor(desc)
        limiter = get_limiter(self.node_id)
        socket = Tor_Socket(
            self.host,
            on_cell=self.handle_cell,
            node_id=self.node_id,
            limiter=limiter,
            **get_args(sim_ip=self.sim_ip)
        )

        #和guard的tls握手记录
        await socket.setup_socket(remote_addr=self.guard.addr)
        self._ev("tls_handshake_done", peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client")

        self._spawn_bg_task(self.handle_connection(self.guard.addr, socket))
        await socket.listen_started.wait()
        #和guard的tor握手
        await socket.tor_handshake_client()
        await socket.handshake_done.wait()
        self._ev("tor_handshake_done", peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", versions=[3, 4], auth="none")

        self.ready_to_send.set()

    @staticmethod
    def _normalize_resolve_name(hostname: str) -> str:
        if not isinstance(hostname, str):
            raise TypeError("hostname must be a string")
        hostname = hostname.strip()
        if not hostname or "\x00" in hostname:
            raise ValueError("invalid hostname")
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None:
            return str(literal)
        try:
            normalized = hostname.encode("idna").decode("ascii").rstrip(".").lower()
        except UnicodeError as exc:
            raise ValueError("invalid internationalized hostname") from exc
        if not normalized or len(normalized) > 253:
            raise ValueError("hostname length is invalid")
        labels = normalized.split(".")
        if any(not label or len(label) > 63 for label in labels):
            raise ValueError("hostname label is invalid")
        return normalized

    @staticmethod
    def _channel_id(socket) -> str:
        channel = getattr(socket, "channel", None)
        for attr in ("channel_uid", "uid", "id", "channel_id"):
            value = getattr(channel, attr, None)
            if value is not None and not callable(value):
                return str(value)
        # Process-local fallback only; stable for the lifetime of this channel object.
        return f"py:{id(channel)}"

    def get_resolve_record(self, request_id: str) -> dict[str, Any] | None:
        record = self._resolve_records.get(request_id)
        return dict(record) if record is not None else None

    def get_resolve_snapshot(self) -> dict[str, Any]:
        reserved = len(self._pending_resolves)
        return {
            **self.resolve_metrics,
            "pending_request_count": reserved,
            "completed_record_count": len(self._resolve_records),
            "active_request_count": sum(m.n_streams for m in self.circuit_mgr.pool.values()),
        }

    def _store_resolve_record(self, record: dict[str, Any]) -> None:
        request_id = record["request_id"]
        if request_id not in self._resolve_records:
            self._resolve_record_order.append(request_id)
        self._resolve_records[request_id] = dict(record)
        while len(self._resolve_records) > self._resolve_record_order.maxlen:
            oldest = self._resolve_record_order.popleft()
            self._resolve_records.pop(oldest, None)
        self._ev("dns_request_complete", **record)

    async def resolve_hostname(
        self,
        hostname: str,
        *,
        hops_count: int = 3,
        extend_routers=None,
        timeout: float = 5.0,
        request_id: str | None = None,
    ) -> ResolveResult:
        """Resolve a hostname through the circuit exit using RELAY_RESOLVE."""
        await self.ready_to_send.wait()
        normalized = self._normalize_resolve_name(hostname)
        socket = self.socket_map.get(self.guard.addr, None)
        if socket is None:
            raise RuntimeError("no socket to guard")

        request_id = request_id or f"{self.name}:{uuid.uuid4().hex}"
        started_ns = time.perf_counter_ns()
        iso_key = f"dns:{normalized}" if self.circuit_mgr.isolation_enabled else "general"
        circuit = await self.circuit_mgr.get_or_build(
            iso_key, exit_hint=None, hops_count=hops_count, extend_routers=extend_routers,
        )
        stream_id = circuit.allocate_request_stream_id()
        self.circuit_mgr.acquire_request(circuit)
        key = (circuit.id, stream_id)
        if key in self._pending_resolves:
            self.resolve_metrics["stream_id_conflict_count"] += 1
            circuit.release_request_stream_id(stream_id)
            self.circuit_mgr.release_request(circuit)
            raise RuntimeError(f"DNS stream ID conflict: circuit={circuit.id} stream={stream_id}")

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        record: dict[str, Any] = {
            "request_id": request_id,
            "client_id": self.name,
            "domain": normalized,
            "channel_id": self._channel_id(socket),
            "circuit_id": circuit.id,
            "stream_id": stream_id,
            "isolation_key": iso_key,
            "request_start_ns": started_ns,
            "encode_time_ns": None,
            "enqueue_time_ns": None,
            "send_time_ns": None,
            "response_time_ns": None,
            "completion_time_ns": None,
            "encode_duration_ms": None,
            "queue_duration_ms": 0.0,
            "response_latency_ms": None,
            "total_latency_ms": None,
            "queue_bypassed": True,
            "answers": [],
            "response_type": None,
            "response_value": None,
            "TTL": None,
            "completion_status": None,
            "error_category": None,
            "error_message": None,
            "response_match_count": 0,
            "duplicate_response": False,
            "unmatched_response": False,
            "stream_released": False,
            "pending_removed": False,
            "circuit_state_after": None,
            "unexpected_teardown": False,
        }
        pending = _PendingResolve(
            request_id=request_id, hostname=normalized, channel_id=record["channel_id"],
            circuit=circuit, stream_id=stream_id, future=future,
            created_at=time.perf_counter(), record=record,
        )
        self._pending_resolves[key] = pending

        result = None
        caught = None
        try:
            encode_start_ns = time.perf_counter_ns()
            inner = CellRelayResolve(hostname=normalized, circuit_id=circuit.id)
            relay = circuit.make_relay(inner_cell=inner, relay_type=CellRelay, stream_id=stream_id)
            record["encode_time_ns"] = time.perf_counter_ns()
            record["encode_duration_ms"] = (record["encode_time_ns"] - encode_start_ns) / 1_000_000.0
            record["enqueue_time_ns"] = time.perf_counter_ns()
            record["send_time_ns"] = record["enqueue_time_ns"]
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=stream_id,
                request_id=request_id, peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
                side="client", dir="send", cell_cmd="RELAY_RESOLVE",
            )
            await socket.send_cell(relay)
            result = await asyncio.wait_for(future, timeout=timeout)
            record["completion_status"] = "success"
            return result
        except asyncio.TimeoutError as exc:
            caught = exc
            record["completion_status"] = "timeout"
            record["error_category"] = "timeout"
            record["error_message"] = str(exc) or f"timeout after {timeout}s"
            raise
        except TorResolveError as exc:
            caught = exc
            record["completion_status"] = "dns_error_transient" if exc.transient else "dns_error_nontransient"
            record["error_category"] = record["completion_status"]
            record["error_message"] = str(exc)
            raise
        except asyncio.CancelledError as exc:
            caught = exc
            record["completion_status"] = "cancelled"
            record["error_category"] = "cancelled"
            record["error_message"] = "request cancelled"
            raise
        except ConnectionResetError as exc:
            caught = exc
            record["completion_status"] = "circuit_destroyed"
            record["error_category"] = "circuit_destroyed"
            record["error_message"] = str(exc)
            raise
        except Exception as exc:
            caught = exc
            record["completion_status"] = "internal_error"
            record["error_category"] = type(exc).__name__
            record["error_message"] = str(exc)
            raise
        finally:
            current = self._pending_resolves.pop(key, None)
            record["pending_removed"] = current is not None
            if current is not None and not current.future.done():
                current.future.cancel()
            circuit.release_request_stream_id(stream_id)
            record["stream_released"] = True
            self.circuit_mgr.release_request(circuit)
            meta = self.circuit_mgr.pool.get(circuit.id)
            record["circuit_state_after"] = meta.state if meta is not None else "REMOVED"
            completed_ns = time.perf_counter_ns()
            record["completion_time_ns"] = completed_ns
            record["total_latency_ms"] = (completed_ns - started_ns) / 1_000_000.0
            if record["response_time_ns"] is not None and record["send_time_ns"] is not None:
                record["response_latency_ms"] = (
                    record["response_time_ns"] - record["send_time_ns"]
                ) / 1_000_000.0
            self._store_resolve_record(record)
            if caught is not None:
                with contextlib.suppress(Exception):
                    setattr(caught, "request_id", request_id)
                    setattr(caught, "request_record", dict(record))

    async def resolve_ipv4(
        self,
        hostname: str,
        *,
        hops_count: int = 3,
        extend_routers=None,
        timeout: float = 5.0,
    ) -> str:
        result = await self.resolve_hostname(
            hostname,
            hops_count=hops_count,
            extend_routers=extend_routers,
            timeout=timeout,
        )
        if not result.ipv4:
            raise TorResolveError(hostname, transient=False, message="No IPv4 answer returned")
        return str(result.ipv4[0].value)

    def _fail_pending_resolves_for_circuit(self, circuit_id: int, exc: Exception) -> None:
        keys = [key for key in self._pending_resolves if key[0] == circuit_id]
        for key in keys:
            pending = self._pending_resolves.pop(key, None)
            if pending is None:
                continue
            if not pending.future.done():
                pending.future.set_exception(exc)

    async def make_stream(self, message, addr, hops_count=3, extend_routers=None):
        await self.ready_to_send.wait()
        socket = self.socket_map.get(self.guard.addr, None)
        if getattr(self.circuit_mgr, "isolation_enabled", False):
            iso_key = compute_isolation_key(addr[0], addr[1])
        else:
            iso_key = "general"

        circuit = await self.circuit_mgr.get_or_build(
            iso_key, exit_hint=None,
            hops_count=hops_count,
            extend_routers=extend_routers
        )
        self.circuit_mgr.mark_used(circuit)
        stream = circuit.create_stream()

        #记录一下流开始
        stream_id = stream.id
        stream_uid = f"{self.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
        dst = f"{addr[0]}:{addr[1]}"
        self.stream_tracker.start(stream_uid, src=self.name, dst=dst)
        if stream_id is not None:
            self._sid2uid[(circuit.id, stream_id)] = stream_uid

        try:
            connect_cell = stream.make_connect(addr)
            await socket.send_cell(connect_cell)
            await stream.wait_connect_ack()
            self.stream_tracker.mark_connected(stream_uid)

            # -------- stream large payload sending, Tor-like gating --------
            max_payload = RelayedTorCell.MAX_PAYLOD_SIZE
            off = 0
            n = len(message)

            while off < n:
                # 1) 先拿流级 credit (只影响本 stream)
                await stream.window.acquire_send(1)

                # 2) 再拿电路级 credit (全局共享, 必须原子)
                if hasattr(circuit, "circ_window_up"):
                    await circuit.circ_window_up.acquire_send(1)

                chunk = message[off: off + max_payload]
                off += len(chunk)

                data_cell = stream.make_relay(CellRelayData(chunk, circuit.id))
                if hasattr(circuit, "circ_window_up") and circuit.circ_window_up.should_record_sendme_sent():
                    digest = getattr(data_cell, "_sendme_digest_forward", None)
                    circuit.record_sendme_expected("up", digest)
                self._ev(
                    "cell_trace", circ_id=circuit.id, stream_id=stream.id,
                    peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client", dir="send",
                    cell_cmd="RELAY_DATA"
                )
                await socket.send_cell(data_cell)



        except asyncio.TimeoutError:
            self.stream_tracker.set_status(stream_uid, "timeout")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise
        except ConnectionResetError:
            self.stream_tracker.set_status(stream_uid, "reset")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise
        except Exception:
            self.stream_tracker.set_status(stream_uid, "error")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise

    async def open_stream(self, addr, hops_count=3, extend_routers=None):
        await self.ready_to_send.wait()

        socket = self.socket_map.get(self.guard.addr, None)
        if socket is None:
            raise RuntimeError("no socket to guard")

        if getattr(self.circuit_mgr, "isolation_enabled", False):
            iso_key = compute_isolation_key(addr[0], addr[1])
        else:
            iso_key = "general"

        circuit = await self.circuit_mgr.get_or_build(
            iso_key, exit_hint=None,
            hops_count=hops_count,
            extend_routers=extend_routers
        )
        self.circuit_mgr.mark_used(circuit)

        stream = circuit.create_stream()

        stream_id = stream.id
        stream_uid = f"{self.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
        dst = f"{addr[0]}:{addr[1]}"
        self.stream_tracker.start(stream_uid, src=self.name, dst=dst)

        if stream_id is not None:
            self._sid2uid[(circuit.id, stream_id)] = stream_uid

        try:
            connect_cell = stream.make_connect(addr)
            await socket.send_cell(connect_cell)
            await stream.wait_connect_ack()
            self.stream_tracker.mark_connected(stream_uid)

        except Exception:
            self.stream_tracker.set_status(stream_uid, "connect_fail")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise

        return circuit, stream

    async def stream_write(self, circuit, stream, data: bytes):
        sent_first = False

        socket = self.socket_map.get(self.guard.addr, None)
        if socket is None:
            raise RuntimeError("no socket to guard")

        max_payload = RelayedTorCell.MAX_PAYLOD_SIZE
        off = 0
        n = len(data)

        while off < n:
            try:
                await asyncio.wait_for(stream.window.acquire_send(1), timeout=5.0)
            except asyncio.TimeoutError:
                self.print(f"[BLOCK] stream.window.acquire_send timeout sid={stream.id} circ={circuit.id}")
                raise

            if hasattr(circuit, "circ_window_up"):
                try:
                    await asyncio.wait_for(circuit.circ_window_up.acquire_send(1), timeout=5.0)
                except asyncio.TimeoutError:
                    self.print(f"[BLOCK] circ_window_up.acquire_send timeout sid={stream.id} circ={circuit.id}")
                    raise

            chunk = data[off: off + max_payload]
            off += len(chunk)
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=stream.id,
                peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client", dir="send",
                cell_cmd="RELAY_DATA"
            )
            relay_cell = stream.make_relay(CellRelayData(chunk, circuit.id))
            if hasattr(circuit, "circ_window_up") and circuit.circ_window_up.should_record_sendme_sent():
                digest = getattr(relay_cell, "_sendme_digest_forward", None)
                circuit.record_sendme_expected("up", digest)
            await socket.send_cell(relay_cell)
            if (not sent_first) and (stream.id is not None):
                stream_uid = self._sid2uid.get((circuit.id, stream.id))
                if stream_uid:
                    self.stream_tracker.mark_first_up(stream_uid)
                sent_first = True

    async def create_circuit(self, hops_count=3, extend_routers=None):
        socket = self.socket_map.get(self.guard.addr)
        if not socket:
            raise RuntimeError("[cirmgr] guard socket not ready")

        # print(f"[create_circuit] begin -> guard {self.guard.addr} hops={hops_count}")
        circuit = await self.circuit_list.create_new_client(socket.channel)
        circuit.apply_sendme_params(self.consensus.params)
        #guard选择记录
        snap = self.consensus.get_consensus_snapshot()
        t0_total = time.perf_counter()
        used_fp = set()
        used_fp.add(self.guard.fingerprint_str)
        if not getattr(self.guard, "descriptor_str", None):
            desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
            self.guard.set_descriptor(desc)

        guard_hop = self.guard.spawn_circuit_hop()

        #电路的第一跳记录
        self._ev("path_step_selected", circ_id=circuit.id, hop=1, nickname=guard_hop.nickname,
                 fp=guard_hop.fingerprint_str, role="guard",
                 consensus_id=snap["consensus_id"])
        create_cell = circuit.make_create2_cell_to_guard(guard_hop)
        self._ev(
            "cell_trace", circ_id=circuit.id, peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
            side="client", dir="send", cell_cmd="CREATE2"
        )
        await socket.send_cell(create_cell)
        await circuit.guard_handsake(wait_time=600)
        self.print("guard is :", self.guard.ip)

        while circuit.nodes_count < hops_count:
            if circuit.nodes_count == hops_count - 1:
                router = self.consensus.get_random_exit_node(exclude=used_fp)
                role = "exit"
                hop = circuit.nodes_count + 1
            else:
                router = self.consensus.get_random_middle_node(exclude=used_fp)
                role = "middle"
                hop = circuit.nodes_count + 1

            used_fp.add(router["fingerprint"])
            self._ev("path_step_selected", circ_id=circuit.id, hop=hop, nickname=router['nickname'],
                     fp=router["fingerprint"], role=role,
                     weight=router.get("bandwidth"),  # 作为权重的近似
                     consensus_id=snap["consensus_id"])

            descriptor_str = await self.consensus.fetch_descriptor(router["fingerprint"])
            extend_node = Tor_Router(router)
            extend_node.set_descriptor(descriptor_str)
            extend_hop = extend_node.spawn_circuit_hop()

            self.print("hop is :", extend_node.ip)

            t_rtt = HopTimer().start()
            try:
                extend_cell = circuit.connect_to_extend(extend_hop)
                self._ev(
                    "cell_trace", circ_id=circuit.id, peer=f"{extend_node.ip}:{extend_node.or_port}",
                    side="client", dir="send", cell_cmd="EXTEND2"
                )
                await socket.send_cell(extend_cell)
                await circuit.extend_handshake(descriptor_str, wait_time=60)
                self._ev("circuit_extend_success", circ_id=circuit.id, hop=hop, nickname=router['nickname'],
                         fp=router["fingerprint"], rtt_ms=t_rtt.ms())
            except Exception as e:
                reason = classify_exception(e).value
                self._ev("circuit_extend_fail", circ_id=circuit.id, hop=hop, nickname=router['nickname'], rtt_ms=t_rtt.ms(),
                         fp=router["fingerprint"], fail_reason=reason, error=str(e))
                # 聚合一条 circuits（失败版）
                self._circuit(circ_id=f"{self.name}:{circuit.id}", client=self.name,
                              guard=guard_hop.fingerprint_str,
                              middle=None, exit=None,
                              build_ms=(time.perf_counter() - t0_total) * 1000.0,
                              success=False, fail_reason=f"extend_hop{hop}:{e}")
                raise

        # ---- 全部完成：写最终 paths + circuits 成功 ----

        guard_fp = circuit.circuit_nodes[0].fingerprint_str
        exit_fp = circuit.circuit_nodes[-1].fingerprint_str

        # 收集所有 middle（可能有多个）
        middles = [n.fingerprint_str for n in circuit.circuit_nodes[1:-1]]
        middle_str = ";".join(middles) if middles else None

        # 写 path 日志
        self._path(client=self.name, guard=guard_fp ,middle=middle_str, exit=exit_fp, wg=1.0, we=1.0, consensus_id=snap["consensus_id"])

        # 写 circuit 日志
        self._circuit(circ_id=f"{self.name}:{circuit.id}", client=self.name, guard=guard_fp, middle=middle_str, exit=exit_fp, build_ms=(time.perf_counter() - t0_total) * 1000.0, success=True)

        return circuit

    async def handle_cell(self, cell, sock):
        # self.print("receive client cell_type:", type(cell))
        # self.print("cell content",cell)
        if isinstance(cell, CellVersions):
            sock.handshake.retrieve_versions(cell)
            # self.print("sock protocol:", sock.protocol.version)
        elif isinstance(cell, CellCerts):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            sock.handshake.recv_authenticate(cell)
        elif isinstance(cell, CellNetInfo):
            sock.handshake.retrieve_net_info(cell)
        elif isinstance(cell, CellCreated2):
            circuit = sock.channel.recv_map.get(cell.circuit_id)
            circuit.created_cell = cell
            self._ev(
                "cell_trace", circ_id=cell.circuit_id, peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
                side="client", dir="recv", cell_cmd="CREATED2"
            )
            circuit.connect_event.set()
        elif isinstance(cell, CellDestroy):
            circuit = sock.channel.recv_map.get(cell.circuit_id) or self.circuit_list.get_by_id(cell.circuit_id)
            if circuit is None:
                return
            locally_expected = circuit.id in self._locally_closing_circuits
            if locally_expected:
                self._locally_closing_circuits.discard(circuit.id)
            else:
                self.resolve_metrics["unexpected_teardown_count"] += 1
                for key, pending in list(self._pending_resolves.items()):
                    if key[0] == circuit.id:
                        pending.record["unexpected_teardown"] = True
            self._ev(
                "circuit_destroy_received", circ_id=circuit.id,
                reason=getattr(cell, "reason", None), expected=locally_expected,
            )
            self._fail_pending_resolves_for_circuit(
                circuit.id, ConnectionResetError(f"circuit {circuit.id} was destroyed"),
            )
            self.circuit_mgr._unregister(circuit.id)
            self.circuit_list.remove(circuit.id)
            with contextlib.suppress(Exception):
                sock.channel.recv_map.pop(cell.circuit_id, None)
        elif isinstance(cell, CellRelay):
            circuit = sock.channel.recv_map.get(cell.circuit_id)
            if circuit is None:
                self.print(f"[client] unknown circuit_id={cell.circuit_id} (relay)")
                return

            try:
                inner_cell = circuit.handle_relay(cell)
            except Exception as e:
                # 关键：别再丢失错误细节，否则你只能看到 prebuild 一直重试
                try:
                    enc = cell.get_encrypted() if hasattr(cell, "get_encrypted") else None
                    self.print(
                        f"[client] RELAY decrypt failed circ={cell.circuit_id} sid={getattr(cell, 'stream_id', None)} "
                        f"checked={getattr(cell, '_checked', None)} enc_len={len(enc) if enc else None} err={repr(e)}")
                except Exception:
                    self.print(f"[client] RELAY decrypt failed circ={cell.circuit_id} err={repr(e)}")
                return

            # # 到这里说明已成功识别出 inner
            # self.print(
            #     f"[client] RELAY decrypted circ={cell.circuit_id} sid={getattr(cell, 'stream_id', None)} inner={type(inner_cell).__name__}")
            await self.handle_cell_relay(inner_cell, circuit, cell)

    async def handle_cell_relay(self, cell, circuit, origin_cell):
        # self.print("inner_cell:", cell)
        if isinstance(cell, CellRelayResolved):
            sid = origin_cell.stream_id
            key = (circuit.id, sid)
            pending = self._pending_resolves.get(key)
            if pending is None:
                self.resolve_metrics["unmatched_response_count"] += 1
                self._ev("resolve_unmatched_response", circ_id=circuit.id, stream_id=sid)
                return
            if pending.future.done():
                self.resolve_metrics["duplicate_response_count"] += 1
                pending.record["duplicate_response"] = True
                self._ev(
                    "resolve_duplicate_response", request_id=pending.request_id,
                    circ_id=circuit.id, stream_id=sid,
                )
                return
            pending.record["response_match_count"] += 1
            pending.record["response_time_ns"] = time.perf_counter_ns()

            error_answers = [
                answer for answer in cell.answers
                if answer[0] in (
                    CellRelayResolved.TYPE_ERROR_TRANSIENT,
                    CellRelayResolved.TYPE_ERROR_NONTRANSIENT,
                )
            ]
            normal_answers = [answer for answer in cell.answers if answer not in error_answers]
            if error_answers and normal_answers:
                if not pending.future.done():
                    pending.future.set_exception(
                        TorResolveError(
                            pending.hostname,
                            transient=False,
                            message="Malformed RESOLVED response mixes errors and answers",
                        )
                    )
                return
            if error_answers:
                transient = error_answers[0][0] == CellRelayResolved.TYPE_ERROR_TRANSIENT
                raw_message = error_answers[0][1]
                if isinstance(raw_message, bytes):
                    message = raw_message.decode("utf-8", errors="replace")
                else:
                    message = str(raw_message)
                if not pending.future.done():
                    pending.future.set_exception(
                        TorResolveError(pending.hostname, transient=transient, message=message)
                    )
                return

            if not cell.answers:
                if not pending.future.done():
                    pending.future.set_exception(
                        TorResolveError(
                            pending.hostname,
                            transient=False,
                            message="Empty RESOLVED response",
                        )
                    )
                return

            answers = tuple(
                ResolvedAnswer(int(answer_type), value, int(ttl))
                for answer_type, value, ttl in cell.answers
            )
            result = ResolveResult(query=pending.hostname, answers=answers)
            pending.record["answers"] = [
                {"response_type": a.answer_type, "response_value": str(a.value), "TTL": a.ttl}
                for a in answers
            ]
            if len(answers) == 1:
                pending.record["response_type"] = answers[0].answer_type
                pending.record["response_value"] = str(answers[0].value)
                pending.record["TTL"] = answers[0].ttl
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=sid,
                request_id=pending.request_id,
                peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
                side="client", dir="recv", cell_cmd="RELAY_RESOLVED",
            )
            if not pending.future.done():
                pending.future.set_result(result)
        elif isinstance(cell, CellRelayExtended2):
            circuit.extended_cell = cell
            self._ev(
                "cell_trace", circ_id=circuit.id, peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
                side="client", dir="recv", cell_cmd="EXTENDED2"
            )
            circuit.connect_event.set()
        elif isinstance(cell, CellRelayConnected):
            # self.print(origin_cell.stream_id)
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=origin_cell.stream_id,
                peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client", dir="recv",
                cell_cmd="RELAY_CONNECTED"
            )
            stream.connect_event.set()
        elif isinstance(cell, CellRelayEnd):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=origin_cell.stream_id,
                peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client", dir="recv",
                cell_cmd="RELAY_END"
            )
            stream.set_end(cell)
            data = await stream.recv_all_until_end(timeout=5.0)

            # === 结束 stream 并写日志 ===
            self.circuit_mgr.on_stream_end(circuit)
            stream_uid = self._sid2uid.pop((circuit.id, origin_cell.stream_id), None)
            if stream_uid:
                rec = self.stream_tracker.end(stream_uid)
                if rec:
                    self._stream(**rec)
            circuit.remove_stream(stream)
            if data:
                # 如果是二进制，建议打印 repr 的前一段，避免控制台爆炸
                self.print("final data: ", data[:200])
            else:
                self.print("final data: <empty>")

        elif isinstance(cell, CellRelayData):
            # --- circuit-level recv window (from guard -> client) ---
            if hasattr(circuit, "circ_window_down"):
                circuit.circ_window_down.on_recv_data_cell(1)
                if circuit.circ_window_down.should_send_sendme():
                    # 电路级 SENDME：stream_id = 0
                    sendme_digest = getattr(origin_cell, "_sendme_digest_backward", None)
                    emit_version = circuit.sendme_emit_min_version
                    if emit_version >= 1 and sendme_digest:
                        sendme_inner = CellRelaySendMe(
                            circuit_id=circuit.id,
                            version=1,
                            digest=sendme_digest,
                        )
                    else:
                        sendme_inner = CellRelaySendMe(circuit_id=circuit.id)
                    circ_sendme = circuit.make_relay(inner_cell=sendme_inner, relay_type=CellRelay, stream_id=0)
                    socket = self.socket_map.get(self.guard.addr, None)
                    if socket is not None:
                        await socket.send_cell(circ_sendme)

            # --- 流级逻辑（你已有的，稍微整理一下） ---
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            if stream is None:
                return

            stream.window.on_recv_data_cell(1)
            stream.append(cell.data)

            stream_uid = self._sid2uid.get((circuit.id, origin_cell.stream_id))
            if stream_uid:
                self.stream_tracker.on_down_chunk(stream_uid, nbytes=len(cell.data))

            if stream.window.should_send_sendme():
                socket = self.socket_map.get(self.guard.addr, None)
                if socket is not None:
                    sendme_cell = stream.make_sendme()
                    await socket.send_cell(sendme_cell)
        elif isinstance(cell, CellRelaySendMe):
            sid = origin_cell.stream_id
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=sid,
                peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client", dir="recv",
                cell_cmd="RELAY_SENDME"
            )
            if sid == 0:
                # ---- circuit-level SENDME ----
                if hasattr(circuit, "circ_window_up"):
                    version = getattr(cell, "version", 0)
                    accept_min = circuit.sendme_accept_min_version
                    if version < 0:
                        self.print(f"[client] invalid SENDME payload circ={circuit.id} sid={sid}")
                        await self.close_circuit(circuit)
                        return
                    if version < accept_min:
                        self.print(
                            f"[client] unacceptable SENDME version={version} "
                            f"min={accept_min} circ={circuit.id} sid={sid}"
                        )
                        await self.close_circuit(circuit)
                        return
                    if version == 1:
                        digest = getattr(cell, "digest", b"")
                        expected = circuit.pop_sendme_expected("up")
                        if not digest:
                            self.print(f"[client] SENDME v1 missing digest circ={circuit.id}")
                            await self.close_circuit(circuit)
                            return
                        if digest != expected:
                            self.print(f"[client] SENDME v1 digest mismatch circ={circuit.id}")
                            await self.close_circuit(circuit)
                            return
                    elif version == 0:
                        # Keep expected digest queue in sync even without validation.
                        circuit.pop_sendme_expected("up")
                    else:
                        self.print(f"[client] unsupported SENDME version={version} circ={circuit.id}")
                        await self.close_circuit(circuit)
                        return
                    circuit.circ_window_up.on_recv_sendme()
            else:
                # ---- stream-level SENDME ----
                stream = circuit.streams.get_by_id(sid)
                if stream is not None:
                    stream.window.on_recv_sendme()

    async def close_stream(self, circuit, stream, wait_end_s: float = 3.0):
        socket = self.socket_map.get(self.guard.addr, None)
        if not socket:
            raise RuntimeError("socket has closed before stream")

        end_cell = stream.make_end()
        await socket.send_cell(end_cell)
        await asyncio.sleep(0)

        # 等对端 END（如果对端实现会回 END）
        if hasattr(stream, "end_event"):
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stream.end_event.wait(), timeout=wait_end_s)

        self.circuit_mgr.on_stream_end(circuit)

        # 对 client 模式，这个 aclose 当前主要清理 server-side 资源，不一定必须
        if hasattr(stream, "aclose"):
            await stream.aclose()
        circuit.remove_stream(stream)

    async def close_circuit(self, circuit):
        self._locally_closing_circuits.add(circuit.id)
        self._fail_pending_resolves_for_circuit(
            circuit.id,
            ConnectionResetError(f"circuit {circuit.id} was closed"),
        )
        socket = self.socket_map.get(self.guard.addr, None)
        if socket is None:
            return

        # 按你项目里的真实类名替换，比如 CellDestroy 或 Relay DESTROY
        try:
            destroy = CellDestroy(circuit_id=circuit.id, reason=0)
            await socket.send_cell(destroy)
            await asyncio.sleep(0)
        except Exception:
            pass



