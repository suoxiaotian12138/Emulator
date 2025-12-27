import asyncio
from queue import Queue
from typing import Literal
import time
import contextlib
from tools.Log.stream_tracker import StreamTracker
from tools.Log.utils import HopTimer, classify_exception, FailReason

from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.Tor_Consensus import Tor_Consensus
from examples.Tor_simplified.Tor_Router import Tor_Router
from examples.Tor_simplified.Tor_Socket import Tor_Socket
from examples.Tor_simplified.Tor_Cell import *

from examples.Tor_simplified.Tor_Circuit import CircuitManager, MAX_CIRCUIT_AGE_S, \
    MAX_STREAMS_PER_CIRCUIT, IDLE_TIMEOUT_S, PREBUILD_OPEN, compute_isolation_key

from tools.Network_Management.delay_env import get_args
class Tor_Client(Tor_base):
    def __init__(self, name: str, host: str, port: int, model: Literal["sim", "real"] = "sim", sim_ip: str | None = None):
        super().__init__(name, host, port, model)
        self.output_buffer = Queue()

        self.consensus = Tor_Consensus(model, self.dire_ip, self.dire_port)
        self.guard = None

        self.circuit_list = Tor_CircuitsList()
        self.ready_to_send = asyncio.Event()
        self.stream_tracker = StreamTracker()     # ★ 新增
        self._sid2uid: dict[int, str] = {}
        self.circuit_mgr = CircuitManager(self)

        self.sim_ip = sim_ip or "9.9.9.9"
    async def start_protocol(self):
        try:
            self.tasks['listener_task'] = self._spawn_bg_task(self.monitor_tor_socket())
            await self.consensus_init()

            self.tasks['prebuild'] = self._spawn_bg_task(self.circuit_mgr.maintain_prebuild())
            self.tasks['housekeeping'] = self._spawn_bg_task(self._circuit_housekeeping())

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
        socket = Tor_Socket(
            self.host,
            on_cell=self.handle_cell,
            node_id=self.node_id,
            limiter=self.limiter,
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
            self._sid2uid[stream_id] = stream_uid

        try:
            connect_cell = stream.make_connect(addr)
            await socket.send_cell(connect_cell)
            await stream.wait_connect_ack()

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
            self._sid2uid[stream_id] = stream_uid

        try:
            connect_cell = stream.make_connect(addr)
            await socket.send_cell(connect_cell)
            await stream.wait_connect_ack()
        except Exception:
            self.stream_tracker.set_status(stream_uid, "connect_fail")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise

        return circuit, stream

    async def stream_write(self, circuit, stream, data: bytes):
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
            await socket.send_cell(stream.make_relay(CellRelayData(chunk, circuit.id)))

    async def create_circuit(self, socket, hops_count=3, extend_routers=None):
        # print(f"[create_circuit] begin -> guard {self.guard.addr} hops={hops_count}")
        circuit = await self.circuit_list.create_new_client(socket.channel)
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
        create_cell = circuit.connect_to_guard(guard_hop)
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
            sock.protocol.version = sock.handshake.retrieve_versions(cell)
            sock.channel.update_version(sock.protocol.version)
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

            # 到这里说明已成功识别出 inner
            self.print(
                f"[client] RELAY decrypted circ={cell.circuit_id} sid={getattr(cell, 'stream_id', None)} inner={type(inner_cell).__name__}")
            await self.handle_cell_relay(inner_cell, circuit, cell)

    async def handle_cell_relay(self, cell, circuit, origin_cell):
        # self.print("inner_cell:", cell)
        if isinstance(cell, CellRelayExtended2):
            self.print(f"[client] EXTENDED2 ok circ={circuit.id} (event set)")
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
            stream_uid = self._sid2uid.pop(origin_cell.stream_id, None)
            if stream_uid:
                rec = self.stream_tracker.end(stream_uid)
                if rec:
                    self._stream(**rec)
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

            stream_uid = self._sid2uid.get(origin_cell.stream_id)
            if stream_uid:
                self.stream_tracker.on_down_chunk(stream_uid, nbytes=len(cell.data))

            if stream.window.should_send_sendme():
                socket = self.socket_map.get(self.guard.addr, None)
                if socket is not None:
                    sendme_cell = stream.make_sendme()
                    await socket.send_cell(sendme_cell)
        elif isinstance(cell, CellRelaySendMe):
            sid = origin_cell.stream_id
            self.print(f"[RECV] SENDME sid={sid} circ={circuit.id}")
            self._ev(
                "cell_trace", circ_id=circuit.id, stream_id=sid,
                peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client", dir="recv",
                cell_cmd="RELAY_SENDME"
            )
            if sid == 0:
                # ---- circuit-level SENDME ----
                if hasattr(circuit, "circ_window_up"):
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

    async def close_circuit(self, circuit):
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



