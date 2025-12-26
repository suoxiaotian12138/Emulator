import asyncio
from queue import Queue

from examples.Tor_simplified.Tor_Stream import StreamsList
from examples.Tor_simplified.Tor_Router import Tor_Router_simple
from examples.Tor_simplified.Tor_Crypt import NtorKeyAgreement

# from torpy.keyagreement import NtorKeyAgreement
from examples.Tor_simplified.Tor_Cell import *
import logging
from collections import deque
from dataclasses import dataclass
from typing import Dict, Set, Optional, Any
import time, asyncio
from examples.Tor_simplified.Tor_Cell import CellDestroy  # 若类名不同，替换为你项目里的 DESTROY cell
from examples.Tor_simplified.Tor_Window import TorWindow


logger = logging.getLogger(__name__)

# circuit_policy.py  (或放到 Tor_Client 顶部)
MAX_CIRCUIT_AGE_S = 600          # 10min
MAX_STREAMS_PER_CIRCUIT = 256
IDLE_TIMEOUT_S = 120              # 2min no new streams
PREBUILD_OPEN = 1                # keep 2 hot OPEN circuits
BUILD_TIMEOUT_S = 60
EXTEND_TIMEOUT_S = 30
CIRC_WINDOW_INIT = 1000   # 电路级窗口初始值
CIRC_WINDOW_INC  = 100    # 电路级每次 SENDME 增量（这步先只用来初始化）

@dataclass
class RelayQueueItem:
    cell: Any
    out_sock: Any
    stream: Any
    is_data: bool
    enqueued_at: float

class Tor_CircuitsList:
    LOCK = asyncio.Lock()
    GLOBAL_CIRCUIT_ID = 0

    def __init__(self, is_client=True):
        self.msb = is_client
        self._circuits_map = {}

    def values(self):
        return self._circuits_map.items()

    async def _get_next_circuit_id(self, initiator: Optional[bool] = None):
        """Allocate a new circ_id following tor's MSB parity rule.

        initiator=True  -> set MSB to 1 (we opened the OR connection)
        initiator=False -> set MSB to 0 (peer opened the OR connection)
        initiator=None  -> fall back to self.msb (constructor role)
        """
        async with Tor_CircuitsList.LOCK:
            Tor_CircuitsList.GLOBAL_CIRCUIT_ID += 1
            circuit_id = Tor_CircuitsList.GLOBAL_CIRCUIT_ID
        use_msb = self.msb if initiator is None else initiator
        if use_msb:
            circuit_id |= 0x80000000
        else:
            circuit_id &= 0x7FFFFFFF
        return circuit_id

    async def allocate_circuit_id(self, initiator: Optional[bool] = None) -> int:
        return await self._get_next_circuit_id(initiator)

    def _register(self, circuit_id: int, circuit: "TorCircuit"):
        self._circuits_map[circuit_id] = circuit
        if hasattr(circuit, "alias_ids"):
            circuit.alias_ids.add(circuit_id)


    async def create_new_client(self, circuit_id: int | None = None):
        if circuit_id is None:
            circuit_id = await self._get_next_circuit_id(initiator=True)
        circuit = TorCircuit(circuit_id, role="client")
        self._register(circuit.id, circuit)
        return circuit

    async def create_circuit_server(self, circuit_id):
        circuit = TorCircuit(circuit_id, role="server")
        self._register(circuit.id, circuit)
        return circuit

    def add_alias(self, circuit: "TorCircuit", circuit_id: int):
        self._register(circuit_id, circuit)

    def get_by_id(self, circuit_id):
        return self._circuits_map.get(circuit_id, None)

    def remove(self, circuit_id):
        circuit = self._circuits_map.pop(circuit_id, None)
        if not circuit:
            return None

        for alias_id in list(getattr(circuit, "alias_ids", [])):
            self._circuits_map.pop(alias_id, None)
        if hasattr(circuit, "alias_ids"):
            circuit.alias_ids.clear()
        return circuit


class CircuitRoleOps:
    def __init__(self, circuit):
        self.circuit = circuit

    def encrypt(self, relay_cell):
        raise NotImplementedError

    def decrypt(self, relay_cell):
        raise NotImplementedError

    def handle_relay(self, cell):
        raise NotImplementedError


class ClientCircuitOps(CircuitRoleOps):
    def encrypt(self, relay_cell):
        for node in reversed(self.circuit.circuit_nodes):
            if getattr(node, "_crypto_state", None) is None:
                continue
            node.encrypt_forward(relay_cell)

    def decrypt(self, relay_cell):
        for node in self.circuit.circuit_nodes:
            if getattr(node, "_crypto_state", None) is None:
                continue
            if getattr(relay_cell, "_checked", False):
                break
            node.decrypt_backward(relay_cell)

        if not getattr(relay_cell, "_checked", False):
            raise ValueError("RELAY decrypt failed: no hop recognized (checked=False)")

        return relay_cell.get_decrypted()

    def handle_relay(self, cell):
        return self.decrypt(cell)


class ServerCircuitOps(CircuitRoleOps):
    def encrypt(self, relay_cell):
        self.circuit.circuit_nodes[0].encrypt_forward(relay_cell)

    def decrypt(self, relay_cell):
        node = self.circuit.circuit_nodes[0]
        node.decrypt_backward(relay_cell)

        # IMPORTANT:
        # If not recognized, relay_cell remains encrypted.
        # Do NOT reconstruct a new object (will lose stream_id/header state).
        if relay_cell.is_encrypted:
            return relay_cell

        # Recognized and decrypted
        return relay_cell.get_decrypted()

    def handle_relay(self, cell):
        return self.decrypt(cell)


class TorCircuit:
    def __init__(self, circuit_id, role: str):
        self._id = circuit_id
        self.alias_ids: set[int] = set()
        self.link_circ_ids: dict[Any, int] = {}
        self.streams = StreamsList(self)
        self.buffer = Queue()
        self._relay_send_lock = asyncio.Lock()
        self.circuit_nodes = []
        self._extend_lock = asyncio.Lock()
        self.connect_event = self._make_new_event()
        self.role_ops = ClientCircuitOps(self) if role == "client" else ServerCircuitOps(self)

        self.created_at = time.time()
        self.last_used = self.created_at
        self._n_streams = 0

        self.circ_window_down = TorWindow(start=CIRC_WINDOW_INIT, increment=CIRC_WINDOW_INC)
        self.circ_window_up   = TorWindow(start=CIRC_WINDOW_INIT, increment=CIRC_WINDOW_INC)
        self.upstream_sock = None    # towards client
        self.downstream_sock = None  # towards exit
        self.sendq = {}
        self.sendq_stats = {"dequeued": 0, "wait_total_s": 0.0, "avg_wait_s": 0.0}
        self.scheduler = None

    def connect_to_guard(self, guard):
        key_agreement_cls = NtorKeyAgreement
        circuit_node = guard
        onion_skin = circuit_node.create_onion_skin()
        self.circuit_nodes.append(circuit_node)
        cell_create = Cell_Create2(key_agreement_cls.TYPE, onion_skin, self.id)
        self.created_cell = None
        return cell_create

    async def guard_handsake(self, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            circuit_node = self.circuit_nodes[0]
            circuit_node.complete_handshake(self.created_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for guard handshake")

    def connect_to_extend(self, extend_node):
        skin = extend_node.create_onion_skin()
        inner_cell = CellRelayExtend2(extend_node.ip, extend_node.or_port, extend_node.fingerprint, skin)
        extend_cell = self.make_relay(inner_cell, relay_type=Cell_RelayEarly)
        self.circuit_nodes.append(extend_node)
        self.extended_cell = None
        return extend_cell

    def create_stream(self):
        st = self.streams.create_new()
        # optional local counters:
        self._n_streams += 1
        self.last_used = time.time()
        return st
    def remove_stream(self, tor_stream):
        self.streams.remove(tor_stream)
        # optional local counters:
        self._n_streams = max(0, self._n_streams - 1)

    async def extend_handshake(self, descriptor_str, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            recv_cell = self.extended_cell
            if isinstance(recv_cell, CellRelayTruncated):
                raise Exception(f'Extend error {recv_cell.reason.name}')
            extend_node = self.last_node
            extend_node.set_descriptor(descriptor_str)
            extend_node.complete_handshake(recv_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for extend handshake")

    def server_connected(self, protocol, create_cell, sock):
        payload, share_key = protocol.handle_create2(create_cell.serialize_payload())
        created_cell = CellCreated2(payload, create_cell.circuit_id)
        simple_node = Tor_Router_simple(sock, share_key)
        self.circuit_nodes.append(simple_node)
        return created_cell

    def handle_relay(self, cell):
        return self.role_ops.handle_relay(cell)

    def make_relay(self, inner_cell, relay_type=None, stream_id=0):
        relay_type = relay_type or CellRelay
        relay_cell = relay_type(inner_cell, stream_id=stream_id, circuit_id=self.id)
        self.role_ops.encrypt(relay_cell)
        return relay_cell


    def enqueue_relay(self, cell, *, out_sock, stream=None, is_data=False):
        if out_sock is None:
            raise ValueError("enqueue_relay requires out_sock")
        out_circ_id = self.link_circ_ids.get(out_sock)
        if out_circ_id is not None:
            cell.circuit_id = out_circ_id
        item = RelayQueueItem(
            cell=cell,
            out_sock=out_sock,
            stream=stream,
            is_data=is_data,
            enqueued_at=time.monotonic(),
        )
        self.sendq.setdefault(out_sock, deque()).append(item)
        if self.scheduler is not None:
            self.scheduler.notify_enqueue(self, out_sock)
        return item

    def peek_sendq(self, out_sock):
        queue = self.sendq.get(out_sock)
        if queue:
            return queue[0]
        return None

    def pop_sendq(self, out_sock):
        queue = self.sendq.get(out_sock)
        if not queue:
            return None
        item = queue.popleft()
        if not queue:
            self.sendq.pop(out_sock, None)
        return item

    def record_send_dequeue(self, wait_s: float):
        st = self.sendq_stats
        st["dequeued"] += 1
        st["wait_total_s"] += wait_s
        st["avg_wait_s"] = st["wait_total_s"] / st["dequeued"]

    def close_all_streams(self):
        for stream in list(self.streams.values()):
            stream.aclose()

    def destroy(self, send_destroy=True):
        pass

    @property
    def id(self):
        return self._id

    @property
    def nodes_count(self):
        return len(self.circuit_nodes)

    @property
    def last_node(self):
        return self.circuit_nodes[-1]

    @staticmethod
    def _make_new_event():
        return asyncio.Event()



def compute_isolation_key(dst_host: str, dst_port: int, client_id: str|None=None) -> str:
    # simple but effective: isolate by destination endpoint (+ optional client id)
    return f"dst={dst_host}:{dst_port}|cid={client_id or 'default'}"


class CircuitMeta:
    """Metadata for lifecycle & isolation."""
    __slots__ = ("id","created_at","last_used","n_streams","purpose","exit_fp","isolation_key","state")
    def __init__(self, cid: int, isolation_key: str, purpose: str="general", exit_fp: Optional[str]=None):
        self.id = cid
        self.created_at = time.time()
        self.last_used = self.created_at
        self.n_streams = 0
        self.purpose = purpose
        self.exit_fp = exit_fp
        self.isolation_key = isolation_key
        self.state = "OPEN"   # BUILDING->OPEN->DIRTY->CLOSING

class CircuitManager:
    """Own-customer multiplexing only (per Tor_Client)."""
    def __init__(self, client, isolation_enabled: bool = False):
        self.client = client      # Tor_Client
        self.pool: Dict[int, CircuitMeta] = {}      # circ_id -> meta
        self.index: Dict[str, Set[int]] = {}        # isolation_key -> set(circ_id)
        self._lock = asyncio.Lock()
        self._build_sem = asyncio.Semaphore(1)
        self.isolation_enabled = isolation_enabled

    def _register(self, circ, isolation_key: str, purpose="general", exit_fp=None):
        m = CircuitMeta(circ.id, isolation_key, purpose, exit_fp)
        self.pool[circ.id] = m
        self.index.setdefault(isolation_key, set()).add(circ.id)

    def _unregister(self, circ_id: int):
        m = self.pool.pop(circ_id, None)
        if not m: return
        s = self.index.get(m.isolation_key)
        if s: s.discard(circ_id)
        if s and not s: self.index.pop(m.isolation_key, None)

    def _compatible(self, want_key: str, have_key: str) -> bool:
        # 开启隔离且目标不是 general 时，必须严格匹配
        if self.isolation_enabled and want_key != "general":
            return have_key == want_key
        # 否则允许 general 作为兜底
        return have_key == want_key or have_key == "general"

    def _pick_open(self, isolation_key: str):
        # pick an OPEN & compatible circuit with least load, then LRU
        cand: list[tuple[int, CircuitMeta]] = []
        for cid, m in self.pool.items():
            if m.state == "OPEN" and self._compatible(isolation_key, m.isolation_key):
                cand.append((cid, m))
        if not cand:
            return None
        cand.sort(key=lambda kv: (kv[1].n_streams, kv[1].last_used))  # min streams, then LRU
        cid = cand[0][0]
        return self.client.circuit_list.get_by_id(cid)

    async def get_or_build(self, isolation_key: str,
                           exit_hint=None, hops_count=3, extend_routers=None,
                           prefer_new: bool = False):
        # —— 第一次检查：持锁只做查表、准备 —— #
        async with self._lock:
            circ = self._pick_open(isolation_key)
            if circ:
                return circ

            if not self.isolation_enabled:
                # 没开隔离，可以复用 general
                circ = self._pick_open("general")
                if circ:
                    # 给 general 电路挂别名
                    self.index.setdefault(isolation_key, set()).add(circ.id)
                    return circ

        # 如果没开隔离：只允许等 general，不允许新建
        if not self.isolation_enabled and not prefer_new:
            # 等待直到有 general 出现
            while True:
                await asyncio.sleep(0.5)
                async with self._lock:
                    circ = self._pick_open("general")
                    if circ:
                        self.index.setdefault(isolation_key, set()).add(circ.id)
                        return circ

        # —— isolation 模式，或者显式要求新建 —— #
        await self.client.ready_to_send.wait()
        socket = self.client.socket_map.get(self.client.guard.addr)
        if not socket:
            raise RuntimeError("[cirmgr] guard socket not ready")

        # 串行化建路
        async with self._build_sem:
            async with self._lock:
                circ = self._pick_open(isolation_key)
                if circ:
                    return circ
                if not self.isolation_enabled:
                    circ = self._pick_open("general")
                    if circ:
                        self.index.setdefault(isolation_key, set()).add(circ.id)
                        return circ

            # 真正建路
            try:
                circ = await self.client.create_circuit(socket, hops_count, extend_routers)
            except Exception as e:
                import traceback
                print(f"[cirmgr] build error: {repr(e)}")
                print(traceback.format_exc())
                raise
            async with self._lock:
                self._register(circ, isolation_key=isolation_key, purpose="general", exit_fp=None)
            return circ

    def mark_used(self, circ):
        m = self.pool.get(circ.id)
        if not m:
            return
        m.last_used = time.time()
        m.n_streams += 1
        if m.n_streams >= MAX_STREAMS_PER_CIRCUIT:
            m.state = "DIRTY"

    def on_stream_end(self, circ):
        m = self.pool.get(circ.id)
        if not m: return
        m.n_streams = max(0, m.n_streams - 1)

    def _send_destroy(self, circ_id: int):
        sock = self.client.socket_map.get(self.client.guard.addr)
        if not sock:
            return
        try:
            # Adjust if your project uses another destroy cell constructor
            destroy = CellDestroy(circuit_id=circ_id)
            asyncio.create_task(sock.send_cell(destroy))
        except Exception:
            pass

    def _maybe_close(self, cid: int, m: CircuitMeta):
        # close only when no streams active
        if m.n_streams == 0:
            m.state = "CLOSING"

    def tick(self):
        now = time.time()
        to_close = []
        for cid, m in self.pool.items():
            if m.state == "OPEN":
                if (now - m.created_at > MAX_CIRCUIT_AGE_S) or (m.n_streams >= MAX_STREAMS_PER_CIRCUIT):
                    m.state = "DIRTY"
                elif (now - m.last_used > IDLE_TIMEOUT_S) and m.n_streams == 0:
                    m.state = "CLOSING"
            elif m.state == "DIRTY":
                self._maybe_close(cid, m)
            if m.state == "CLOSING":
                to_close.append(cid)
        # actually destroy and unregister
        for cid in to_close:
            self._send_destroy(cid)
            self._unregister(cid)

    async def maintain_prebuild(self):
        # 避免链路未就绪就建路
        await self.client.ready_to_send.wait()

        while True:
            try:
                async with self._lock:
                    idle = sum(1 for m in self.pool.values()
                               if m.state == "OPEN" and m.purpose == "general" and m.n_streams == 0)
                    target = PREBUILD_OPEN
                # print(f"[prebuild] tick idle_general={idle} target={target}")

                need = max(0, target - idle)
                for _ in range(need):
                    # 预建最好“真新建”，以便把 idle 拉到目标
                    try:
                        await self.get_or_build("general", hops_count=3, extend_routers=None, prefer_new=True)
                    except TypeError:
                        await self.get_or_build("general", hops_count=3, extend_routers=None)
            except Exception as e:
                import traceback
                print(f"[prebuild] error: {repr(e)}")
                print(traceback.format_exc())
            await asyncio.sleep(2.0)



