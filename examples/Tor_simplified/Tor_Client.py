import asyncio
from queue import Queue
from typing import Literal
import time

from tools.Log.stream_tracker import StreamTracker
from tools.Log.utils import HopTimer, classify_exception, FailReason

from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.Tor_Consensus import Tor_Consensus
from examples.Tor_simplified.Tor_Router import Tor_Router
from examples.Tor_simplified.Tor_Socket import Tor_Socket
from examples.Tor_simplified.Tor_Cell import *



class Tor_Client(Tor_base):
    def __init__(self, name: str, host: str, port: int, model: Literal["sim", "real"] = "sim"):
        super().__init__(name, host, port, model)
        self.output_buffer = Queue()

        self.consensus = Tor_Consensus(model, self.dire_ip, self.dire_port)
        self.guard = None

        self.circuit_list = Tor_CircuitsList()
        self.ready_to_send = asyncio.Event()
        self.stream_tracker = StreamTracker()     # ★ 新增
        self._sid2uid: dict[int, str] = {}

    async def start_protocol(self):
        self.tasks['listener_task'] = asyncio.create_task(self.monitor_tor_socket())
        await self.consensus_init()

        self._ev("client_start_protocol", ip=self.host, port=self.port)
        await asyncio.gather(*self.tasks.values())


    async def consensus_init(self):
        await self.consensus.consus_init_async()
        guard = self.consensus.get_random_guard_node()
        self.guard = Tor_Router(guard)

        desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
        self.guard.set_descriptor(desc)
        socket = Tor_Socket(self.host, on_cell=self.handle_cell, node_id=self.node_id)

        #和guard的tls握手记录
        await socket.setup_socket(remote_addr=self.guard.addr)
        self._ev("tls_handshake_done", peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client")

        asyncio.create_task(self.handle_connection(self.guard.addr, socket))
        await socket.listen_started.wait()
        #和guard的tor握手
        await socket.tor_handshake_client()
        await socket.handshake_done.wait()
        self._ev("tor_handshake_done", peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", versions=[3, 4], auth="none")

        self.ready_to_send.set()

    async def make_stream(self, message, addr, hops_count=3, extend_routers=None):
        await self.ready_to_send.wait()
        socket = self.socket_map.get(self.guard.addr, None)
        circuit = await self.create_circuit(socket, hops_count, extend_routers)
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
            cells = stream.make_relays(message)
            await socket.send_cells(cells)

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

    async def create_circuit(self, socket, hops_count=3, extend_routers=None):
        circuit = await self.circuit_list.create_new_client()
        #guard选择记录
        snap = self.consensus.get_consensus_snapshot()
        t0_total = time.perf_counter()
        used_fp = set()
        used_fp.add(self.guard.fingerprint_str)

        #电路的第一跳记录
        self._ev("path_step_selected", circ_id=circuit.id, hop=1, nickname=self.guard.nickname,
                 fp=self.guard.fingerprint_str, role="guard",
                 consensus_id=snap["consensus_id"])
        create_cell = circuit.connect_to_guard(self.guard)
        await socket.send_cell(create_cell)
        await circuit.guard_handsake(wait_time=600)

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

            t_rtt = HopTimer().start()
            try:
                extend_cell = circuit.connect_to_extend(extend_node)
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
                              guard=self.guard.fingerprint_str,
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
            # self.print("sock protocol:", sock.protocol.version)
        elif isinstance(cell, CellCerts):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            sock.handshake.recv_authenticate(cell)
        elif isinstance(cell, CellNetInfo):
            sock.handshake.retrieve_net_info(cell)
        elif isinstance(cell, CellCreated2):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            circuit.created_cell = cell
            circuit.connect_event.set()
        elif isinstance(cell, CellRelay):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            inner_cell = circuit.handle_relay(cell)
            await self.handle_cell_relay(inner_cell, circuit, cell)

    async def handle_cell_relay(self, cell, circuit, origin_cell):
        # self.print("inner_cell:", cell)
        if isinstance(cell, CellRelayExtended2):
            circuit.extended_cell = cell
            circuit.connect_event.set()
        elif isinstance(cell, CellRelayConnected):
            # self.print(origin_cell.stream_id)
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.connect_event.set()
        elif isinstance(cell, CellRelayEnd):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.set_end(cell)
            data = await stream.recv(2048)
            # === 新增：结束 stream 并写日志 ===
            stream_uid = self._sid2uid.pop(origin_cell.stream_id, None)
            if stream_uid:
                rec = self.stream_tracker.end(stream_uid)
                if rec:
                    self._stream(**rec)  # 写入 streams.jsonl（或 flows.jsonl 兼容别名）
            self.print("final data: ", data)
        elif isinstance(cell, CellRelayData):
            # self.print("cell data: ", cell.data)
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.append(cell.data)
            stream.window.deliver_dec()

            # === 新增：记录首包与累计字节 ===
            stream_uid = self._sid2uid.get(origin_cell.stream_id)
            if stream_uid:
                self.stream_tracker.on_down_chunk(stream_uid, nbytes=len(cell.data))

            if stream.window.need_sendme():
                sendme_cell = stream.make_relay(CellRelaySendMe(circuit_id=cell.circuit_id))
                socket = self.socket_map.get(self.guard.addr, None)
                await socket.send_cell(sendme_cell)
        elif isinstance(cell, CellRelaySendMe):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.window.package_inc()


    async def close_stream(self, stream):
        socket = self.socket_map.get(self.guard.addr, None)  # 之后补充guard的查验逻辑，即guard是否断线，如果没断就一直保持socket连通
        if not socket:
            raise "socket has closed before stream"
        end_cell = stream.make_end()
        await socket.send_cell( end_cell)

        stream.close()




