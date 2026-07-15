# network_src/TorCore/Tor_NodeSim.py
import asyncio, time
from collections import defaultdict
from network_src.TorCore.Tor_Node import Tor_Node as _Tor_Node_Base
from example_test.delay_test.Tor_SocketSim import Tor_SocketSim
from tools.Log.utils import HopTimer, classify_exception, FailReason
from network_src.TorCore.Tor_Router import Tor_Router_simple
from network_src.TorCore.Tor_Cell import (
    Cell_Create2, CellCreated2, CellRelay, Cell_RelayEarly,
    CellRelayExtend2, CellRelayExtended2, CellRelayBegin, CellRelayConnected,
    CellRelayEnd, CellRelayData, CellRelaySendMe, StreamReason
)

class Tor_NodeSim(_Tor_Node_Base):
    """
    仅覆盖需要使用 Tor_SocketSim 的拨号/附加节点部分；不改其它逻辑。
    新增：self.dir_sim_map 用于 OR IP -> sim_ip 的映射（可为空）。
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dir_sim_map: dict[str, str] = {}  # 目录返回后可填充 {or_ip: sim_ip}

    async def create_circuit(self, create_cell, sock, circuit_id):
        # 与父类一致
        t0 = time.perf_counter()
        circuit = await self.circuit_list.create_circuit_server(circuit_id)
        created_cell = circuit.server_connected(self.protocol_version, create_cell, sock)
        self._ev("circuit_server_connected", circ_id=circuit_id,
                 peer=str(sock.socket.getpeername()), ms=(time.perf_counter()-t0)*1000.0)
        await sock.send_cell(created_cell)
        simple_node = Tor_Router_simple(sock)
        circuit.circuit_nodes.append(simple_node)
        return circuit

    async def extend_next_node(self, cell: CellRelayExtend2, circuit_id: int):
        ip = cell.ip; port = cell.port; addr = (ip, port)
        skin = cell.skin; handshake_type = cell.finger_type
        sock = self.socket_map.get(addr, None)

        if sock is None:
            lock = self._socket_locks[addr]
            async with lock:
                sock = self.socket_map.get(addr, None)
                if sock is None:
                    t_tls = time.perf_counter()
                    try:
                        # ★ 唯一差异：用 Tor_SocketSim.dial 并传 sim_ip / peer_sim_map
                        sock = await Tor_SocketSim.dial(
                            remote_addr=addr,
                            source_ip=self.host,
                            on_cell=self.handle_cell,
                            node_id=self.node_id,
                            sim_ip=self.sim_ip,
                            peer_sim_map=self.dir_sim_map  # 可为空；则回退用对端真实 IP
                        )
                        self.socket_map[addr] = sock
                        asyncio.create_task(self.handle_connection(addr, sock))
                        await sock.listen_started.wait()
                        self._ev("tls_handshake_done", peer=f"{ip}:{port}", side="client",
                                 ms=(time.perf_counter() - t_tls) * 1000.0)
                    except Exception as e:
                        self._ev("tls_handshake_fail", peer=f"{ip}:{port}", side="client",
                                 fail_reason=FailReason.TLS_FAIL.value, error=str(e),
                                 ms=(time.perf_counter() - t_tls) * 1000.0)
                        raise

                    # Tor 链路握手（握手面也会被 socket 子类注入延迟）
                    t_tor = time.perf_counter()
                    try:
                        await sock.tor_handshake_client()
                        self._ev("tor_handshake_done", peer=f"{ip}:{port}", side="client",
                                 version=getattr(sock.protocol, "version", None),
                                 ms=(time.perf_counter() - t_tor) * 1000.0)
                    except Exception as e:
                        self._ev("tor_handshake_fail", peer=f"{ip}:{port}", side="client",
                                 fail_reason=FailReason.NTOR_FAIL.value, error=str(e),
                                 version=getattr(sock.protocol, "version", None),
                                 ms=(time.perf_counter() - t_tor) * 1000.0)
                        raise

        await sock.handshake_done.wait()

        circuit = self.circuit_list.get_by_id(circuit_id)
        simple_node = Tor_Router_simple(sock)
        circuit.circuit_nodes.append(simple_node)

        # 下游 CREATE2
        create2 = Cell_Create2(handshake_type=handshake_type, onion_skin=skin, circuit_id=circuit_id)
        t_ext = time.perf_counter()
        try:
            await sock.send_cell(create2)
            self._ev("circuit_extend_downstream_sent", circ_id=circuit_id, target=f"{ip}:{port}")
        except Exception as e:
            self._ev("circuit_extend_downstream_fail", circ_id=circuit_id, target=f"{ip}:{port}",
                     error=str(e), ms=(time.perf_counter() - t_ext) * 1000.0)
            raise
