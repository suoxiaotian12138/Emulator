# network_src/TorCore/Tor_ClientSim.py
from network_src.TorCore.Tor_Client import Tor_Client as _Tor_Client_Base
from example_test.delay_test.Tor_SocketSim import Tor_SocketSim

class Tor_ClientSim(_Tor_Client_Base):
    def __init__(self, name: str, host: str, port: int, sim_ip: str, model: str = "sim"):
        super().__init__(name, host, port, model)
        self.sim_ip = sim_ip
        self.peer_sim_map = {}  # 可按需填充 guard OR IP -> sim_ip

    async def consensus_init(self):
        await self.consensus.consus_init_async()
        guard = self.consensus.get_random_guard_node()
        self.guard = self.consensus.wrap_router(guard) if hasattr(self.consensus, "wrap_router") else self.guard

        desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
        self.guard.set_descriptor(desc)

        # ★ 只改这一行：用 Tor_SocketSim
        socket = await Tor_SocketSim.dial(
            remote_addr=self.guard.addr,
            source_ip=self.host,
            on_cell=self.handle_cell,
            node_id=self.node_id,
            sim_ip=self.sim_ip,
            peer_sim_map=self.peer_sim_map
        )

        self._ev("tls_handshake_done", peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", side="client")
        asyncio.create_task(self.handle_connection(self.guard.addr, socket))
        await socket.listen_started.wait()
        await socket.tor_handshake_client()
        await socket.handshake_done.wait()
        self._ev("tor_handshake_done", peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}", versions=[3, 4], auth="none")
        self.ready_to_send.set()
