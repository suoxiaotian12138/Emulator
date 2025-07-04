import asyncio
from queue import Queue
from typing import Literal


from tools.Crypt.key_generator import curve25519_setup

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
        self.privk_ntor, self.pubk_ntor = curve25519_setup()

        self.consensus = Tor_Consensus(model)
        self.guard = None

        self.circuit_list = Tor_CircuitsList()

    async def start_protocol(self):
        self.tasks['listener_task'] = asyncio.create_task(self.monitor_tor_socket())
        self.tasks['routing_task'] = asyncio.create_task(self.consensus_init())

        await asyncio.gather(*self.tasks.values())

    async def handle_connection(self, addr, tor_sock):
        try:
            self.socket_map[addr] = tor_sock
            handle = await tor_sock.start_listen()  # 返回 monitor_handle task
            await tor_sock.tor_handshake_client()   #
            await handle  # 等连接断开
        finally:
            self.socket_map.pop(addr, None)
            self.print(f"[Monitor] Connection {addr} closed and removed from map.")

    async def consensus_init(self):
        self.print("pb:01")
        await self.consensus.consus_init()
        self.print("pb:02")
        self.guard = Tor_Router(self.consensus.get_random_guard_node())
        desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
        self.guard.set_descriptor(desc)
        socket = Tor_Socket(on_cell=self.handle_cell)
        await socket.setup_socket(remote_addr=self.guard.addr)
        asyncio.create_task(self.handle_connection(self.guard.addr, socket))

    async def make_stream(self, message, addr, hops_count=3, extend_routers=None):
        socket = self.socket_map.get(self.guard.addr, None)
        if socket is None:
            socket = Tor_Socket(on_cell=self.handle_cell)
            await socket.setup_socket(remote_addr=self.guard.addr)
            asyncio.create_task(self.handle_connection(self.guard.addr, socket))

        circuit = await self.create_circuit(socket, hops_count, extend_routers)
        stream = circuit.create_stream()
        connect_cell = stream.make_connect(addr)
        await socket.send_cell(connect_cell)
        await stream.wait_connect_ack()
        cells = stream.make_relays(message)

        await socket.send_cells(cells)

    async def create_circuit(self, socket, hops_count=3, extend_routers=None):
        circuit = await self.circuit_list.create_new_client()

        used_fp = set()
        used_fp.add(self.guard.fingerprint_str)

        create_cell = circuit.connect_to_guard(self.guard)
        await socket.send_cell(create_cell)
        await circuit.guard_handsake(wait_time=60)

        while circuit.nodes_count < hops_count:
            if circuit.nodes_count == hops_count - 1:
                router = self.consensus.get_random_exit_node(exclude=used_fp)
            else:
                router = self.consensus.get_random_middle_node(exclude=used_fp)
            used_fp.add(router["fingerprint"])

            descriptor_str = await self.consensus.fetch_descriptor(router["fingerprint"])
            extend_node = Tor_Router(router)
            extend_node.set_descriptor(descriptor_str)

            extend_cell = circuit.connect_to_extend(extend_node)
            await socket.send_cell(extend_cell)
            await circuit.extend_handshake(descriptor_str, wait_time=60)

        if extend_routers:
            for router in extend_routers:
                if router["fingerprint"] in used_fp:
                    continue
                used_fp.add(router["fingerprint"])

                extend_cell = circuit.extend(router)
                await socket.send_cell(extend_cell)
                descriptor_str = await self.consensus.fetch_descriptor(router["fingerprint"])
                await circuit.extend_handshake(descriptor_str, wait_time=60)

        return circuit

    async def handle_cell(self, cell, sock):
        self.print("receive client cell_type:", type(cell))
        if isinstance(cell, CellVersions):
            sock.protocal.version = sock.handshake.retrieve_versions(cell)
        elif isinstance(cell, CellCerts):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            sock.handshake.retrieve_certs(cell)
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
        self.print("inner_cell:", cell)
        if isinstance(cell, CellRelayExtended2):
            circuit.extended_cell = cell
            circuit.connect_event.set()
        elif isinstance(cell, CellRelayConnected):
            self.print(origin_cell.stream_id)
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.connect_event.set()
        elif isinstance(cell, CellRelayEnd):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.set_end(cell)
            data = await stream.recv(2048)
            print("final data: ", data)
        elif isinstance(cell, CellRelayData):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.append(cell.data)
            stream.window.deliver_dec()
            if stream.window.need_sendme():
                sendme_cell = stream.make_relay(CellRelaySendMe(circuit_id=cell.circuit_id))
                socket = self.socket_map.get(self.guard.addr, None)
                socket.send_cell(sendme_cell)
            self.print("have received")
        elif isinstance(cell, CellRelaySendMe):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.window.package_inc()


    async def close_stream(self, stream):
        socket = self.socket_map.get(self.guard.addr, None)  # 之后补充guard的查验逻辑，即guard是否断线，如果没断就一直保持socket连通
        if not socket:
            raise "socket has closed before stream"
        end_cell = stream.make_end
        await socket.send_cell( end_cell)

        stream.close()




