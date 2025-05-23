import asyncio
from queue import Queue


from tools.Packet.packet_TCP import is_socket_alive
from tools.Crypt.key_generator import curve25519_setup

from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import TorCircuit, CircuitsList

class Tor_Client(Tor_base):
    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.output_buffer = Queue()
        self.privk_ntor, self.pubk_ntor = curve25519_setup()
        self._version = 4
        self._send_lock = asyncio.Lock()
        self.guard = None
        self.socket_to_guard = None
        self.circuit_list = CircuitsList(self.guard)

    async def start_protocol(self):
        # self.tasks['routing_task'] = asyncio.create_task(self.routing_request())
        self.tasks['listener_task'] = asyncio.create_task(self.listener())
        self.tasks['process_task'] = asyncio.create_task(self.process())
        # self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(*self.tasks.values())

    async def make_stream(self, message, addr, hops_count=3, extend_routers=None):
        socket = self.socket_map.get(self.guard.addr, None)   #之后补充guard的查验逻辑，即guard是否断线，如果没断就一直保持socket连通
        if not is_socket_alive(socket):
            socket = self.create_tls_connection(self.addr, self.guard.addr)
            self.socket_map[self.guard.addr] = socket

        circuit = await self.create_circuit(socket, hops_count, extend_routers)
        stream = circuit.create_stream()

        connect_cell = stream.make_connect(addr)
        await self.send_cell(socket, connect_cell)
        await stream.wait_connect_ack()

        cells = stream.make_relays(message)
        await self.send_cells(cells, socket)


    async def create_circuit(self, socket, hops_count=3, extend_routers=None):
        """Quickly select several random nodes and freely add nodes, such as exit nodes"""

        circuit = self.circuit_list.create_new()
        circuit.initialize()
        circuit.guard_handsake(wait_time=60)
        while circuit.nodes_count < hops_count:
            if circuit.nodes_count == hops_count - 1:
                router = self.consensus.get_random_exit_node()
            else:
                router = self.consensus.get_random_middle_node()
            extend_cell = circuit.extend(router)
            await self.send_cell(socket, extend_cell)
            await circuit.extend_handshake(wait_time=60)

        if extend_routers:
            for router in extend_routers:
                extend_cell = circuit.extend(router)
                await self.send_cell(socket, extend_cell)
                await circuit.extend_handshake(wait_time=60)

        return circuit


    async def send_cells(self, cells, socket):
        for cell in cells:
            cell = self.serialize(cell)
            async with self._send_lock:
                try:
                    await self.send(socket, cell)
                except OSError as e:
                    print(f"[Error] Socket send failed: {e}")


    def get_guard(self):
        pass


    async def process(self):
        import binascii
        while True:
            obj = await self.buffer.extract_by_size()
            if obj is None:
                break
            self.print(binascii.hexlify(obj))

    async def send_cell(self, cell, socket):
        buffer = self.serialize(cell)
        async with self._send_lock:
            try:
                await self.send(socket, buffer)
            except OSError as e:
                print(f"[Error] Socket send failed: {e}")

    async def close_stream(self, stream):
        socket = self.socket_map.get(self.guard.addr, None)  # 之后补充guard的查验逻辑，即guard是否断线，如果没断就一直保持socket连通
        if not socket:
            raise "socket has closed before stream"

        end_cell = stream.make_end
        await self.send_cell(socket, end_cell)

        stream.close()
