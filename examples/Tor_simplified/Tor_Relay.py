import numpy as np
import asyncio
from queue import Queue


from tools.Crypt.key_generator import curve25519_setup
from tools.Crypt.serialization import decode


from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import TorCircuit, Tor_CircuitsList

class Tor_Client(Tor_base):
    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.output_buffer = Queue()
        self.privk_ntor, self.pubk_ntor = curve25519_setup()
        self._version = 4
        self._send_lock = asyncio.Lock()
        self.guard = None
        self.circuit_list = Tor_CircuitsList(self.guard)

    async def start_protocol(self):
        # self.tasks['routing_task'] = asyncio.create_task(self.routing_request())
        self.tasks['listener_task'] = asyncio.create_task(self.listener())
        self.tasks['process_task'] = asyncio.create_task(self.process())
        # self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(*self.tasks.values())

    async def make_stream(self, message, addr, hops_count=3, extend_routers=None):
        circuit = await self.create_circuit(hops_count, extend_routers)
        stream = circuit.create_stream(addr)
        cells = stream.make_relay(message)


    async def create_circuit(self, hops_count=3, extend_routers=None):
        """Quickly select several random nodes and freely add nodes, such as exit nodes"""
        self.connect_to_guard()
        circuit = self.circuit_list.create_new()
        circuit.create()
        circuit.build_hops(hops_count)
        if extend_routers:
            for router in extend_routers:
                circuit.extend(router)
        return circuit

    async def send_cells(self, cells):
        for cell in cells:
            cell = self.serialize(cell)



    def connect_to_guard(self):
        self.__tor_socket = TorCellSocket(self._router)
        self.__tor_socket.connect()
        pass


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