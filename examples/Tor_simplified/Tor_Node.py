import asyncio
import requests

from torpy.cells import *

from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.Tor_Descriptor import TorDescriptor_build
from examples.Tor_simplified.Tor_Router import Tor_Router

from tools.Crypt.key_generator import curve25519_setup, ed25519_setup, rsa_setup



class Tor_Guard(Tor_base):
    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)

        self.ntor_pvk, self.ntor_puk = curve25519_setup()
        self.ed_pvk, self.ed_puk = ed25519_setup()
        self.rsa_pvk, _ = rsa_setup()
        self.circuit_list = Tor_CircuitsList()


    async def start_protocol(self):
        self.tasks['routing_task'] = asyncio.create_task(self.register_to_dire())
        self.tasks['listener_task'] = asyncio.create_task(self.serve_tor_socket())
        # self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(*self.tasks.values())

    async def register_to_dire(self):
        descriptor = self.generate_descriptor()
        await self.upload_descriptor_to_dirserver(descriptor, "127.0.0.1", 9030)

    async def upload_descriptor_to_dirserver(self,
                                             descriptor_text: str,
                                             dirserver_ip: str,
                                             dirserver_port: int = 80,
                                             path: str = "/tor/post/dir"
                                             ) -> None:
        """
        异步上传 server descriptor 到目录服务器
        """
        url = f"http://{dirserver_ip}:{dirserver_port}{path}"
        headers = {
            "User-Agent": "Tor 0.4.8.x on Python",
            "Content-Type": "application/x-tor-server-descriptor",
        }

        def sync_post():
            return requests.post(url, headers=headers, data=descriptor_text.encode("utf-8"), timeout=10)

        try:
            response = await asyncio.to_thread(sync_post)
            print(f"[+] Descriptor uploaded. HTTP {response.status_code}")
            print("Response body:")
            print(response.text)
        except Exception as e:
            print(f"[!] Failed to upload descriptor: {e}")

    def generate_descriptor(self):
        desc_build = TorDescriptor_build(
            nickname=self.name,
            ip=self.host,
            ed_sk=self.ed_pvk,
            ed_pk=self.ed_puk,
            curve_sk=self.ntor_pvk,
            curve_pk=self.ntor_puk,
            rsa_sk=self.rsa_pvk,
            or_port=self.port
        )
        descriptor = desc_build.build()
        return descriptor

    async def create_circuit(self, socket, hops_count=3, extend_routers=None):
        """Quickly select several random nodes and freely add nodes, such as exit nodes"""
        circuit = await self.circuit_list.create_new()
        create_cell = circuit.initialize(self.guard)
        await socket.send_cell(create_cell)
        await circuit.guard_handsake(wait_time=60)

        while circuit.nodes_count < hops_count:
            if circuit.nodes_count == hops_count - 1:
                router = self.consensus.get_random_exit_node()
            else:
                router = self.consensus.get_random_middle_node()
            descriptor_str = self.consensus.get_descriptor_by_fingerprint(router['fingerprint'])
            extend_node = Tor_Router(router)
            extend_node.set_descriptor(descriptor_str)

            extend_cell = circuit.extend(extend_node)
            await socket.send_cell(extend_cell)

            await circuit.extend_handshake(descriptor_str, wait_time=60)

        if extend_routers:
            for router in extend_routers:
                extend_cell = circuit.extend(router)
                await socket.send_cell(extend_cell)
                descriptor_str = self.consensus.get_descriptor_by_fingerprint(router['fingerprint'])
                await circuit.extend_handshake(descriptor_str, wait_time=60)

        return circuit


    async def handle_cell(self, cell):
        self.print("receive client cell_type:", type(cell))
        if isinstance(cell, CellCreated2):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            circuit.created_cell = cell
            circuit.connect_event.set()
            self.print('guard is ready')
        if isinstance(cell, CellRelay):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            print("check cell content", cell)
            print("check if encrypt:", cell.is_encrypted)
            inner_cell = circuit.handle_relay(cell)
            await self.handle_cell_relay(inner_cell, circuit, cell)

    async def handle_cell_relay(self, cell, circuit, origin_cell):

        if isinstance(cell, CellRelayExtended2):
            circuit.extend_cell = cell
            circuit.connect_event.set()
        elif isinstance(cell, CellRelayConnected):
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
        elif isinstance(cell, CellRelaySendMe):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            logger.debug('Stream #%i: sendme received', stream.id)
            stream.window.package_inc()


    async def close_stream(self, stream):
        socket = self.socket_map.get(self.guard.addr, None)  # 之后补充guard的查验逻辑，即guard是否断线，如果没断就一直保持socket连通
        if not socket:
            raise "socket has closed before stream"
        end_cell = stream.make_end
        await socket.send_cell( end_cell)

        stream.close()

if __name__ == "__main__":
    from torpy.parsers import RouterDescriptorParser
    from torpy.consesus import Descriptor

    guard = Tor_Guard("guard1", "127.0.0.1", 9001)
    descriptor_txt = guard.generate_descriptor()
    print(descriptor_txt)
    descriptor_info = RouterDescriptorParser.parse(descriptor_txt)
    aas = Descriptor(**descriptor_info)
    print(aas)
    print(aas.onion_key)
    print(aas.ntor_key)
    print(aas.signing_key)