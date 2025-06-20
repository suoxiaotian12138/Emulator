import asyncio
import requests

from examples.Tor_simplified.Tor_Cell import *
from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.Tor_Descriptor import TorDescriptor_build
from examples.Tor_simplified.Tor_Router import Tor_Socket, Tor_Router_simple

from tools.Crypt.key_generator import curve25519_setup, ed25519_setup, rsa_setup
from examples.Tor_simplified.Tor_Crypt import NtorServerKeyAgreement, RelayCryptoState

import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from textwrap import wrap

class Tor_Guard(Tor_base):
    def __init__(self, name: str, host: str, port: int, role: str = 'Guard'):
        super().__init__(name, host, port)

        self.ntor_pvk, self.ntor_puk = curve25519_setup()
        self.ed_pvk, self.ed_puk = ed25519_setup()
        self.circuit_list = Tor_CircuitsList()
        fingerprint = self.rsa_identity_digest(self.rsa_pvk)
        self.protocol = NtorServerKeyAgreement(fingerprint, self.ntor_pvk)
        self.role = role

    async def start_protocol(self):
        self.tasks['routing_task'] = asyncio.create_task(self.register_to_dire())
        self.tasks['listener_task'] = asyncio.create_task(self.serve_tor_socket())

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
            or_port=self.port,
            sim_flag=self.get_sim_flag()
        )
        descriptor = desc_build.build()
        return descriptor

    def get_sim_flag(self) -> str:
        sim_flag = "sim-flags" + ' ' + self.role
        return sim_flag

    async def create_circuit(self, create_cell, sock, circuit_id):
        """Quickly select several random nodes and freely add nodes, such as exit nodes"""
        circuit = await self.circuit_list.create_circuit_server(circuit_id)
        created_cell = circuit.server_connected(self.protocol, create_cell, sock)
        await sock.send_cell(created_cell)
        return circuit

    async def extend_next_node(self, cell: CellRelayExtend2, circuit_id: int):
        ip = cell.ip
        port = cell.port
        addr = (ip, port)
        skin = cell.skin
        handshake_type = cell.finger_type

        create2 = Cell_Create2(handshake_type=handshake_type, onion_skin=skin, circuit_id=circuit_id)

        sock = Tor_Socket(on_cell=self.handle_cell)
        await sock.setup_socket(remote_addr=addr)
        asyncio.create_task(self.handle_connection(addr, sock))
        await sock.tor_handshake_client()

        circuit = self.circuit_list.get_by_id(circuit_id)
        self.print("circuit:", circuit)
        simple_node = Tor_Router_simple(sock)
        circuit.circuit_nodes.append(simple_node)

        await sock.send_cell(create2)

    async def reply_extend(self, cell: CellCreated2):

        circuit_id = cell.circuit_id
        handshake_data = cell.handshake_data
        extend_cell = CellRelayExtended2(handshake_data, circuit_id)
        self.print(circuit_id)
        self.print(cell.circuit_id)
        self.print(self.circuit_list.values())
        circuit = self.circuit_list.get_by_id(circuit_id)
        cell = circuit.make_relay(inner_cell=extend_cell, relay_type=CellRelay)
        sock = circuit.circuit_nodes[0].sock
        await sock.send_cell(cell)



    async def handle_cell(self, cell, sock):
        self.print("receive client cell_type:", type(cell))
        self.print("cell content:", cell)
        if isinstance(cell, CellVersions):
            if not sock.handshake_initiator:
                await sock.tor_handshake_server(cell, self.cert_file)
            else:
                sock.protocal.version = sock.handshake.retrieve_versions(cell)
        elif isinstance(cell, CellCerts):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellNetInfo):
            sock.handshake.retrieve_net_info(cell)
        elif isinstance(cell, Cell_Create2):
            await self.create_circuit(cell, sock, cell.circuit_id)
        elif isinstance(cell, CellCreated2):
            await self.reply_extend(cell)
        elif isinstance(cell, CellRelay):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            if sock == circuit.circuit_nodes[0].sock:
                inner_cell = circuit.handle_relay(cell)
                await self.handle_cell_relay(inner_cell, circuit, cell, sock)
            else:
                next_node = circuit.circuit_nodes[0]
                next_node.encrypt_forward(cell)
                print('forward relay cell:', cell)
                await next_node.sock.send_cell(cell)

        elif isinstance(cell, Cell_RelayEarly):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            inner_cell = circuit.handle_relay(cell)
            await self.handle_cell_relay(inner_cell, circuit, cell, sock)

    async def handle_cell_relay(self, cell, circuit, origin_cell, sock):
        self.print("inner_cell:", cell)
        if isinstance(cell, CellRelayExtend2):
            await self.extend_next_node(cell, circuit.id)
        elif isinstance(cell, Cell_RelayEarly):
            if sock == circuit.circuit_nodes[0].sock:
                next_hop_sock = circuit.circuit_nodes[-1].sock
            else:
                next_hop_sock = circuit.circuit_nodes[0].sock
            await next_hop_sock.send_cell(cell)
        elif isinstance(cell, CellRelay):
            if sock == circuit.circuit_nodes[0].sock:
                next_hop_sock = circuit.circuit_nodes[-1].sock
            else:
                next_hop_sock = circuit.circuit_nodes[0].sock
            await next_hop_sock.send_cell(cell)
        elif isinstance(cell, CellRelayBegin):
            host = cell.address
            port = cell.port
            addr = (host, port)
            circuit.streams.set_stream(stream_id=origin_cell.stream_id, target_addr=addr)
            self.print("stream id", origin_cell.stream_id)
            ip_address = await self.resolve_ipv4_async(host)
            self.print("ip_address:", ip_address)
            connected_cell = CellRelayConnected(ip_address, 0, origin_cell.circuit_id)
            self.print(connected_cell)
            self.print(connected_cell.address)
            relay_cell = circuit.make_relay(inner_cell=connected_cell, relay_type=CellRelay, stream_id=origin_cell.stream_id)

            await sock.send_cell(relay_cell)
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
            message = stream.extract_guessed_message_from_buffer()
            if message is None:
                pass
            self.print(message)
            text = await stream.handle_http_request(message)
            self.print(text)
            cell_list = stream.make_relays_server(text)
            for cell in cell_list:
                await sock.send_cell(cell)
            self.print("pd:01")
            end_cell = CellRelayEnd(StreamReason(6), circuit.id)
            self.print("pd:02")
            relay_cell = circuit.make_relay(inner_cell=end_cell, relay_type=CellRelay, stream_id=origin_cell.stream_id)
            self.print("pd:03")
            await sock.send_cell(relay_cell)
            self.print("pd:04")
            # stream.window.deliver_dec()
            # if stream.window.need_sendme():
            #     sendme_cell = stream.make_relay(CellRelaySendMe(circuit_id=cell.circuit_id))
            #     socket = self.socket_map.get(self.guard.addr, None)
            #     socket.send_cell(sendme_cell)
        elif isinstance(cell, CellRelaySendMe):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.window.package_inc()

    async def resolve_ipv4_async(self, domain: str) -> str:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                return sockaddr[0]
        raise ValueError("No IPv4 address found")

    async def close_stream(self, stream):
        items = self.socket_map.items()
        for addr, sock in items:
            if sock:
                end_cell = stream.make_end
                await sock.send_cell(end_cell)
            else:
                raise "socket has closed before stream"
        stream.close()

    @staticmethod
    def rsa_identity_digest(rsa_priv: rsa.RSAPrivateKey) -> bytes:
        """
        Return the raw 20-byte SHA-1 digest of the RSA identity public key.
        Pass this value to NtorServerKeyAgreement(...).

        :param rsa_priv: server's long-term RSA *private* key object
        """
        der = rsa_priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha1(der).digest()
