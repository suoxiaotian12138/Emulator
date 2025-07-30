import asyncio
import requests
import time, hashlib

from tools.Crypt.key_generator import curve25519_setup, ed25519_setup, rsa_setup
from tools.Crypt.crypt_common import rsa_identity_digest
from tools.Network_Management.DNSResolver import DNSResolver

from examples.Tor_simplified.Tor_Cell import *
from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.Tor_Descriptor import TorDescriptor_build
from examples.Tor_simplified.Tor_Router import Tor_Router_simple
from examples.Tor_simplified.Tor_Socket import Tor_Socket
from examples.Tor_simplified.Tor_Crypt import NtorServerKeyAgreement
from cryptography.hazmat.primitives import serialization, hashes
from tools.Crypt.crypt_common import (
    build_ed25519_cert, build_rsa_to_ed_crosscert,
    rsa_id_x509_der, rsa_pubkey_spki_der, rsa_identity_x509_der,
    CT_RSA_ID_X509, CT_ED_ID_SIGNING, CT_ED_SIGNING_TLS, CT_RSA_TO_ED_CROSS,
    debug_build_crosscert
)
from examples.Tor_simplified.Tor_Cell import CellCerts

class Tor_Node(Tor_base):
    def __init__(self, name: str, host: str, port: int, flags,
                 protocols: str = "Cons=2 Desc=2 DirCache=2 FlowCtrl=2 Link=4-5 LinkAuth=3 Microdesc=2 Padding=2 Relay=4",
                 exit_policy: str = 'accept 1-65535', sim_ip='8.8.8.8'):
        super().__init__(name, host, port)

        self.ntor_pvk, self.ntor_puk = curve25519_setup()
        self.ed_pvk, self.ed_puk = ed25519_setup()
        self.ed_sign_sk, self.ed_sign_pk = ed25519_setup()

        self.rsa_id_sk, _ = rsa_setup()
        self.rsa_onion_sk, _ = rsa_setup()
        self.tls_cert_der = rsa_id_x509_der(self.cert_file)

        self.circuit_list = Tor_CircuitsList()
        self.protocol_version = NtorServerKeyAgreement(rsa_identity_digest(self.rsa_id_sk), self.ntor_pvk)
        self.flags = flags
        self.protocols = protocols
        self.exit_policy = exit_policy
        self.sim_ip = sim_ip
        self.print(self.sim_ip)
        self.start_time = time.time()
        now_hr = int(self.start_time // 3600)
        self.exp_hr = now_hr + 24 * 7
        self.dns_solver = DNSResolver(nameservers=["1.1.1.1", "8.8.8.8", "9.9.9.9"], timeout=1.5, lifetime=3.0)


    async def start_protocol(self):
        self.tasks['routing_task'] = asyncio.create_task(self.register_to_dire())
        self.tasks['listener_task'] = asyncio.create_task(self.monitor_tor_socket())

        await asyncio.gather(*self.tasks.values())

    async def register_to_dire(self):
        descriptor = self.generate_descriptor()
        await self.upload_descriptor_to_dirserver(descriptor, self.dire_ip, self.dire_port)

    async def upload_descriptor_to_dirserver(self,
                                             descriptor_text: str,
                                             dirserver_ip: str,
                                             dirserver_port: int = 80,
                                             path: str = "/tor/"
                                             ) -> None:
        """
        异步上传 server descriptor 到目录服务器
        """
        url = f"http://{dirserver_ip}:{dirserver_port}{path}"
        headers = {
            "User-Agent": "Tor 0.4.8.17 on Python",
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
            master_ed_sk=self.ed_pvk,
            curve_sk=self.ntor_pvk,
            rsa_sk=self.rsa_pvk,
            or_port=self.port,
            protocols=self.protocols,
            exit_policy=self.exit_policy,
            sim_flag=self.get_sim_flag(),
            sim_ip=self.sim_ip,
            rsa_id_sk=self.rsa_id_sk,
            rsa_onion_sk=self.rsa_onion_sk,
            signing_ed_sk=self.ed_sign_sk,
            start_time=self.start_time,
        )
        descriptor = desc_build.build()
        return descriptor

    def get_sim_flag(self) -> str:
        sim_flag = "opt sim-flags"
        for flag in self.flags:
            sim_flag += ' ' + flag
        return sim_flag

    async def create_circuit(self, create_cell, sock, circuit_id):
        """Quickly select several random nodes and freely add nodes, such as exit nodes"""
        circuit = await self.circuit_list.create_circuit_server(circuit_id)
        created_cell = circuit.server_connected(self.protocol_version, create_cell, sock)
        await sock.send_cell(created_cell)
        return circuit

    async def extend_next_node(self, cell: CellRelayExtend2, circuit_id: int):
        ip = cell.ip
        port = cell.port
        addr = (ip, port)
        skin = cell.skin
        handshake_type = cell.finger_type
        print("pd:01")
        create2 = Cell_Create2(handshake_type=handshake_type, onion_skin=skin, circuit_id=circuit_id)
        print("pd:02")
        sock = self.socket_map.get(addr, None)
        print("pd:03")

        if sock is None:
            print("pd:04")
            sock = Tor_Socket(source_ip=self.host, on_cell=self.handle_cell)
            await sock.setup_socket(remote_addr=addr)
            print("build a new socket from: ", addr)
            asyncio.create_task(self.handle_connection(addr, sock))
            await sock.tor_handshake_client()
        circuit = self.circuit_list.get_by_id(circuit_id)
        print("pd:05")

        simple_node = Tor_Router_simple(sock)
        print("pd:06")

        circuit.circuit_nodes.append(simple_node)
        print("pd:07")

        await sock.send_cell(create2)

    async def reply_extend(self, cell: CellCreated2):
        circuit_id = cell.circuit_id
        handshake_data = cell.handshake_data
        extend_cell = CellRelayExtended2(handshake_data, circuit_id)
        circuit = self.circuit_list.get_by_id(circuit_id)
        cell = circuit.make_relay(inner_cell=extend_cell, relay_type=CellRelay)
        sock = circuit.circuit_nodes[0].sock
        await sock.send_cell(cell)

    async def handle_cell(self, cell, sock: Tor_Socket):
        self.print(f"receive cell from {sock.socket.getpeername()}")
        self.print("cell content:", cell)

        if isinstance(cell, CellVersions):
            if not sock.handshake_initiator:
                certs_cell = self.make_certs_cell()
                await sock.tor_handshake_server(cell, certs_cell, self.cert_file)
            else:
                sock.protocal.version = sock.handshake.retrieve_versions(cell)
        elif isinstance(cell, CellCerts):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            self.print("receive CellAuthChallenge", CellAuthChallenge)
            self.print("receive CellAuthChallenge content", cell.challenge)
            self.print("receive CellAuthChallenge method", cell.methods)
            # sock.handshake.handle_cell_auth_challenge(cell)
        elif isinstance(cell, CellNetInfo):
            sock.handshake.retrieve_net_info(cell)
        elif isinstance(cell, Cell_Create2):
            await self.create_circuit(cell, sock, cell.circuit_id)
        elif isinstance(cell, CellCreated2):
            await self.reply_extend(cell)
        elif isinstance(cell, CellAuthenticate):  # or cmd == 131
            self.print("receive a recv_authenticate")
            sock.handshake.recv_authenticate(cell)
        elif isinstance(cell, CellRelay):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            if sock == circuit.circuit_nodes[0].sock:
                inner_cell = circuit.handle_relay(cell)
                await self.handle_cell_relay(inner_cell, circuit, cell, sock)
            else:
                next_node = circuit.circuit_nodes[0]
                next_node.encrypt_forward(cell)
                await next_node.sock.send_cell(cell)
        elif isinstance(cell, Cell_RelayEarly):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            inner_cell = circuit.handle_relay(cell)
            await self.handle_cell_relay(inner_cell, circuit, cell, sock)
        elif isinstance(cell, CellDestroy):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            if sock == circuit.circuit_nodes[0].sock:
                next_hop_sock = circuit.circuit_nodes[-1].sock
            else:
                next_hop_sock = circuit.circuit_nodes[0].sock
            await next_hop_sock.send_cell(cell)
            circuit.close_all_streams()
            for node in circuit.circuit_nodes:
                sock = getattr(node, 'socket', None)
                if sock:
                    try:
                        sock.sock.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        sock.close()
                    except Exception:
                        pass
            circuit.circuit_nodes.clear()
            self.circuit_list.remove(cell.circuit_id)


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
            ip_address = await self.resolve_ipv4_async(host)
            connected_cell = CellRelayConnected(ip_address, 0, origin_cell.circuit_id)

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
            await self.handle_data_relay(circuit, cell, origin_cell, sock)
        elif isinstance(cell, CellRelaySendMe):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.window.package_inc()

    async def handle_data_relay(self, circuit, cell, origin_cell, sock):
        stream = circuit.streams.get_by_id(origin_cell.stream_id)
        stream.append(cell.data)  # 上行数据 -> stream 内部 buffer

        loop = asyncio.get_running_loop()
        deadline = loop.time() + 0.05  # 50ms 抽干窗口；可调为 20–100ms

        while True:
            try:
                # 建议把 coalesce_bytes 设成 498 的倍数，减少小尾巴 cell
                chunk = await stream.extract_guessed_message_from_buffer(
                    timeout_ms=20, coalesce_bytes=498 * 64
                )
            except Exception:
                # 发生异常：发送 END(Internal/Misc)
                end = CellRelayEnd(StreamReason(10), circuit.id)  # INTERNAL=10（或按你的枚举）
                relay = circuit.make_relay(inner_cell=end, relay_type=CellRelay,
                                           stream_id=origin_cell.stream_id)
                await sock.send_cell(relay)
                break

            if chunk is None:
                # 暂无可回写数据：在窗口内再试；超时后退出本轮
                if loop.time() < deadline:
                    continue
                break

            if chunk == b'':
                # 远端 EOF，正常结束
                end = CellRelayEnd(StreamReason(6), circuit.id)  # DONE=6
                relay = circuit.make_relay(inner_cell=end, relay_type=CellRelay,
                                           stream_id=origin_cell.stream_id)
                await sock.send_cell(relay)
                break

            # 有数据：切分为 RelayData cells 发送
            for rc in stream.make_relays_server(chunk):
                await sock.send_cell(rc)

    async def resolve_ipv4_async(self, domain: str) -> str:
        ip = await self.dns_solver.resolve_ipv4(domain)
        return ip



    async def close_stream(self, stream):
        items = self.socket_map.items()
        for addr, sock in items:
            if sock:
                end_cell = stream.make_end
                await sock.send_cell(end_cell)
            else:
                raise "socket has closed before stream"
        stream.close()

    def make_certs_cell(self) -> CellCerts:
        # 1) type 4  identity->signing   (Ed master -> Ed signing)
        ed_id_pub32 = self.ed_puk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_sign_pub32 = self.ed_sign_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        cert4 = build_ed25519_cert(
            cert_type=CT_ED_ID_SIGNING,
            issuer_sk=self.ed_pvk,
            subject_key_bytes=ed_sign_pub32,
            exp_hours=self.exp_hr,
            issuer_pub_for_ext=ed_id_pub32,
            keytype=1
        )

        # 2) type 5  signing->TLS  (Ed signing -> TLS key)
        # 规范要求 subject_key 为 TLS 公钥的“raw 表示”或其哈希。Tor 用 32B SHA256(pubkey) 前 32 字节。
        tls_hash32 = hashlib.sha256(self.tls_cert_der).digest()[:32]
        cert5 = build_ed25519_cert(
            cert_type=CT_ED_SIGNING_TLS,
            issuer_sk=self.ed_sign_sk,
            subject_key_bytes=tls_hash32,
            exp_hours=self.exp_hr,
            issuer_pub_for_ext=ed_sign_pub32,
            keytype=2
        )
        # 3) type 7  RSA->Ed crosscert
        cert7 = build_rsa_to_ed_crosscert(
            self.rsa_id_sk,
            ed_id_pub32,
            self.exp_hr,  # __init__ 里算好的那个小时数
        )
        # 4) type 2  RSA ID X.509
        cert2 = rsa_identity_x509_der(self.rsa_id_sk)  # 直接 DER



        return CellCerts([
            (CT_RSA_ID_X509, cert2),
            (CT_ED_ID_SIGNING, cert4),
            (CT_ED_SIGNING_TLS, cert5),
            (CT_RSA_TO_ED_CROSS, cert7),
        ])

