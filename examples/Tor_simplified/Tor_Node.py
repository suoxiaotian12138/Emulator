import asyncio
import requests
import time, hashlib
import ipaddress
import contextlib
from tools.Crypt.key_generator import curve25519_setup, ed25519_setup, rsa_setup
from tools.Crypt.crypt_common import rsa_identity_digest
from tools.Network_Management.DNSResolver import DNSResolver
from tools.Log.utils import HopTimer, classify_exception, FailReason

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
from collections import defaultdict
from tools.Network_Management.delay_env import get_args

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
        self.start_time = time.time()
        now_hr = int(self.start_time // 3600)
        self.exp_hr = now_hr + 24 * 7
        self.dns_solver = DNSResolver(use_cache=True, nameservers=["223.5.5.5","114.114.114.114"], timeout=1.0, lifetime=2.0, min_ttl=5, max_ttl=1800, neg_ttl=20, parallel_ns=True)
        self._socket_locks = defaultdict(asyncio.Lock)

        self._relay_bytes = {}  # key=(circ_id, stream_id, direction) -> {"bytes":0,"cells":0,"t0":mono_ns}
        self._relay_agg = {}
        self._relay_flush_task = self._spawn_bg_task(self._flush_relay_agg())


    async def start_protocol(self):
        self.tasks['routing_task'] = self._spawn_bg_task(self.register_to_dire())
        self.tasks['listener_task'] = self._spawn_bg_task(self.monitor_tor_socket())

        await asyncio.gather(*self.tasks.values())

    async def register_to_dire(self):
        try:
            descriptor = self.generate_descriptor()
            await self.upload_descriptor_to_dirserver(descriptor, self.dire_ip, self.dire_port)
            self._ev("descriptor_upload_ok", url=f"{self.dire_ip}:{self.dire_port}", bytes=len(descriptor))
        except Exception as e:
            self._ev("descriptor_upload_fail", error=str(e))

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
        t0 = time.perf_counter()
        circuit = await self.circuit_list.create_circuit_server(circuit_id)

        created_cell = circuit.server_connected(self.protocol_version, create_cell, sock)
        self._ev("circuit_server_connected", circ_id=circuit_id, peer=str(sock.socket.getpeername()), ms=(time.perf_counter()-t0)*1000.0)
        await sock.send_cell(created_cell)
        return circuit

    async def extend_next_node(self, cell: CellRelayExtend2, circuit_id: int):
        ip = cell.ip
        port = cell.port
        addr = (ip, port)
        skin = cell.skin
        handshake_type = cell.finger_type

        sock = self.socket_map.get(addr, None)
        if sock is None:
            lock = self._socket_locks[addr]
            async with lock:
                sock = self.socket_map.get(addr, None)
                if sock is None:
                    t_tls = time.perf_counter()
                    try:
                        sock = await Tor_Socket.dial(remote_addr=addr, source_ip=self.host, on_cell=self.handle_cell, node_id=self.node_id, **get_args(sim_ip=self.sim_ip))
                        print("build a new socket from: ", addr)
                        self._spawn_bg_task(self.handle_connection(addr, sock))
                        await sock.listen_started.wait()
                        self._ev("tls_handshake_done", peer=f"{ip}:{port}", side="client", ms=(time.perf_counter() - t_tls) * 1000.0)
                    except Exception as e:
                        self._ev("tls_handshake_fail", peer=f"{ip}:{port}", side="client", fail_reason=FailReason.TLS_FAIL.value, error=str(e), ms=(time.perf_counter() - t_tls) * 1000.0)
                        raise

                    # Tor 链路握手
                    t_tor = time.perf_counter()
                    try:
                        await sock.tor_handshake_client()
                        self._ev("tor_handshake_done", peer=f"{ip}:{port}", side="client", version=getattr(sock.protocol, "version", None), ms=(time.perf_counter() - t_tor) * 1000.0)
                    except Exception as e:
                        self._ev("tor_handshake_fail", peer=f"{ip}:{port}", side="client", fail_reason=FailReason.NTOR_FAIL.value, error=str(e), version=getattr(sock.protocol, "version", None), ms=(time.perf_counter() - t_tor) * 1000.0)
                        raise

        await sock.handshake_done.wait()

        circuit = self.circuit_list.get_by_id(circuit_id)
        simple_node = Tor_Router_simple(sock)
        circuit.circuit_nodes.append(simple_node)

        # 发送下游 CREATE2，计时并记录是否成功（下游会回 EXTENDED2）
        create2 = Cell_Create2(handshake_type=handshake_type, onion_skin=skin, circuit_id=circuit_id)
        t_ext = time.perf_counter()
        try:
            await sock.send_cell(create2)
            self._ev("circuit_extend_downstream_sent",
                     circ_id=circuit_id, target=f"{ip}:{port}")
        except Exception as e:
            self._ev("circuit_extend_downstream_fail",
                     circ_id=circuit_id, target=f"{ip}:{port}", error=str(e),
                     ms=(time.perf_counter() - t_ext) * 1000.0)
            raise

    async def reply_extend(self, cell: CellCreated2):
        circuit_id = cell.circuit_id
        handshake_data = cell.handshake_data
        extend_cell = CellRelayExtended2(handshake_data, circuit_id)
        circuit = self.circuit_list.get_by_id(circuit_id)
        cell = circuit.make_relay(inner_cell=extend_cell, relay_type=CellRelay)
        sock = circuit.circuit_nodes[0].sock
        await sock.send_cell(cell)

    def _cw_send(self, circuit, out_sock: Tor_Socket):
        """
        Pick circuit window for sending DATA on the outgoing link.
        Send to upstream uses circ_window_up, else circ_window_down.
        """
        upstream = circuit.circuit_nodes[0].sock
        return circuit.circ_window_up if out_sock == upstream else circuit.circ_window_down

    def _cw_recv(self, circuit, in_sock: Tor_Socket):
        """
        Pick circuit window for receiving DATA from the incoming link.
        DATA coming from upstream belongs to downstream direction, so use circ_window_down.
        DATA coming from downstream belongs to upstream direction, so use circ_window_up.
        """
        upstream = circuit.circuit_nodes[0].sock
        return circuit.circ_window_down if in_sock == upstream else circuit.circ_window_up

    async def _forward_relay_cell(self, circuit, in_sock: Tor_Socket, out_sock: Tor_Socket, cell):
        """
        Tor-like forwarding:
        - Only RELAY_DATA consumes circuit send credit.
        - Control relay cells (BEGIN, CONNECTED, END, SENDME, EXTEND2...) do not consume credit.
        - Direction is defined by *outgoing* link: if we send toward upstream then use circ_window_up,
          if we send toward downstream then use circ_window_down.
        """
        # Determine outgoing direction by out_sock
        # upstream is circuit_nodes[0].sock
        upstream_sock = circuit.circuit_nodes[0].sock
        sending_to_upstream = (out_sock == upstream_sock)

        cw = self._cw_send(circuit, out_sock)

        # If this is a RELAY cell, we can peek relay command from serialized payload only if you already parsed it.
        # Here we rely on the already-decoded "inner_cell" if caller has it; otherwise treat as not-data.
        is_data = False
        try:
            # You already call circuit.handle_relay(cell) in some branches.
            # If caller attached inner_cell on cell for convenience, use it.
            inner = getattr(cell, "_inner", None)
            is_data = isinstance(inner, CellRelayData)
        except Exception:
            is_data = False

        if is_data:
            await cw.acquire_send(1)

        await out_sock.send_cell(cell)

    async def handle_cell(self, cell, sock: Tor_Socket):
        self.print(f"receive cell from {sock.socket.getpeername()}")
        self.print("cell content:", cell)

        if isinstance(cell, CellVersions):
            if not sock.handshake_initiator:
                certs_cell = self.make_certs_cell()
                t_tor = time.perf_counter()
                try:
                    await sock.tor_handshake_server(cell, certs_cell, self.cert_file)
                    self._ev("tor_handshake_done",peer=str(sock.socket.getpeername()), side="server",version=getattr(sock.protocol, "version", None),ms=(time.perf_counter() - t_tor) * 1000.0)
                except Exception as e:
                    self._ev("tor_handshake_fail",peer=str(sock.socket.getpeername()), side="server",error=str(e),version=getattr(sock.protocol, "version", None),ms=(time.perf_counter() - t_tor) * 1000.0)
                    raise
            else:
                sock.protocol.version = sock.handshake.retrieve_versions(cell)
        elif isinstance(cell, CellCerts):
            sock.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            # self.print("receive CellAuthChallenge", CellAuthChallenge)
            # self.print("receive CellAuthChallenge content", cell.challenge)
            # self.print("receive CellAuthChallenge method", cell.methods)
            # sock.handshake.handle_cell_auth_challenge(cell)
            pass
        elif isinstance(cell, CellNetInfo):
            sock.handshake.retrieve_net_info(cell)
            sock.handshake_done.set()  # 关键：握手以收齐NETINFO为完成点
        elif isinstance(cell, Cell_Create2):
            await self.create_circuit(cell, sock, cell.circuit_id)
        elif isinstance(cell, CellCreated2):
            await self.reply_extend(cell)
        elif isinstance(cell, CellAuthenticate):  # or cmd == 131
            # self.print("receive a recv_authenticate")
            sock.handshake.recv_authenticate(cell)
        elif isinstance(cell, CellRelay):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)

            if sock == circuit.circuit_nodes[0].sock:
                # upstream -> this hop: peel one layer
                inner_or_relay = circuit.handle_relay(cell)

                # NOT RECOGNIZED: still encrypted, must be forwarded downstream
                if isinstance(inner_or_relay, RelayedTorCell) and inner_or_relay.is_encrypted:
                    out_sock = circuit.circuit_nodes[-1].sock
                    await out_sock.send_cell(cell)
                    return

                # RECOGNIZED: handle inner cell locally
                await self.handle_cell_relay(inner_or_relay, circuit, cell, sock)
                return

            # downstream -> upstream: add one layer and forward upstream
            next_node = circuit.circuit_nodes[0]
            next_node.encrypt_forward(cell)
            await next_node.sock.send_cell(cell)

        elif isinstance(cell, Cell_RelayEarly):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            inner_cell = circuit.handle_relay(cell)
            await self.handle_cell_relay(inner_cell, circuit, cell, sock)
        elif isinstance(cell, CellDestroy):
            circuit = self.circuit_list.get_by_id(cell.circuit_id)
            self._ev("circuit_destroy_forwarded", circ_id=cell.circuit_id, from_side=("upstream" if sock == circuit.circuit_nodes[0].sock else "downstream"))
            if sock == circuit.circuit_nodes[0].sock:
                next_hop_sock = circuit.circuit_nodes[-1].sock
            else:
                next_hop_sock = circuit.circuit_nodes[0].sock
            await next_hop_sock.send_cell(cell)
            circuit.close_all_streams()
            circuit.circuit_nodes.clear()
            self.circuit_list.remove(cell.circuit_id)


    async def handle_cell_relay(self, cell, circuit, origin_cell, sock):
        self.print("inner_cell:", cell)
        if isinstance(cell, CellRelayExtend2):
            await self.extend_next_node(cell, circuit.id)
        elif isinstance(cell, Cell_RelayEarly):
            if sock == circuit.circuit_nodes[0].sock:
                out_sock = circuit.circuit_nodes[-1].sock
            else:
                out_sock = circuit.circuit_nodes[0].sock
            # origin_cell already carries encrypted relay payload; use origin_cell for forwarding
            setattr(origin_cell, "_inner", cell)
            await self._forward_relay_cell(circuit, in_sock=sock, out_sock=out_sock, cell=origin_cell)

        elif isinstance(cell, CellRelay):
            if sock == circuit.circuit_nodes[0].sock:
                out_sock = circuit.circuit_nodes[-1].sock
            else:
                out_sock = circuit.circuit_nodes[0].sock
            setattr(origin_cell, "_inner", cell)
            await self._forward_relay_cell(circuit, in_sock=sock, out_sock=out_sock, cell=origin_cell)

        elif isinstance(cell, CellRelayBegin):
            cid = circuit.id
            sid = origin_cell.stream_id
            host = cell.address
            port = cell.port
            self._ev("begin_rx", circ_id=cid, stream_id=sid, host=host, port=port)

            try:
                ip_address = await self.resolve_ipv4_async(host)
                addr = (ip_address, port)
                # 先建 stream，并写入 target_addr
                stream = circuit.streams.set_stream(stream_id=sid, target_addr=addr)
                self._spawn_bg_task(self._exit_connect_and_start(circuit, sock, sid), name=f"exit_connect:{cid}:{sid}")
                # ★关键：立刻回 CONNECTED，避免 client 卡在 wait_connect_ack
                connected = CellRelayConnected(address=ip_address, ttl=3600, circuit_id=cid)
                relay_conn = circuit.make_relay(inner_cell=connected, relay_type=CellRelay, stream_id=sid)
                await sock.send_cell(relay_conn)
                self._ev("begin_connected_tx", circ_id=cid, stream_id=sid, dst=f"{ip_address}:{port}")

                # ★关键：异步连 TCP 并启动双向转发，但必须被追踪可取消

            except Exception as e:
                end = CellRelayEnd(StreamReason.INTERNAL, cid)
                relay = circuit.make_relay(inner_cell=end, relay_type=CellRelay, stream_id=sid)
                await sock.send_cell(relay)
                self._ev("begin_fail", circ_id=cid, stream_id=sid, error=repr(e))

        elif isinstance(cell, CellRelayConnected):
            stream = circuit.streams.get_by_id(origin_cell.stream_id)
            stream.connect_event.set()
        elif isinstance(cell, CellRelayEnd):
            sid = origin_cell.stream_id
            stream = circuit.streams.get_by_id(sid)
            if stream is not None:
                # 告诉 pump_to_remote：上游不再发了，去 write_eof
                await stream._to_remote.put(None)

            # 不要在 node 端 recv 应用层数据
            # 统计部分你原样保留即可
            key_up = (circuit.id, sid, "up")
            key_dn = (circuit.id, sid, "down")
            for k in (key_up, key_dn):
                st = self._relay_bytes.pop(k, None)
                if st:
                    self._ev("relay_agg", circ_id=circuit.id, stream_id=sid,
                             direction=k[2], bytes=st["bytes"], cells=st["cells"], interval_ms=None)

        elif isinstance(cell, CellRelayData):
            cid = circuit.id
            sid = origin_cell.stream_id

            # Determine where to forward if we are not the exit consumer for this stream.
            if sock == circuit.circuit_nodes[0].sock:
                out_sock = circuit.circuit_nodes[-1].sock
                direction = "down"
            else:
                out_sock = circuit.circuit_nodes[0].sock
                direction = "up"

            stream = circuit.streams.get_by_id(sid)

            # We are an exit consumer only if this stream has a live remote TCP endpoint.
            # Otherwise (no stream, or TCP not connected yet), this node must behave as a relay:
            # forward the cell and do NOT touch recv windows / do NOT generate SENDME.
            is_exit_consumer = (
                    stream is not None and
                    (stream._remote_writer is not None or stream._remote_reader is not None)
            )

            if not is_exit_consumer:
                # Relay behavior: forward original encrypted relay cell.
                setattr(origin_cell, "_inner", cell)
                await self._forward_relay_cell(circuit, in_sock=sock, out_sock=out_sock, cell=origin_cell)

                # stats (keep your accounting)
                key = (cid, sid, direction)
                st = self._relay_bytes.get(key)
                if not st:
                    st = self._relay_bytes[key] = {"bytes": 0, "cells": 0, "t0": time.monotonic_ns()}
                st["bytes"] += len(cell.data)
                st["cells"] += 1
                return

            # ==========================
            # Exit consumer behavior
            # ==========================

            # --- circuit-level recv window ---
            cw = self._cw_recv(circuit, sock)
            cw.on_recv_data_cell(1)

            if cw.should_send_sendme():
                # circuit-level SENDME: stream_id = 0, send back toward the sender on this link
                sendme_inner = CellRelaySendMe(circuit_id=cid)
                circ_sendme = circuit.make_relay(inner_cell=sendme_inner, relay_type=CellRelay, stream_id=0)
                await sock.send_cell(circ_sendme)

                st = self._relay_agg.get((cid, 0))
                if not st:
                    st = self._relay_agg[(cid, 0)] = {
                        "up_bytes": 0, "up_cells": 0,
                        "down_bytes": 0, "down_cells": 0,
                        "sendme_sent": 0, "sendme_recv": 0,
                        "last_win": None,
                    }
                st["sendme_sent"] = st.get("sendme_sent", 0) + 1
                st["last_win"] = cw.send_window

            # --- stream-level recv window ---
            stream.window.on_recv_data_cell(1)

            if stream.window.should_send_sendme():
                sendme_cell = stream.make_sendme()  # stream_id = sid
                await sock.send_cell(sendme_cell)

                st = self._relay_agg.get((cid, sid))
                if not st:
                    st = self._relay_agg[(cid, sid)] = {
                        "up_bytes": 0, "up_cells": 0,
                        "down_bytes": 0, "down_cells": 0,
                        "sendme_sent": 0, "sendme_recv": 0,
                        "last_win": None,
                    }
                st["sendme_sent"] = st.get("sendme_sent", 0) + 1
                st["last_win"] = stream.window.send_window

            # deliver to local TCP forwarder
            await stream._to_remote.put(cell.data)

            # stats
            key = (cid, sid, direction)
            st = self._relay_bytes.get(key)
            if not st:
                st = self._relay_bytes[key] = {"bytes": 0, "cells": 0, "t0": time.monotonic_ns()}
            st["bytes"] += len(cell.data)
            st["cells"] += 1

        elif isinstance(cell, CellRelaySendMe):
            cid = circuit.id
            sid = origin_cell.stream_id

            if sid == 0:
                cw = self._cw_send(circuit, out_sock=sock)
                cw.on_recv_sendme()

                st = self._relay_agg.get((cid, sid))
                if not st:
                    st = self._relay_agg[(cid, sid)] = {
                        "up_bytes": 0, "up_cells": 0,
                        "down_bytes": 0, "down_cells": 0,
                        "sendme_sent": 0, "sendme_recv": 0,
                        "last_win": None,
                    }
                st["sendme_recv"] = st.get("sendme_recv", 0) + 1
                st["last_win"] = cw.send_window

            else:
                # ---- stream-level SENDME ----
                stream = circuit.streams.get_by_id(sid)
                if stream is not None:
                    stream.window.on_recv_sendme()

                st = self._relay_agg.get((cid, sid))
                if not st:
                    st = self._relay_agg[(cid, sid)] = {
                        "up_bytes": 0, "up_cells": 0,
                        "down_bytes": 0, "down_cells": 0,
                        "sendme_sent": 0, "sendme_recv": 0,
                        "last_win": None,
                    }
                st["sendme_recv"] = st.get("sendme_recv", 0) + 1
                if stream is not None:
                    st["last_win"] = stream.window.send_window

    async def _exit_connect_and_start(self, circuit, sock, sid: int):
        stream = circuit.streams.get_by_id(sid)
        if stream is None:
            return

        try:
            # 这里会真的 dial TCP
            await stream.open_remote_raw(timeout=5.0)

            # 启动双向转发
            stream.start_duplex_tasks(
                circuit=circuit,
                sock=sock,
                cw_picker=self._cw_send  # 你原来传的 cw_picker 用什么就填什么
            )

            self._ev("exit_tcp_connected", circ_id=circuit.id, stream_id=sid, dst=str(stream.target_addr))

        except asyncio.CancelledError:
            # stop_protocol 时会 cancel，正常退出
            with contextlib.suppress(Exception):
                await stream.aclose()
            raise

        except Exception as e:
            # ★关键：不要吞异常，否则你只看到 INTERNAL，不知道为什么
            self._ev("exit_tcp_connect_fail", circ_id=circuit.id, stream_id=sid, dst=str(stream.target_addr),
                     error=repr(e))

            # 失败就发 END，唤醒 client 侧收尾
            with contextlib.suppress(Exception):
                end = CellRelayEnd(StreamReason.INTERNAL, circuit.id)
                relay = circuit.make_relay(inner_cell=end, relay_type=CellRelay, stream_id=sid)
                await sock.send_cell(relay)

            with contextlib.suppress(Exception):
                await stream.aclose()

    async def resolve_ipv4_async(self, domain: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(domain)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                ip_str = str(ip_obj)
                self._ev("dns_bypass_ip_literal", domain=domain, ip=ip_str, ms=0.0)
                return ip_str
        except ValueError:
            # Not an IP literal, fall back to real DNS
            pass
        t0 = time.perf_counter()
        try:
            ip = await self.dns_solver.resolve_ipv4(domain)
            self._ev("dns_resolve_ok", domain=domain, ip=ip, ms=(time.perf_counter() - t0) * 1000.0)
            print(f"[DNS] {domain} -> {ip}")
            return ip
        except Exception as e:
            self._ev("dns_resolve_fail", domain=domain,fail_reason=FailReason.UNREACHABLE.value, error=str(e), ms=(time.perf_counter() - t0) * 1000.0)
            raise


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

    async def _flush_relay_agg(self, interval_ms: int = 500):
        try:
            while True:
                await asyncio.sleep(interval_ms / 1000)
                current, self._relay_agg = self._relay_agg, {}
                for (cid, sid), st in current.items():
                    # 上下行分两条写，便于画双向曲线
                    if st.get("up_cells", 0) or st.get("up_bytes", 0):
                        self._ev("relay_agg", circ_id=cid, stream_id=sid, direction="up",
                                 bytes=st.get("up_bytes", 0), cells=st.get("up_cells", 0),
                                 sendme_sent=st.get("sendme_sent", 0), sendme_recv=st.get("sendme_recv", 0),
                                 win_cur=st.get("last_win", None), sample_ms=interval_ms)
                    if st.get("down_cells", 0) or st.get("down_bytes", 0):
                        self._ev("relay_agg", circ_id=cid, stream_id=sid, direction="down",
                                 bytes=st.get("down_bytes", 0), cells=st.get("down_cells", 0),
                                 sendme_sent=st.get("sendme_sent", 0), sendme_recv=st.get("sendme_recv", 0),
                                 win_cur=st.get("last_win", None), sample_ms=interval_ms)
        except asyncio.CancelledError:
            pass  # 正常退出




