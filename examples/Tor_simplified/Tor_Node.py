import asyncio
import requests
import time, hashlib
import ipaddress
import contextlib
from tools.Crypt.key_generator import curve25519_setup, ed25519_setup, rsa_setup
from tools.Crypt.crypt_common import rsa_identity_digest
from tools.Network_Management.DNSResolver import DNSResolver
from tools.Log.utils import HopTimer, classify_exception, FailReason
from collections import defaultdict
from examples.Tor_simplified.Tor_Cell import *
from examples.Tor_simplified.Tor_base import Tor_base
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.circid_alloc import allocate_circid, validate_incoming_create_circid
from examples.Tor_simplified.Tor_Descriptor import TorDescriptor_build
from examples.Tor_simplified.Tor_Router import Tor_Router_simple
from examples.Tor_simplified.Tor_Crypt import NtorServerKeyAgreement
from examples.Tor_simplified.Tor_Socket import Tor_Socket
from examples.Tor_simplified.Tor_Scheduler import CircuitSendScheduler
from tools.Network_Management.bandwidth_env import get_limiter
from cryptography.hazmat.primitives import serialization, hashes
from tools.Crypt.crypt_common import (
    build_ed25519_cert, build_rsa_to_ed_crosscert,
    rsa_id_x509_der, rsa_pubkey_spki_der, rsa_identity_x509_der,
    CT_RSA_ID_X509, CT_ED_ID_SIGNING, CT_ED_SIGNING_TLS, CT_RSA_TO_ED_CROSS, CT_ED_SIGNING_LINK_AUTH,
    debug_build_crosscert
)
from examples.Tor_simplified.Tor_Cell import CellCerts
from tools.Network_Management.delay_env import get_args

class Tor_Node(Tor_base):
    def __init__(self, name: str, host: str, port: int, flags,
                 protocols: str = "Cons=2 Desc=2 DirCache=2 FlowCtrl=2 Link=4-5 LinkAuth=3 Microdesc=2 Padding=2 Relay=4",
                 exit_policy: str = 'accept 1-65535', sim_ip='8.8.8.8'):
        super().__init__(name, host, port)

        self.ntor_pvk, self.ntor_puk = curve25519_setup()
        # Identity key: long-term Ed25519 master key used for relay identity proofs.
        self.ed_pvk, self.ed_puk = ed25519_setup()
        # Identity key: long-term Ed25519 master key used for relay identity proofs.
        self.ed_sign_sk, self.ed_sign_pk = ed25519_setup()
        # Link authentication key: dedicated Ed25519 key for authenticating the OR link.
        self.link_auth_sk, self.link_auth_pk = ed25519_setup()

        # Backward-compatible aliases for legacy call sites expecting ks_link_* names.
        self.ks_link_sk, self.ks_link_pk = self.link_auth_sk, self.link_auth_pk

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

        self._circuit_scheduler = CircuitSendScheduler(self)

    async def start_protocol(self):
        self.tasks['routing_task'] = self._spawn_bg_task(self.register_to_dire())
        self.tasks['listener_task'] = self._spawn_bg_task(self.monitor_tor_socket())

        await asyncio.gather(*self.tasks.values())

    async def register_to_dire(self):
        try:
            descriptor = self.generate_descriptor()
            await self.upload_descriptor_to_dirserver(descriptor, self.dire_ip, self.dire_port)
            # self._ev("descriptor_upload_ok", url=f"{self.dire_ip}:{self.dire_port}", bytes=len(descriptor))
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
        await sock.ensure_handshake_complete()
        validate_incoming_create_circid(sock.channel, circuit_id, remote_initiator=not sock.handshake_initiator)
        circuit = await self.circuit_list.create_circuit_server(circuit_id, sock.channel)
        circuit.scheduler = self._circuit_scheduler
        # self._ev(
        #     "cell_trace", circ_id=circuit_id, peer=str(sock.socket.getpeername()),
        #     side="node", dir="recv", cell_cmd="CREATE2"
        # )
        created_cell = circuit.server_connected(self.protocol_version, create_cell, sock)
        # self._ev("circuit_server_connected", circ_id=circuit_id, peer=str(sock.socket.getpeername()), ms=(time.perf_counter()-t0)*1000.0)
        await sock.send_cell(created_cell)
        # self._ev(
        #     "cell_trace", circ_id=circuit_id, peer=str(sock.socket.getpeername()),
        #     side="node", dir="send", cell_cmd="CREATED2"
        # )
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
                        limiter = get_limiter(self.node_id)
                        sock = await Tor_Socket.dial(
                            remote_addr=addr,
                            source_ip=self.host,
                            on_cell=self.handle_cell,
                            node_id=self.node_id,
                            role="relay",
                            rsa_identity_key=self.rsa_id_sk,
                            ed_identity_key=self.ed_pvk,
                            ed_signing_key=self.ed_sign_sk,
                            link_auth_key=self.link_auth_sk,
                            tls_cert_der=self.tls_cert_der,
                            limiter=limiter,
                            **get_args(sim_ip=self.sim_ip)
                        )
                        print("build a new socket from: ", addr)
                        self._spawn_bg_task(self.handle_connection(addr, sock))
                        await sock.listen_started.wait()
                        # self._ev("tls_handshake_done", peer=f"{ip}:{port}", side="client", ms=(time.perf_counter() - t_tls) * 1000.0)
                    except Exception as e:
                        # self._ev("tls_handshake_fail", peer=f"{ip}:{port}", side="client", fail_reason=FailReason.TLS_FAIL.value, error=str(e), ms=(time.perf_counter() - t_tls) * 1000.0)
                        raise

                    # Tor 链路握手
                    t_tor = time.perf_counter()
                    try:
                        await sock.tor_handshake_client(
                            authenticate=True,
                            certs_cell=self.make_certs_cell_initiator(),
                        )
                        # self._ev("tor_handshake_done", peer=f"{ip}:{port}", side="client", version=getattr(sock.protocol, "version", None), ms=(time.perf_counter() - t_tor) * 1000.0)
                    except Exception as e:
                        # self._ev("tor_handshake_fail", peer=f"{ip}:{port}", side="client", fail_reason=FailReason.NTOR_FAIL.value, error=str(e), version=getattr(sock.protocol, "version", None), ms=(time.perf_counter() - t_tor) * 1000.0)
                        raise


        async def _send_extend():
            await sock.ensure_handshake_complete()

            circuit = self.circuit_list.get_by_id(circuit_id)
            simple_node = Tor_Router_simple(sock)
            circuit.circuit_nodes.append(simple_node)

            circid_out = allocate_circid(sock.channel)
            circuit.bind_next(sock.channel, circid_out)

            # 发送下游 CREATE2，计时并记录是否成功（下游会回 EXTENDED2）
            create2 = Cell_Create2(handshake_type=handshake_type, onion_skin=skin, circuit_id=circid_out)
            t_ext = time.perf_counter()
            try:
                await sock.send_cell(create2)
                # self._ev("circuit_extend_downstream_sent",
                #          circ_id=circuit_id, target=f"{ip}:{port}")
                # self._ev(
                #     "cell_trace", circ_id=circuit_id, peer=f"{ip}:{port}",
                #     side="node", dir="send", cell_cmd="CREATE2"
                # )
            except Exception as e:
                # self._ev("circuit_extend_downstream_fail",
                #          circ_id=circuit_id, target=f"{ip}:{port}", error=str(e),
                #          ms=(time.perf_counter() - t_ext) * 1000.0)
                raise

        if sock.channel_handshake_state.handshake_complete:
            await _send_extend()
        else:
            sock.enqueue_circuit_op(_send_extend)
            self._ev("circuit_extend_queued", circ_id=circuit_id, target=f"{ip}:{port}")


    def _sendme_direction_for_out_sock(self, circuit, out_sock: Tor_Socket) -> str:
        upstream = circuit.circuit_nodes[0].sock
        return "up" if out_sock == upstream else "down"

    async def reply_extend(self, cell: CellCreated2, sock):
        circuit_id = cell.circuit_id
        handshake_data = cell.handshake_data
        extend_cell = CellRelayExtended2(handshake_data, circuit_id)
        circuit = sock.channel.recv_map.get(circuit_id)
        cell = circuit.make_relay(inner_cell=extend_cell, relay_type=CellRelay)
        sock = circuit.circuit_nodes[0].sock
        # Upstream must see the circuit ID it negotiated on that link.
        if circuit.prev_circid is not None:
            cell.circuit_id = circuit.prev_circid
        circuit.enqueue_relay(cell, out_sock=sock, is_data=False)
        # self._ev(
        #     "cell_trace", circ_id=circuit_id, peer=str(sock.socket.getpeername()),
        #     side="node", dir="send", cell_cmd="EXTENDED2"
        # )

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

        if sending_to_upstream and circuit.prev_circid is not None:
            cell.circuit_id = circuit.prev_circid
        elif (not sending_to_upstream) and circuit.next_circid is not None:
            cell.circuit_id = circuit.next_circid


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

        stream = None
        if cell.stream_id:
            stream = circuit.streams.get_by_id(cell.stream_id)

        inner = getattr(cell, "_inner", None)
        # if isinstance(inner, CellRelaySendMe):
        #     self._ev(
        #         "cell_trace", circ_id=circuit.id, stream_id=cell.stream_id,
        #         peer=str(out_sock.socket.getpeername()), side="node", dir="send",
        #         cell_cmd="RELAY_SENDME"
        #     )
        # elif isinstance(inner, CellRelayData):
        #     self._ev(
        #         "cell_trace", circ_id=circuit.id, stream_id=cell.stream_id,
        #         peer=str(out_sock.socket.getpeername()), side="node", dir="send",
        #         cell_cmd="RELAY_DATA"
        #     )

        circuit.enqueue_relay(cell, out_sock=out_sock, stream=stream, is_data=is_data)

    async def handle_cell(self, cell, sock: Tor_Socket):
        # self.print(f"receive cell from {sock.socket.getpeername()}")
        # self.print("cell content:", cell)

        if isinstance(cell, CellVersions):
            if not sock.handshake_initiator:
                certs_cell = self.make_certs_cell()
                t_tor = time.perf_counter()
                try:
                    await sock.tor_handshake_server(cell, certs_cell, self.cert_file)
                    # self._ev("tor_handshake_done",peer=str(sock.socket.getpeername()), side="server",version=getattr(sock.protocol, "version", None),ms=(time.perf_counter() - t_tor) * 1000.0)
                except Exception as e:
                    # self._ev("tor_handshake_fail",peer=str(sock.socket.getpeername()), side="server",error=str(e),version=getattr(sock.protocol, "version", None),ms=(time.perf_counter() - t_tor) * 1000.0)
                    raise
            else:
                sock.handshake.retrieve_versions(cell)
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
            try:
                await self.create_circuit(cell, sock, cell.circuit_id)
            except Exception:
                destroy = CellDestroy(circuit_id=cell.circuit_id, reason=0)
                await sock.send_cell(destroy)
                return
        elif isinstance(cell, CellCreated2):
            await self.reply_extend(cell, sock)
        elif isinstance(cell, CellAuthenticate):  # or cmd == 131
            # self.print("receive a recv_authenticate")
            sock.handshake.recv_authenticate(cell)
        elif isinstance(cell, CellRelay):
            circuit = sock.channel.recv_map.get(cell.circuit_id) or self.circuit_list.get_by_id(cell.circuit_id)

            if sock == circuit.circuit_nodes[0].sock:
                # upstream -> this hop: peel one layer
                inner_or_relay = circuit.handle_relay(cell)

                # NOT RECOGNIZED: still encrypted, must be forwarded downstream
                if isinstance(inner_or_relay, RelayedTorCell) and inner_or_relay.is_encrypted:
                    downstream_sock = None
                    if len(circuit.circuit_nodes) > 1:
                        downstream_sock = circuit.circuit_nodes[-1].sock
                    if downstream_sock is None or downstream_sock == sock:
                        # self._ev(
                        #     "relay_forward_blocked",
                        #     circ_id=cell.circuit_id,
                        #     sock=str(sock.socket.getpeername()),
                        #     downstream_sock=str(getattr(downstream_sock, "socket", None).getpeername())
                        #     if downstream_sock is not None
                        #     else None,
                        # )
                        return
                    if circuit.next_circid is not None:
                        cell.circuit_id = circuit.next_circid
                    circuit.enqueue_relay(cell, out_sock=downstream_sock, is_data=False)
                    return

                # RECOGNIZED: handle inner cell locally
                await self.handle_cell_relay(inner_or_relay, circuit, cell, sock)
                return
            # downstream -> upstream: add one layer and forward upstream
            next_node = circuit.circuit_nodes[0]
            next_node.encrypt_forward(cell)
            if circuit.prev_circid is not None:
                cell.circuit_id = circuit.prev_circid
            circuit.enqueue_relay(cell, out_sock=next_node.sock, is_data=False)

        elif isinstance(cell, Cell_RelayEarly):
            circuit = sock.channel.recv_map.get(cell.circuit_id) or self.circuit_list.get_by_id(cell.circuit_id)
            inner_cell = circuit.handle_relay(cell)
            await self.handle_cell_relay(inner_cell, circuit, cell, sock)
        elif isinstance(cell, CellDestroy):
            circuit = sock.channel.recv_map.get(cell.circuit_id) or self.circuit_list.get_by_id(cell.circuit_id)
            if sock == circuit.circuit_nodes[0].sock:
                next_hop_sock = circuit.circuit_nodes[-1].sock
            else:
                next_hop_sock = circuit.circuit_nodes[0].sock
            # self._ev(
            #     "cell_trace", circ_id=cell.circuit_id, peer=str(next_hop_sock.socket.getpeername()),
            #     side="node", dir="send", cell_cmd="DESTROY"
            # )
            if next_hop_sock == circuit.circuit_nodes[0].sock and circuit.prev_circid is not None:
                cell.circuit_id = circuit.prev_circid
            elif circuit.next_circid is not None:
                cell.circuit_id = circuit.next_circid
            await next_hop_sock.send_cell(cell)
            circuit.close_all_streams()
            circuit.circuit_nodes.clear()
            self.circuit_list.remove(cell.circuit_id)


    async def handle_cell_relay(self, cell, circuit, origin_cell, sock):
        # self.print("inner_cell:", cell)
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
            # self._ev("begin_rx", circ_id=cid, stream_id=sid, host=host, port=port)

            try:
                ip_address = await self.resolve_ipv4_async(host)
                addr = (ip_address, port)
                # 先建 stream，并写入 target_addr
                stream = circuit.streams.set_stream(stream_id=sid, target_addr=addr)
                # 异步连 TCP 并启动双向转发（成功后再回 CONNECTED）
                self._spawn_bg_task(self._exit_connect_and_start(circuit, sock, sid), name=f"exit_connect:{cid}:{sid}")


            except Exception as e:
                await self._send_end_once(circuit, sock, sid, StreamReason.INTERNAL)
                # self._ev("begin_fail", circ_id=cid, stream_id=sid, error=repr(e))

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
                # if st:
                #     self._ev("relay_agg", circ_id=circuit.id, stream_id=sid,
                #              direction=k[2], bytes=st["bytes"], cells=st["cells"], interval_ms=None)

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
            tcp_ready = stream is not None and (
                stream._remote_writer is not None or stream._remote_reader is not None
            )
            exit_tcp_not_ready = (
                stream is not None and
                stream.target_addr is not None and
                stream._remote_writer is None and
                stream._remote_reader is None
            )
            is_exit_consumer = tcp_ready

            if not is_exit_consumer:
                # Relay behavior: forward original encrypted relay cell.
                if exit_tcp_not_ready:
                    self._ev(
                        "relay_data_drop_tcp_not_ready",
                        circ_id=cid,
                        stream_id=sid,
                        dst=str(stream.target_addr),
                    )
                    await stream._to_remote.put(cell.data)
                    return

                if stream is None:
                    # self._ev(
                    #     "relay_data_forward_no_stream",
                    #     circ_id=cid,
                    #     stream_id=sid,
                    #     direction=direction,
                    # )
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

                # self._ev(
                #     "relay_data_drop_stream_not_ready",
                #     circ_id=cid,
                #     stream_id=sid,
                #     dst=str(stream.target_addr),
                # )
                await self._send_end_once(circuit, sock, sid, StreamReason.INTERNAL)
                return

            # ==========================
            # Exit consumer behavior
            # ==========================

            # --- circuit-level recv window ---
            cw = self._cw_recv(circuit, sock)
            cw.on_recv_data_cell(1)

            if cw.should_send_sendme():
                # circuit-level SENDME: stream_id = 0, send back toward the sender on this link
                sendme_digest = getattr(origin_cell, "_sendme_digest_backward", None)
                emit_version = circuit.sendme_emit_min_version
                if emit_version >= 1 and sendme_digest:
                    sendme_inner = CellRelaySendMe(
                        circuit_id=cid,
                        version=1,
                        digest=sendme_digest,
                    )
                else:
                    sendme_inner = CellRelaySendMe(circuit_id=cid)
                circ_sendme = circuit.make_relay(inner_cell=sendme_inner, relay_type=CellRelay, stream_id=0)
                circuit.enqueue_relay(circ_sendme, out_sock=sock, is_data=False)

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
                circuit.enqueue_relay(sendme_cell, out_sock=sock, stream=stream, is_data=False)

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
                direction = self._sendme_direction_for_out_sock(circuit, sock)
                version = getattr(cell, "version", 0)
                accept_min = circuit.sendme_accept_min_version
                if version < 0:
                    await self._close_circuit_protocol(circuit, sock)
                    return
                if version < accept_min:
                    await self._close_circuit_protocol(circuit, sock)
                    return
                if version == 1:
                    digest = getattr(cell, "digest", b"")
                    expected = circuit.pop_sendme_expected(direction)
                    if expected is None or expected != digest:
                        await self._close_circuit_protocol(circuit, sock)
                        return
                elif version == 0:
                    circuit.pop_sendme_expected(direction)
                else:
                    await self._close_circuit_protocol(circuit, sock)
                    return
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

    async def _send_destroy_to_sock(self, circuit, out_sock: Tor_Socket, reason: int = 0):
        cell = CellDestroy(circuit_id=circuit.id, reason=reason)
        upstream_sock = circuit.circuit_nodes[0].sock
        if out_sock == upstream_sock and circuit.prev_circid is not None:
            cell.circuit_id = circuit.prev_circid
        elif out_sock != upstream_sock and circuit.next_circid is not None:
            cell.circuit_id = circuit.next_circid
        # self._ev(
        #     "cell_trace", circ_id=cell.circuit_id, peer=str(out_sock.socket.getpeername()),
        #     side="node", dir="send", cell_cmd="DESTROY"
        # )
        await out_sock.send_cell(cell)

    async def _close_circuit_protocol(self, circuit, in_sock: Tor_Socket, reason: int = 0):
        other_sock = None
        if circuit.circuit_nodes:
            upstream_sock = circuit.circuit_nodes[0].sock
            other_sock = circuit.circuit_nodes[-1].sock if in_sock == upstream_sock else upstream_sock
        await self._send_destroy_to_sock(circuit, in_sock, reason=reason)
        if other_sock is not None and other_sock != in_sock:
            await self._send_destroy_to_sock(circuit, other_sock, reason=reason)
        circuit.close_all_streams()
        circuit.circuit_nodes.clear()
        self.circuit_list.remove(circuit.id)

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
                cw_picker=self._cw_send,  # 你原来传的 cw_picker 用什么就填什么
                spawner=self._spawn_bg_task,
            )
            connected = CellRelayConnected(address=stream.target_addr[0], ttl=3600, circuit_id=circuit.id)
            relay_conn = circuit.make_relay(inner_cell=connected, relay_type=CellRelay, stream_id=sid)
            circuit.enqueue_relay(relay_conn, out_sock=sock, stream=stream, is_data=False)
            # self._ev("begin_connected_tx", circ_id=circuit.id, stream_id=sid, dst=str(stream.target_addr))
            #
            # self._ev("exit_tcp_connected", circ_id=circuit.id, stream_id=sid, dst=str(stream.target_addr))

        except asyncio.CancelledError:
            # stop_protocol 时会 cancel，正常退出
            with contextlib.suppress(Exception):
                await stream.aclose()
            raise

        except Exception as e:
            # self._ev("exit_tcp_connect_fail", circ_id=circuit.id, stream_id=sid, dst=str(stream.target_addr),
            #          error=repr(e))

            # 失败就发 END，唤醒 client 侧收尾
            with contextlib.suppress(Exception):
                await self._send_end_once(circuit, sock, sid, StreamReason.INTERNAL)

            with contextlib.suppress(Exception):
                await stream.aclose()

    async def _send_end_once(self, circuit, sock, stream_id: int, reason: StreamReason):
        stream = circuit.streams.get_by_id(stream_id)
        if stream is not None and not stream.mark_end_sent():
            return
        end = CellRelayEnd(reason, circuit.id)
        relay = circuit.make_relay(inner_cell=end, relay_type=CellRelay, stream_id=stream_id)
        circuit.enqueue_relay(relay, out_sock=sock, stream=stream, is_data=False)

    async def resolve_ipv4_async(self, domain: str) -> str:
        try:
            ip_obj = ipaddress.ip_address(domain)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                ip_str = str(ip_obj)
                # self._ev("dns_bypass_ip_literal", domain=domain, ip=ip_str, ms=0.0)
                return ip_str
        except ValueError:
            # Not an IP literal, fall back to real DNS
            pass
        t0 = time.perf_counter()
        try:
            ip = await self.dns_solver.resolve_ipv4(domain)
            # self._ev("dns_resolve_ok", domain=domain, ip=ip, ms=(time.perf_counter() - t0) * 1000.0)
            print(f"[DNS] {domain} -> {ip}")
            return ip
        except Exception as e:
            # self._ev("dns_resolve_fail", domain=domain,fail_reason=FailReason.UNREACHABLE.value, error=str(e), ms=(time.perf_counter() - t0) * 1000.0)
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

    def make_certs_cell_initiator(self, include_rsa: bool = True) -> CellCerts:
        """Build CERTS cell for initiator relay mode.

        This uses the relay's identity key to delegate to the signing key (type 4),
        and the signing key to delegate to the link authentication key (type 6).
        RSA-related certs (types 2 and 7) remain optional but enabled by default
        to mimic real relay behavior.
        """

        ed_id_pub32 = self.ed_puk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ed_sign_pub32 = self.ed_sign_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        link_auth_pub32 = self.link_auth_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        certs: list[tuple[int, bytes]] = []

        cert4 = build_ed25519_cert(
            cert_type=CT_ED_ID_SIGNING,
            issuer_sk=self.ed_pvk,
            subject_key_bytes=ed_sign_pub32,
            exp_hours=self.exp_hr,
            issuer_pub_for_ext=ed_id_pub32,
            keytype=1,
        )
        certs.append((CT_ED_ID_SIGNING, cert4))

        cert6 = build_ed25519_cert(
            cert_type=CT_ED_SIGNING_LINK_AUTH,
            issuer_sk=self.ed_sign_sk,
            subject_key_bytes=link_auth_pub32,
            exp_hours=self.exp_hr,
            issuer_pub_for_ext=ed_sign_pub32,
            keytype=3,
        )
        certs.append((CT_ED_SIGNING_LINK_AUTH, cert6))

        if include_rsa:
            cert2 = rsa_identity_x509_der(self.rsa_id_sk)
            cert7 = build_rsa_to_ed_crosscert(
                self.rsa_id_sk,
                ed_id_pub32,
                self.exp_hr,
            )
            certs.extend(
                (
                    (CT_RSA_ID_X509, cert2),
                    (CT_RSA_TO_ED_CROSS, cert7),
                )
            )

        self._ev("initiator_certs_built", cert_types=[c[0] for c in certs])
        return CellCerts(certs)

    async def _flush_relay_agg(self, interval_ms: int = 500):
        try:
            while True:
                await asyncio.sleep(interval_ms / 1000)
                current, self._relay_agg = self._relay_agg, {}
                # for (cid, sid), st in current.items():
                #     # 上下行分两条写，便于画双向曲线
                #     if st.get("up_cells", 0) or st.get("up_bytes", 0):
                #         self._ev("relay_agg", circ_id=cid, stream_id=sid, direction="up",
                #                  bytes=st.get("up_bytes", 0), cells=st.get("up_cells", 0),
                #                  sendme_sent=st.get("sendme_sent", 0), sendme_recv=st.get("sendme_recv", 0),
                #                  win_cur=st.get("last_win", None), sample_ms=interval_ms)
                #     if st.get("down_cells", 0) or st.get("down_bytes", 0):
                #         self._ev("relay_agg", circ_id=cid, stream_id=sid, direction="down",
                #                  bytes=st.get("down_bytes", 0), cells=st.get("down_cells", 0),
                #                  sendme_sent=st.get("sendme_sent", 0), sendme_recv=st.get("sendme_recv", 0),
                #                  win_cur=st.get("last_win", None), sample_ms=interval_ms)
        except asyncio.CancelledError:
            pass  # 正常退出




