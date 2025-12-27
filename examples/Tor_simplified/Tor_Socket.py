import asyncio
import ssl
import struct
import time
import contextlib
import hashlib
from pathlib import Path
from enum import Enum, auto
from typing import Optional, Callable, Awaitable, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

from examples.Tor_simplified.Tor_Cell import TorCell, CellCerts, CellAuthChallenge, TorCommands, \
    CellVersions, CellNetInfo, AUTH_METHOD_ED25519_SHA256, CellAuthenticate, CellVPadding, CellPadding

from examples.Tor_simplified.Tor_Router import logger
from examples.Tor_simplified.circid_alloc import Channel
from tools.Packet.packet_TCP import ByteBuffer
from tools.Packet.packet_TCP import dial_tls
from tools.Network_Management.bandwidth_limiter import BandwidthLimiter

# === 延迟注入：已存在的工具（若你已有此模块，直接用；没有也不影响运行，测试脚本会提供兜底方案） ===
from tools.Network_Management.geo_delay_injector import (
    MappingCache, GeoDelayModel, DelayInjectorWriter
)
from tools.Crypt.crypt_common import (
    rsa_identity_digest,
    debug_build_crosscert,
    CT_RSA_ID_X509,
    CT_RSA_TO_ED_CROSS,
    CT_ED_ID_SIGNING,
    CT_ED_SIGNING_TLS,
    CT_ED_SIGNING_LINK_AUTH,
    build_ed25519_cert,
    build_rsa_to_ed_crosscert,
    rsa_identity_x509_der,
    hours_since_epoch,
)

from tools.Network_Management.tls_registry import (
    get_client_ctx, get_global_sem, get_node_sem
)
_TLS_HANDSHAKE_SEM = asyncio.Semaphore(64)


class Tor_Socket():
    def __init__(
        self,
        source_ip: str,
        node_id: Optional[str],
        reader: asyncio.StreamReader = None,
        writer: asyncio.StreamWriter = None,
        on_cell=None,
        *,
        role: str = "client",
        rsa_identity_key=None,
        ed_identity_key=None,
        ed_signing_key=None,
        link_auth_key=None,
        tls_cert_der: bytes | None = None,
        limiter: Optional[BandwidthLimiter] = None,
        enable_delay: bool = False,                     # ★ 一键总开关（默认关）
        sim_ip: Optional[str] = None,                   # ★ 本端仿真IP
        delay_mapping: Optional[MappingCache] = None,   # ★ 指纹/IP -> sim_ip 的映射缓存
        delay_model: Optional[GeoDelayModel] = None     # ★ 地理延迟模型
    ):
        self.protocol = TorProtocol()
        self._send_lock = asyncio.Lock()
        self.handshake = TorHandshake(self)
        self.print = print
        self.buffer = ByteBuffer()
        self.on_cell: Optional[Callable[[TorCell, "Tor_Socket"], Awaitable[None]]] = on_cell
        self.handshake_initiator = False
        self.source_ip = source_ip
        self.node_id = node_id
        self.handshake_done = asyncio.Event()
        self.listen_started = asyncio.Event()
        self._closing = asyncio.Event()
        self.closed = False
        self._limiter = limiter

        # Default peer/local metadata so dependent components can initialize safely
        self.peer = None
        self.peer_str = "unknown"
        self.local = None
        self.local_str = "unknown"

        # —— 延迟注入配置 ——  # ★
        self.enable_delay = bool(enable_delay)
        self.sim_ip = sim_ip
        self.delay_mapping = delay_mapping
        self.delay_model = delay_model
        self._inj = None

        # 异步I/O组件
        self.reader: Optional[asyncio.StreamReader] = reader
        self.writer: Optional[asyncio.StreamWriter] = writer

        self._q_ctrl = asyncio.Queue()  # 控制面队列（自动优先）
        self._q_data = asyncio.Queue(maxsize=4096)  # 数据面队列
        self._q_data_backpressure = 3072  # 触发背压阈值
        self._wakeup = asyncio.Event()  # 有新数据时唤醒 writer
        self._writer_task = None
        self._last_queue_log = 0.0

        self.role = role
        if self.role not in {"client", "relay"}:
            raise ValueError("role must be either 'client' or 'relay'")
        self.rsa_identity_key = rsa_identity_key
        self.ed_identity_key = ed_identity_key
        self.ed_signing_key = ed_signing_key
        self.link_auth_key = link_auth_key
        self.tls_cert_der = tls_cert_der

        if self.role == "relay":
            missing = [
                name for name, val in (
                    ("rsa_identity_key", self.rsa_identity_key),
                    ("ed_identity_key", self.ed_identity_key),
                    ("ed_signing_key", self.ed_signing_key),
                    ("link_auth_key", self.link_auth_key),
                )
                if val is None
            ]
            if missing:
                raise ValueError(f"relay role requires keys: {', '.join(missing)}")

        self.channel = Channel(
            channel_id=self.peer_str,
            link_protocol_version=self.protocol.version,
            circid_len_bytes=4 if self.protocol.version >= 4 else 2,
            initiator_is_me=self.handshake_initiator,
        )


        if self.reader is not None:
            # 被动连接，已经有SSL socket
            try:
                self.transport = writer.transport
                self.socket = self.transport.get_extra_info("socket")

                self.peer = self.transport.get_extra_info("peername")
                self.peer_str = f"{self.peer[0]}:{self.peer[1]}"
                self.local = self.socket.getsockname()
                self.local_str = f"{self.local[0]}:{self.local[1]}"
                self.channel.channel_id = self.peer_str
            except:
                self.peer = None
                self.peer_str = "unknown"

            # ★ 已有 reader/writer 的场景（被动接受），异步创建注入器
            asyncio.create_task(self._ensure_injector())
        else:
            self.peer = None
            self.peer_str = "not_connected"

    def update_link_protocol_version(self, version: int):
        """Synchronize negotiated link protocol version across components."""
        self.protocol.version = version
        self.channel.update_version(version)

    async def _ensure_injector(self):   # ★ 新增/重写
        """
        在 writer/peer 就绪后，如果打开开关且依赖齐全，则创建连接级注入器。
        """
        if self._inj is not None:
            return
        if not self.enable_delay:
            return
        if self.writer is None or self.peer is None:
            return
        if not (self.sim_ip and self.delay_mapping and self.delay_model):
            # 依赖不齐，跳过注入（保持直写）
            return
        try:
            # 这里没有对端指纹，可用地址回退（mapping 会优先用 addr 命中，否则 default）
            self._inj = await DelayInjectorWriter.create(
                self.writer,
                local_sim_ip=self.sim_ip,
                peer_fingerprint=None,
                peer_addr=self.peer,
                mapping=self.delay_mapping,
                model=self.delay_model
            )
        except Exception as e:
            self.print(f"[DelayInjector:init-fail] {self.peer} {e}")
            self._inj = None

    async def setup_socket(self, remote_addr: tuple[str, int]):
        """通过 tools.dial_tls 拿到 (reader, writer)，保持分层。"""
        reader, writer = await dial_tls(
            remote_addr,
            source_ip=self.source_ip,
            node_id=self.node_id,
            timeout=15.0
        )
        # 搬运
        self.reader, self.writer = reader, writer
        self.transport = writer.transport
        self.socket = self.transport.get_extra_info("socket")
        self.peer = self.transport.get_extra_info("peername")
        self.peer_str = f"{self.peer[0]}:{self.peer[1]}"
        self.local = self.writer.get_extra_info("sockname")
        self.local_str = f"{self.local[0]}:{self.local[1]}"
        self.handshake_initiator = True

        self.channel.channel_id = self.peer_str
        self.channel.initiator_is_me = True

        # ★ 出站场景：TLS建好后创建注入器
        await self._ensure_injector()

    @classmethod
    async def dial(cls, remote_addr: tuple[str, int],
                   source_ip: str,
                   on_cell,
                   sem: asyncio.Semaphore | None = None,
                   ssl_ctx: ssl.SSLContext | None = None,
                   node_id: Optional[str] = None,
                   *,
                   role: str = "client",
                   rsa_identity_key=None,
                   ed_identity_key=None,
                   ed_signing_key=None,
                   link_auth_key=None,
                   tls_cert_der: bytes | None = None,
                   limiter: Optional[BandwidthLimiter] = None,
                   enable_delay: bool = False,
                   sim_ip: Optional[str] = None,
                   delay_mapping: Optional[MappingCache] = None,
                   delay_model: Optional[GeoDelayModel] = None
                   ):
        # 1) 先做 TLS 拨号（保持你 tools.dial_tls 的封装）
        reader, writer = await dial_tls(
            remote_addr,
            source_ip=source_ip,
            node_id=node_id,
            timeout=15.0
        )

        # 2) 用现成的 reader/writer 构造 Tor_Socket
        self = cls(
            source_ip=source_ip,
            reader=reader,
            writer=writer,
            on_cell=on_cell,
            node_id=node_id,
            role=role,
            rsa_identity_key=rsa_identity_key,
            ed_identity_key=ed_identity_key,
            ed_signing_key=ed_signing_key,
            link_auth_key=link_auth_key,
            tls_cert_der=tls_cert_der,
            enable_delay=enable_delay,
            sim_ip=sim_ip,
            delay_mapping=delay_mapping,
            delay_model=delay_model,
            limiter=limiter,
        )
        self.handshake_initiator = True

        # 3) 和 setup_socket() 一致，把底层 transport / socket / peer / local 补齐
        try:
            self.transport = writer.transport
            self.socket = self.transport.get_extra_info("socket")
            self.peer = self.transport.get_extra_info("peername")
            self.peer_str = f"{self.peer[0]}:{self.peer[1]}"
            self.local = self.writer.get_extra_info("sockname")
            self.local_str = f"{self.local[0]}:{self.local[1]}"
            self.channel.channel_id = self.peer_str
            self.channel.initiator_is_me = True
        except Exception:
            # 出错也别影响后续逻辑
            pass

        # 4) 若启用注入且依赖齐全，则创建连接级注入器
        await self._ensure_injector()

        return self



    async def send(self, buf: bytes):
        """异步发送数据（入队 + 唤醒 writer loop）"""
        if self._closing.is_set():
            raise ConnectionError("AsyncTor_Socket already closed")

        async with self._send_lock:
            if self._closing.is_set():
                raise ConnectionError("AsyncTor_Socket already closed")

            try:
                if self.writer is None:
                    raise ConnectionError("Writer not initialized")

                blocked = await self._enqueue_data(buf)
                self._wakeup.set()
                return blocked

            except Exception as e:
                self.print(f"[SendErr] {self.peer_str} {e}")
                await self._abort()
                raise

    async def _abort(self):
        """正确关闭连接"""
        if self._closing.is_set():
            return

        self._closing.set()
        self.closed = True
        self._wakeup.set()

        if self._writer_task and self._writer_task is not asyncio.current_task():
            self._writer_task.cancel()
            with contextlib.suppress(Exception):
                await self._writer_task
            self._writer_task = None

        # ★ 关闭注入器（若支持）
        try:
            if self._inj is not None:
                await self._inj.aclose()
        except Exception:
            pass
        self._inj = None

        # 正确关闭writer
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()  # 会自动flush pending data

        self.reader = None
        self.writer = None

    # ★ 新增：运行时动态开/关
    async def set_delay_enabled(self, enabled: bool):
        if enabled and not self.enable_delay:
            self.enable_delay = True
            await self._ensure_injector()
        elif not enabled and self.enable_delay:
            self.enable_delay = False
            if self._inj is not None:
                with contextlib.suppress(Exception):
                    await self._inj.aclose()
                self._inj = None

    async def start_listen(self) -> asyncio.Task:
        if self.reader is None or self.writer is None:
            self._closing.set()
            self.listen_started.set()
            raise RuntimeError("Streams not set ...")

        loop = asyncio.get_running_loop()
        self._recv_task = loop.create_task(self._async_recv_loop())
        self._process_task = loop.create_task(self._process_loop())

        self._writer_task = loop.create_task(self._writer_loop())

        async def _join_and_cleanup():
            try:
                await asyncio.wait(
                    [self._recv_task, self._process_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
            finally:
                await self._abort()
                for t in (self._recv_task, self._process_task):
                    with contextlib.suppress(Exception):
                        t.cancel()
                if self._writer_task:
                    with contextlib.suppress(Exception):
                        self._writer_task.cancel()
                self.print(f"[CLOSE-{'CLI' if self.handshake_initiator else 'SRV'}]"
                           f" {self.source_ip} <---> {self.peer_str}")

        self.listen_started.set()
        return loop.create_task(_join_and_cleanup())

    async def _async_recv_loop(self):
        """完全异步的接收循环，使用更大的缓冲区"""
        try:
            while not self._closing.is_set():
                try:
                    data = await asyncio.wait_for(
                        self.reader.read(16384),  # 16KB buffer
                        timeout=600.0
                    )
                    if not data:  # EOF
                        print(f"[PeerClose] {self.peer_str} connection closed by peer")
                        break
                    await self.buffer.add(data)
                except asyncio.TimeoutError:
                    print(f"[Timeout] {self.peer_str} >600s no data")
                    break
                except Exception as e:
                    print(f"[RecvErr] {self.peer_str} {e}")
                    break
        except Exception as e:
            print(f"[RecvLoop] {self.peer_str} fatal error: {e}")
        finally:
            await self._abort()

    async def _process_loop(self):
        """处理接收到的数据"""
        while not self._closing.is_set():
            try:
                cell = await self.recv_and_parse_cell()
                if cell is None:
                    continue
                try:
                    if not self.handshake_done.is_set():
                        self.handshake.guard_incoming_cell(cell)
                except Exception as e:
                    self.print(f"[HS-ERROR] {self.peer_str} {e}")
                    await self._abort()
                    break
                await self.on_cell(cell, self)
            except Exception as e:
                import traceback
                stack = traceback.format_exc()
                self.print("[STACKTRACE]", stack)
                self.print(f"[ParseErr] {e}")

    async def tor_handshake_client(self, authenticate: bool = False, certs_cell: CellCerts | None = None):
        version_cell = self.handshake.make_versions()

        await self.send_cell(version_cell)

        await asyncio.wait_for(self.handshake.version_event.wait(), 60.0)
        await self.handshake.wait_for_responder_handshake()

        if authenticate:
            if certs_cell is None:
                logger.error("authenticate=True but no CERTS cell provided")
                raise ValueError("CERTS cell required when authenticate=True")
            await self.handshake.wait_for_auth_challenge()
            await self.send_cell(certs_cell)
            auth_cell = self._make_authenticate_cell()
            await self.send_cell(auth_cell)
            logger.debug("initiator_auth_sent")
        net_info_cell = await self.handshake.make_net_info(self.peer, self.local)
        await self.send_cell(net_info_cell)
        self.handshake.mark_done()

    async def tor_handshake_server(self, peer_version_cell: CellVersions, certs_cell, certs_path):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        self.handshake.retrieve_versions(peer_version_cell)
        await self.send_cell(certs_cell)
        auth_cell = CellAuthChallenge()
        await self.send_cell(auth_cell)
        self.handshake._auth_challenge = auth_cell.challenge
        self.handshake._auth_chal_event.set()  # optional but useful
        self.handshake._set_state(HandshakeState.SENT_AUTH_CHAL)

        net_info_cell = await self.handshake.make_net_info(self.peer, self.socket.getsockname())
        await self.send_cell(net_info_cell)


    def _make_authenticate_cell(self) -> CellAuthenticate:
        if self.handshake.auth_challenge is None:
            raise RuntimeError("No auth challenge received; cannot authenticate")
        signature = self.link_auth_key.sign(self.handshake.auth_challenge)
        return CellAuthenticate(auth_type=AUTH_METHOD_ED25519_SHA256, auth_data=signature)



    async def send_cells(self, cells):
        for cell in cells:
            await self.send_cell(cell)

    async def send_cell(self, cell):
        print("send cell: ", cell)
        if self._closing.is_set():
            self.print(f"[SendDrop] closed: {self.peer_str} {cell}")
            return False
        buf = self.protocol.serialize(cell)
        if self._is_control_cell(cell):
            await self._q_ctrl.put((buf, asyncio.get_running_loop().time()))
            self._wakeup.set()
            return False
        else:
            blocked = await self._enqueue_data(buf)
            self._wakeup.set()
            return blocked

    def _is_control_cell(self, cell) -> bool:
        from examples.Tor_simplified.Tor_Cell import (
            CellVersions, CellCerts, CellAuthChallenge, CellNetInfo,
            Cell_Create2, CellCreated2,
            CellRelayExtend2, CellRelayExtended2,
            CellRelayBegin, CellRelayConnected, CellRelayEnd,
            CellRelaySendMe, CellDestroy,
            Cell_RelayEarly, CellRelay
        )
        if isinstance(cell, (CellVersions, CellCerts, CellAuthChallenge, CellNetInfo, CellDestroy)):
            return True
        if isinstance(cell, (Cell_Create2, CellCreated2, CellRelayExtend2, CellRelayExtended2, Cell_RelayEarly)):
            return True
        if isinstance(cell, (CellRelayBegin, CellRelayConnected, CellRelayEnd, CellRelaySendMe)):
            return True
        try:
            return getattr(cell, "is_data", False) is False
        except Exception:
            return False

    async def _writer_loop(self):
        loop = asyncio.get_running_loop()
        try:
            while not self._closing.is_set():
                if self._q_ctrl.empty() and self._q_data.empty():
                    self._wakeup.clear()
                    try:
                        await asyncio.wait_for(self._wakeup.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        continue

                out = bytearray()
                t0 = loop.time()
                ctrl_count = 0
                while not self._q_ctrl.empty():
                    buf, enqueued_at = await self._q_ctrl.get()
                    out.extend(buf)
                    self._maybe_log_queue("ctrl", enqueued_at, self._q_ctrl.qsize())
                    ctrl_count += 1
                    if (loop.time() - t0) > 0.0002 or ctrl_count >= 8:
                        break
                if out:
                    await self._write_once(bytes(out))   # ★ 注入生效点
                    continue

                out.clear()
                t0 = loop.time()
                total = 0
                cells = 0
                while not self._q_data.empty():
                    buf, enqueued_at = await self._q_data.get()
                    out.extend(buf)
                    total += len(buf)
                    self._maybe_log_queue("data", enqueued_at, self._q_data.qsize())
                    cells += 1
                    if (loop.time() - t0) > 0.002 or total >= 64 * 1024 or cells >= 128:
                        break
                if out:
                    if self._limiter is not None:
                        await self._limiter.consume(len(out))
                    await self._write_once(bytes(out))   # ★ 注入生效点
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print(f"[WriterLoopErr] {self.peer_str} {e}")
        finally:
            await self._abort()

    async def _write_once(self, blob: bytes):
        # if (len(blob) % 514) != 0:
        #     self.print(f"[WRITE-MISALIGN] len={len(blob)} not multiple of 514 head32={blob[:32].hex()}")
        #     raise ValueError("write blob misaligned")

        if self._closing.is_set() or self.writer is None:
            return
        try:
            # ★ 若注入器存在则走注入器，否则直写
            if self._inj is not None:
                await self._inj.send(blob)       # ★
            else:
                self.writer.write(blob)
                await self.writer.drain()
        except Exception as e:
            self.print(f"[WriteErr] {self.peer_str} {e}")
            await self._abort()

    async def _enqueue_data(self, buf: bytes) -> bool:
        if self._closing.is_set():
            return False
        loop = asyncio.get_running_loop()
        enqueued_at = loop.time()
        blocked = False
        if self._q_data.qsize() >= self._q_data_backpressure:
            blocked = True
            self.print(
                f"[Backpressure] {self.peer_str} data_q={self._q_data.qsize()} "
                f"limit={self._q_data_backpressure}"
            )
            await self._q_data.put((buf, enqueued_at))
        else:
            try:
                self._q_data.put_nowait((buf, enqueued_at))
            except asyncio.QueueFull:
                blocked = True
                await self._q_data.put((buf, enqueued_at))
        return blocked

    def _maybe_log_queue(self, kind: str, enqueued_at: float, qsize: int):
        now = asyncio.get_running_loop().time()
        delay = now - enqueued_at
        if delay < 0.05 and qsize < self._q_data_backpressure:
            return
        if (now - self._last_queue_log) < 1.0:
            return
        self._last_queue_log = now
        self.print(f"[QueueStat] {self.peer_str} kind={kind} qsize={qsize} wait={delay:.4f}s")

    async def _wait_for_bytes(self, size: int, consume: bool) -> bytes | None:
        if consume:
            return await self.buffer.pop(size)
        else:
            await self.buffer.wait_for(size)
            return await self.buffer.peek(size)

    async def recv_and_parse_cell(self):
        """Receive one cell from the buffered stream and deserialize it.

        During link protocol negotiation we may not yet know whether the peer
        is using 2-byte or 4-byte circuit IDs. If parsing with the currently
        configured header format fails (for example because the peer already
        speaks v4 and is sending 4-byte circuit IDs), fall back to trying the
        4-byte header layout before giving up. This keeps the buffer aligned
        and prevents unknown command errors that break circuit extension.
        """

        primary_header_len = struct.calcsize(self.protocol.header_format)
        header = await self._wait_for_bytes(primary_header_len, consume=False)

        if header is None:
            return None

        parse_attempts = [
            (self.protocol.header_format, primary_header_len, self.protocol.version, header)
        ]

        # If handshake is not done and we are still on a pre-v4 header, also try
        # to parse using the v4 (4-byte circID) format so we don't misalign the
        # stream when the peer speaks a newer version.
        if not self.handshake_done.is_set() and self.protocol.version < 4:
            alt_format = '!IB'
            alt_len = struct.calcsize(alt_format)
            if alt_len > len(header):
                header = await self._wait_for_bytes(alt_len, consume=False)
                if header is None:
                    return None
            parse_attempts.append((alt_format, alt_len, 4, header))

        cell_cls = None
        circ_id = None
        cmd_num = None
        header_len = primary_header_len
        last_error = None
        last_header_len = primary_header_len

        for fmt, hlen, implied_version, hdr in parse_attempts:
            try:
                circ_id, cmd_num = struct.unpack(fmt, hdr[:hlen])
                cell_cls = TorCommands.get_by_num(cmd_num)
                if cell_cls is None:
                    raise ValueError(f"Unknown command {cmd_num}")
                header_len = hlen
                last_header_len = hlen
                if implied_version > self.protocol.version:
                    self.update_link_protocol_version(implied_version)
                break
            except Exception as e:  # struct.error or unknown command
                last_error = e
                last_header_len = hlen
            continue

        if cell_cls is None:
            if cmd_num is None:
                self.print(f"Header unpack error: {last_error}")
                await self.buffer.pop(last_header_len)
                return None

            is_var_len = cmd_num ==7 or cmd_num >= 128

            if is_var_len:
                hdr_plus = await self._wait_for_bytes(header_len + 2, consume=False)
                if hdr_plus is None:
                    return None
                (payload_len,) = struct.unpack(self.protocol.length_format, hdr_plus[-2:])
                total_len = header_len + 2 + payload_len
            else:
                total_len = header_len + TorCell.MAX_PAYLOAD_SIZE
            skipped = await self._wait_for_bytes(total_len, consume=True)
            self.print(f"[UnknownCell] cmd={cmd_num} skipped={len(skipped) if skipped else 0}")
            return None


        if cell_cls.is_var_len():
            hdr_plus = await self._wait_for_bytes(header_len + 2, consume=False)
            if hdr_plus is None:
                return None
            (payload_len,) = struct.unpack(self.protocol.length_format, hdr_plus[-2:])
            total_len = header_len + 2 + payload_len
        else:
            total_len = header_len + TorCell.MAX_PAYLOAD_SIZE

        raw = await self._wait_for_bytes(total_len, consume=True)
        if raw is None:
            return None

        hdr_hex = raw[:header_len].hex() if raw else ""
        self.print(f"[HDR] ver={self.protocol.version} hlen={header_len} circ={circ_id} cmd={cmd_num} hdr={hdr_hex}")


        if not cell_cls.is_var_len():
            expected_len = header_len + TorCell.MAX_PAYLOAD_SIZE
            if self.protocol.version >= 4 and expected_len == 514 and len(raw) != expected_len:
                raise ValueError(f"[RECV-LEN] cmd={cmd_num} raw_len={len(raw)} expected={expected_len}")
            print(f"[RecvCell] cmd={cmd_num} raw_len={len(raw)}")
        else:
            print(f"[RecvCell] cmd={cmd_num} raw_len={len(raw)}")

        payload_offset = header_len + (2 if cell_cls.is_var_len() else 0)
        payload = raw[payload_offset:]


        try:
            return self.protocol.deserialize(cell_cls, payload, circ_id)
        except Exception as e:
            self.print(f"Cell parse error: {e}")
            return None


class TorProtocol:
    DEFAULT_VERSION = 3
    SUPPORTED_VERSION = [3, 4]
    def __init__(self, version=DEFAULT_VERSION):
        self._version = version
    @property
    def version(self):
        return self._version
    @version.setter
    def version(self, version):
        self._version = version
    @property
    def header_format(self):
        if self.version < 4:
            return '!HB'
        else:
            return '!IB'
    @property
    def length_format(self):
        return '!H'
    def deserialize(self, command, payload, circuit_id=0):
        return TorCell.deserialize(command, circuit_id, payload, self.version)
    def serialize(self, cell):
        raw = cell.serialize(self.version)
        header_size = 5 if (self.version >= 4) else 3
        if not cell.is_var_len() and self.version >= 4:
            if len(raw) != 514:
                head_hex = raw[:32].hex()
                raise ValueError(f"[SEND-CHECK] cmd={cell.NUM} payload_len={len(raw) - header_size} raw_len={len(raw)} head32={head_hex}")
        return raw



class HandshakeState(Enum):
    INIT = auto()

    # version negotiation
    GOT_VERSIONS = auto()

    # certificates exchange (either recv or send depending on role)
    GOT_CERTS = auto()

    # auth challenge
    SENT_AUTH_CHAL = auto()   # responder: generated and sent AUTH_CHALLENGE
    GOT_AUTH_CHAL = auto()    # initiator: received AUTH_CHALLENGE

    # netinfo
    SENT_NETINFO = auto()
    GOT_NETINFO = auto()

    DONE = auto()

class TorHandshake:
    def __init__(self, tor_socket, tor_protocol=TorProtocol):
        self.tor_socket = tor_socket
        self.tor_protocol = tor_protocol
        self.version_event = self._make_new_event()
        self.peer_identity_digest: bytes | None = None
        self.peer_ed_identity_pub: bytes | None = None
        self.peer_tls_cert_der: bytes | None = None
        self.peer_cert_list: list[tuple[int, bytes]] = []
        self._negotiated_version: int | None = None
        self.state = HandshakeState.INIT
        self._responder_info_ready = asyncio.Event()
        self._auth_challenge: bytes | None = None
        self._auth_chal_event = asyncio.Event()

    @staticmethod
    def _make_new_event():
        return asyncio.Event()

    def make_versions(self):
        version_cell = CellVersions(self.tor_protocol.SUPPORTED_VERSION)
        return version_cell

    def _set_state(self, new_state: HandshakeState):
        if new_state.value > self.state.value:
            self.state = new_state

    def guard_incoming_cell(self, cell):
        if self.state == HandshakeState.DONE:
            return

        allowed_types = (
            CellVersions,
            CellCerts,
            CellAuthChallenge,
            CellAuthenticate,
            CellNetInfo,
            CellVPadding,
            CellPadding,
        )
        if not isinstance(cell, allowed_types):
            raise RuntimeError(f"Received non-handshake cell {type(cell).__name__} before handshake completion")

        if isinstance(cell, CellVersions):
            self._set_state(HandshakeState.GOT_VERSIONS)

        elif isinstance(cell, CellAuthenticate):
            if self.state.value < HandshakeState.SENT_AUTH_CHAL.value:
                raise RuntimeError("Received AUTHENTICATE before AUTH_CHALLENGE during handshake")
            # optional: verify signature here
            # self._set_state(HandshakeState.GOT_AUTH_CHAL)  # add a state, or just keep GOT_AUTH_CHAL

        elif isinstance(cell, CellCerts):
            if self.state.value < HandshakeState.GOT_VERSIONS.value:
                raise RuntimeError("Received CERTS before VERSIONS during handshake")
            self._set_state(HandshakeState.GOT_CERTS)
        elif isinstance(cell, CellAuthChallenge):
            if self.state.value < HandshakeState.GOT_CERTS.value:
                raise RuntimeError("Received AUTH_CHALLENGE before CERTS during handshake")
            self._set_state(HandshakeState.GOT_AUTH_CHAL)
            self._auth_challenge = cell.challenge
            self._auth_chal_event.set()
        elif isinstance(cell, CellNetInfo):
            if self.state.value < HandshakeState.GOT_AUTH_CHAL.value and self.tor_socket.handshake_initiator:
                raise RuntimeError("Received NETINFO before AUTH_CHALLENGE during handshake")
            self._set_state(HandshakeState.GOT_NETINFO)
            if self.tor_socket.handshake_initiator:
                self._responder_info_ready.set()
            else:
                self.mark_done()

    async def wait_for_responder_handshake(self, wait_time: float = 60.0):
        await asyncio.wait_for(self._responder_info_ready.wait(), wait_time)

    async def wait_for_auth_challenge(self, wait_time: float = 60.0):
        await asyncio.wait_for(self._auth_chal_event.wait(), wait_time)

    @property
    def auth_challenge(self) -> bytes | None:
        return self._auth_challenge

    def mark_done(self):
        if self.state == HandshakeState.DONE:
            return
        self._set_state(HandshakeState.DONE)
        self.tor_socket.handshake_done.set()

    async def make_net_info(self, remote_addr, local_addr, wait_time=60):
        await asyncio.wait_for(self.version_event.wait(), wait_time)
        logger.debug('Sending NET_INFO cell...')
        other_or = remote_addr[0]
        this_or = local_addr[0]
        if getattr(self.tor_socket, "role", "client") == "client":
            ts = 0
        else:
            ts = int(time.time())
        net_info_cell = CellNetInfo(ts, other_or, this_or)
        return net_info_cell

    def retrieve_versions(self, cell):
        assert isinstance(cell, CellVersions)
        logger.debug('Remote protocol versions: %s', cell.versions)
        # Ignore any subsequent VERSIONS once negotiated.
        if self._negotiated_version is not None:
            logger.debug(
                'Ignoring duplicate VERSIONS cell; already negotiated version %s',
                self._negotiated_version,
            )
            return self._negotiated_version

        supported = set(self.tor_protocol.SUPPORTED_VERSION)
        common_versions = supported.intersection(cell.versions)
        if not common_versions:
            self.version_event.set()
            try:
                asyncio.get_running_loop().create_task(self.tor_socket._abort())
            except RuntimeError:
                # If no running loop, defer to caller to close the socket.
                pass
            raise RuntimeError("No shared link protocol version with peer")

        version = max(common_versions)
        self._negotiated_version = version
        self.tor_socket.update_link_protocol_version(version)
        self.version_event.set()
        return version

    def retrieve_certs(self, cell_certs: CellCerts):
        self.peer_cert_list = cell_certs.certs
        for cert_type, cert_bytes in self.peer_cert_list:
            if cert_type == CT_RSA_ID_X509:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                spki = cert.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(spki)
                self.peer_identity_digest = digest.finalize()
            elif cert_type == CT_RSA_TO_ED_CROSS:
                CROSSCERT_PREFIX = b"Tor TLS RSA/Ed25519 cross-certificate"
                prefix_len = len(CROSSCERT_PREFIX)
                ed_pub = cert_bytes[prefix_len : prefix_len + 32]
                self.peer_ed_identity_pub = ed_pub

    def retrieve_net_info(self, cell):
        logger.debug('Retrieving NET_INFO cell...')
        timestamp = getattr(cell, "timestamp", None)
        try:
            if isinstance(timestamp, (int, float)):
                skew = abs(time.time() - timestamp)
                if skew > 3600:
                    logger.warning("NETINFO time skew warning: %.2fs", skew)
        except Exception:
            logger.debug("Failed to evaluate NETINFO timestamp skew", exc_info=True)

    def recv_authenticate(self, cell):
        logger.debug('Retrieving authenticate cell...')


def load_cert_for_cellcerts(path: str):
    file_path = Path(path)
    cert_bytes = file_path.read_bytes()
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        raw = cert.public_bytes(encoding=serialization.Encoding.DER)
    except ValueError:
        raw = cert_bytes
    return raw

def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _default_client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=1")
    return ctx
