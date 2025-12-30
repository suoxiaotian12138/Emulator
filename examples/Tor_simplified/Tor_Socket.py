import asyncio
import ssl
import struct
import time
import contextlib
import hashlib
import hmac
import os
from pathlib import Path
from enum import Enum, auto
from typing import Optional, Callable, Awaitable, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

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

def _hkdf_expand(prk: bytes, info: bytes, length: int, hashmod=hashlib.sha256) -> bytes:
    hash_len = hashmod().digest_size
    if length > 255 * hash_len:
        raise ValueError("Cannot expand to more than 255 * HashLen bytes")
    okm = bytearray()
    prev = b""
    counter = 1
    while len(okm) < length:
        data = prev + info + bytes([counter])
        prev = hmac.new(prk, data, hashmod).digest()
        okm.extend(prev)
        counter += 1
    return bytes(okm[:length])


def _hkdf_expand_label_tls13(secret: bytes, label: bytes, context: bytes, length: int, hashmod=hashlib.sha256) -> bytes:
    full_label = b"tls13 " + label
    hkdf_label = struct.pack("!H", length)
    hkdf_label += struct.pack("!B", len(full_label)) + full_label
    hkdf_label += struct.pack("!B", len(context)) + context
    return _hkdf_expand(secret, hkdf_label, length, hashmod=hashmod)


def _read_exporter_secret_from_keylog(keylog_path: str) -> bytes:
    """
    Read the last EXPORTER_SECRET from the keylog file.

    Note: In your project each TLS connection uses a unique keylog file path,
    so taking the last EXPORTER_SECRET is sufficient and avoids needing
    client_random() (not available on some Python ssl.SSLObject builds).
    """
    path = Path(keylog_path)
    if not path.exists():
        raise RuntimeError(f"Keylog file not found at {keylog_path}")

    last_secret = None
    for delay in (0.0, 0.01, 0.02, 0.04, 0.08):
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("EXPORTER_SECRET "):
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        last_secret = parts[2]
        if last_secret is not None:
            break
        time.sleep(delay)

    if last_secret is None:
        raise RuntimeError(f"EXPORTER_SECRET not found in keylog {keylog_path}")

    try:
        return bytes.fromhex(last_secret)
    except ValueError as exc:
        raise RuntimeError(f"Invalid EXPORTER_SECRET hex in keylog {keylog_path}") from exc



def _sanitize_keylog_component(value: str) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(ch if ch in allowed else "_" for ch in value)

def tor_tls_export_key_material(writer_or_sslobj, label: bytes, context: bytes, length: int) -> bytes:
    """Return exporter output of ``length`` bytes using given label and context."""

    ssl_obj = None
    keylog_path = None
    if isinstance(writer_or_sslobj, ssl.SSLObject):
        ssl_obj = writer_or_sslobj
        keylog_path = getattr(ssl_obj, "_keylog_path", None)
    else:
        get_extra = getattr(writer_or_sslobj, "get_extra_info", None)
        if callable(get_extra):
            ssl_obj = get_extra("ssl_object")
            keylog_path = getattr(ssl_obj, "_keylog_path", None) if ssl_obj else None


    if keylog_path is None and hasattr(writer_or_sslobj, "_keylog_path"):
        keylog_path = getattr(writer_or_sslobj, "_keylog_path", None)

    if ssl_obj is None:
        raise RuntimeError("ssl_object is None; TLS not established")

    if ssl_obj.version() != "TLSv1.3":
        raise RuntimeError("TLS exporter is only supported for TLS 1.3 sessions")

    if keylog_path is None:
        raise RuntimeError("Keylog path not recorded for TLS connection")

    cipher_info = None
    with contextlib.suppress(Exception):
        cipher_info = ssl_obj.cipher()
    hashmod = hashlib.sha256
    if cipher_info and isinstance(cipher_info, (list, tuple)) and cipher_info:
        cipher_name = cipher_info[0]
        # Pick HKDF hash based on the TLS 1.3 cipher suite hash component.
        if isinstance(cipher_name, str):
            if cipher_name.endswith("SHA384"):
                hashmod = hashlib.sha384
            elif cipher_name.endswith("SHA256"):
                hashmod = hashlib.sha256

    # EXPORTER_SECRET from keylog corresponds to the TLS 1.3 exporter_master_secret.
    exporter_master_secret = _read_exporter_secret_from_keylog(keylog_path)

    hash_len = hashmod().digest_size

    # RFC8446 7.5:
    # TLS-Exporter(label, context_value, key_length) =
    #   HKDF-Expand-Label(Derive-Secret(Secret, label, ""),
    #                     "exporter", Hash(context_value), key_length)
    #
    # Derive-Secret(Secret, label, "") uses Hash("") as the context.
    empty_hash = hashmod(b"").digest()

    # Step 1: secret1 = Derive-Secret(exporter_master_secret, label, "")
    secret1 = _hkdf_expand_label_tls13(
        exporter_master_secret,
        label,               # e.g. b"EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"
        empty_hash,          # Hash("")
        hash_len,            # output length = HashLen
        hashmod=hashmod,
    )

    # Step 2: out = HKDF-Expand-Label(secret1, "exporter", Hash(context_value), length)
    context_hash = hashmod(context).digest()
    out = _hkdf_expand_label_tls13(
        secret1,
        b"exporter",
        context_hash,
        length,
        hashmod=hashmod,
    )

    if len(out) != length:
        raise RuntimeError("TLS-Exporter returned wrong length")
    return out



def tls_exporter_auth0003(writer_or_sslobj, cid32: bytes) -> bytes:
    """AUTH0003 helper that exports 32-byte TLSSECRETS for the given CID."""

    assert len(cid32) == 32
    label = b"EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"

    # Tor passes raw CID (32 bytes) as exporter context for AUTH0003.
    return tor_tls_export_key_material(writer_or_sslobj, label, cid32, 32)



from tools.Network_Management.tls_registry import (
    get_client_ctx, get_global_sem, get_node_sem
)
_TLS_HANDSHAKE_SEM = asyncio.Semaphore(64)

class LinkTranscriptSHA256:
    def __init__(self, debug: bool = False, max_dump_len: int = 256):
        self._recv_hasher = hashlib.sha256()
        self._sent_hasher = hashlib.sha256()
        self.debug = debug
        self._max_dump_len = max_dump_len

    def update_recv(self, raw: bytes):
        self._recv_hasher.update(raw)
        if self.debug:
            preview = raw[: self._max_dump_len]
            print(f"[Transcript:recv] {len(raw)}B {preview.hex()}")

    def update_sent(self, raw: bytes):
        self._sent_hasher.update(raw)
        if self.debug:
            preview = raw[: self._max_dump_len]
            print(f"[Transcript:sent] {len(raw)}B {preview.hex()}")

    def snapshot_recv_digest(self) -> bytes:
        return self._recv_hasher.copy().digest()

    def snapshot_sent_digest(self) -> bytes:
        return self._sent_hasher.copy().digest()

class ChannelHandshakeState:
    def __init__(self):
        self.received_certs = False
        self.received_auth_challenge = False
        self.sent_certs = False
        self.sent_authenticate = False
        self.handshake_complete = False
        self.peer_certs_verified = False

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
        delay_model: Optional[GeoDelayModel] = None,    # ★ 地理延迟模型
        debug_transcript: bool = False,
    ):
        self.protocol = TorProtocol()
        self._send_lock = asyncio.Lock()
        self.handshake = TorHandshake(self)
        self.channel_handshake_state = ChannelHandshakeState()
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
        self._handshake_started = False
        self._pending_circuit_ops: list[Callable[[], Awaitable[Any]]] = []
        self._certs_cell_for_auth: CellCerts | None = None
        self._keylog_path: str | None = None

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

        # ctrl queue item: (buf: bytes, enqueued_at: float, flags: int, fut: Optional[Future])
        self._q_ctrl = asyncio.Queue()
        self._CTRL_SOLO = 1 << 0
        self._CTRL_BARRIER = 1 << 1
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
        self.link_transcript = LinkTranscriptSHA256(debug=debug_transcript)

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

    async def flush_ctrl(self):
        """
        Ensure all previously enqueued control-plane buffers are written out.
        Implemented via a barrier item consumed by writer_loop.
        """
        if self._closing.is_set():
            return
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        await self._q_ctrl.put((b"", loop.time(), self._CTRL_BARRIER, fut))
        self._wakeup.set()
        await fut

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
        keylog_dir = Path("temp") / "keylogs"
        keylog_dir.mkdir(parents=True, exist_ok=True)
        host_component = _sanitize_keylog_component(remote_addr[0] or "unknown")
        keylog_path = keylog_dir / f"tls_{host_component}_{remote_addr[1]}_{int(time.monotonic_ns())}.log"
        self._keylog_path = str(keylog_path)
        reader, writer = await dial_tls(
            remote_addr,
            source_ip=self.source_ip,
            node_id=self.node_id,
            timeout=15.0,
            keylog_path=self._keylog_path,
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
                   delay_model: Optional[GeoDelayModel] = None,
                   debug_transcript: bool = False
                   ):
        # 1) 先做 TLS 拨号（保持你 tools.dial_tls 的封装）
        keylog_dir = Path("temp") / "keylogs"
        keylog_dir.mkdir(parents=True, exist_ok=True)
        host_component = _sanitize_keylog_component(remote_addr[0] or "unknown")
        keylog_path = keylog_dir / f"tls_{host_component}_{remote_addr[1]}_{int(time.monotonic_ns())}.log"
        reader, writer = await dial_tls(
            remote_addr,
            source_ip=source_ip,
            node_id=node_id,
            timeout=15.0,
            keylog_path=str(keylog_path),
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
            debug_transcript=debug_transcript,
        )
        self.handshake_initiator = True
        self._keylog_path = str(keylog_path)

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
                await self._handle_handshake_cell(cell)
                await self.on_cell(cell, self)
            except Exception as e:
                import traceback
                stack = traceback.format_exc()
                self.print("[STACKTRACE]", stack)
                self.print(f"[ParseErr] {e}")

    async def _handle_handshake_cell(self, cell: TorCell):
        hs = self.channel_handshake_state
        if isinstance(cell, CellCerts):
            if not hs.received_certs:
                hs.received_certs = True
                logger.info(f"[HS] recv CERTS from {self.peer_str}")

                # Parse and minimally verify required peer identity material for AUTH0003
                try:
                    self.handshake.retrieve_certs(cell)
                    ok = (
                            isinstance(self.handshake.peer_identity_digest, (bytes, bytearray))
                            and len(self.handshake.peer_identity_digest) == 32
                            and isinstance(self.handshake.peer_ed_identity_pub, (bytes, bytearray))
                            and len(self.handshake.peer_ed_identity_pub) == 32
                    )
                    hs.peer_certs_verified = bool(ok)
                    if not hs.peer_certs_verified:
                        logger.error(f"[HS] peer CERTS parsed but missing required identity fields: {self.peer_str}")
                except Exception as e:
                    hs.peer_certs_verified = False
                    logger.error(f"[HS] peer CERTS parse/verify failed: {self.peer_str} err={e}")
        elif isinstance(cell, CellAuthChallenge):
            if not hs.received_auth_challenge:
                hs.received_auth_challenge = True
                logger.info(f"[HS] recv AUTH_CHALLENGE from {self.peer_str}")
            # await self.maybe_send_auth_response()

    async def ensure_handshake_complete(self):
        if self.channel_handshake_state.handshake_complete:
            return True
        await self.handshake_done.wait()
        return self.channel_handshake_state.handshake_complete

    def enqueue_circuit_op(self, op: Callable[[], Awaitable[Any]]):
        if self.channel_handshake_state.handshake_complete:
            asyncio.create_task(op())
            return
        self._pending_circuit_ops.append(op)

    async def _flush_pending_circuit_ops(self):
        if not self._pending_circuit_ops:
            return
        pending = list(self._pending_circuit_ops)
        self._pending_circuit_ops.clear()
        for op in pending:
            asyncio.create_task(op())

    def _mark_handshake_complete(self):
        hs = self.channel_handshake_state
        if hs.handshake_complete:
            return
        hs.handshake_complete = True
        logger.info(f"[HS] handshake complete with {self.peer_str}")
        self.handshake_done.set()
        asyncio.create_task(self._flush_pending_circuit_ops())

    async def maybe_send_auth_response(self):
        hs = self.channel_handshake_state
        if hs.handshake_complete:
            logger.info(f"[HS] Ignoring AUTH response attempt after handshake complete {self.peer_str}")
            return
        if hs.sent_authenticate:
            return
        if not hs.received_auth_challenge:
            logger.info(f"[HS] Refusing to send AUTHENTICATE before AUTH_CHALLENGE from {self.peer_str}")
            return
        if not hs.received_certs:
            logger.info(f"[HS] Waiting for peer CERTS before AUTHENTICATE to {self.peer_str}")
            return
        if not hs.peer_certs_verified:
            logger.info(f"[HS] Waiting for verified peer CERTS before AUTHENTICATE to {self.peer_str}")
            return
        if self._certs_cell_for_auth is None:
            logger.error(f"[HS] Cannot send CERTS/AUTHENTICATE to {self.peer_str}: CERTS payload missing")
            return

        if not hs.sent_certs:
            logger.info(f"[HS] send CERTS to {self.peer_str}")
            await self.send_cell(self._certs_cell_for_auth)
            hs.sent_certs = True
            await self.flush_ctrl()

        if AUTH_METHOD_ED25519_SHA256 in self.handshake.auth_methods:
            slog = self.handshake._slog_at_auth_challenge or self.link_transcript.snapshot_recv_digest()
            clog = self.link_transcript.snapshot_sent_digest()

            # --- DEBUG: verify CID matches the RSA ID cert we are about to send in CERTS ---
            try:
                if self._certs_cell_for_auth is not None:
                    for cert_type, cert_bytes in self._certs_cell_for_auth.certs:
                        if cert_type == CT_RSA_ID_X509:
                            cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                            cid_from_cert = self.handshake.rsa_identity_digest_pkcs1(cert.public_key())
                            cid_from_key = self.handshake.rsa_identity_digest_pkcs1(self.rsa_identity_key)
                            break
            except Exception as e:
                self.print(f"[AUTH0003-CHK] CID compare failed: {e}")

            auth_cell = await self._make_authenticate_auth0003(slog=slog, clog=clog)

            auth_raw = self.protocol.serialize(auth_cell)

            payload = auth_raw

            logger.info(f"[HS] send AUTHENTICATE to {self.peer_str}")
            await self._send_raw_immediate(auth_raw, update_transcript=False)
            self.link_transcript.update_sent(auth_raw)
            hs.sent_authenticate = True
        else:
            logger.info(f"[HS] AUTH0003 not offered by {self.peer_str}; skipping AUTHENTICATE send")

    async def tor_handshake_client(self, authenticate: bool = False, certs_cell: CellCerts | None = None):
        if self.channel_handshake_state.handshake_complete:
            logger.info(f"[HS] Channel handshake already complete with {self.peer_str}; skipping client handshake")
            return
        if self._handshake_started:
            logger.info(f"[HS] Channel handshake already in progress with {self.peer_str}; ignoring duplicate request")
            return
        self._handshake_started = True


        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        await self.flush_ctrl()

        await asyncio.wait_for(self.handshake.version_event.wait(), 60.0)

        if authenticate:
            if certs_cell is None:
                logger.error("authenticate=True but no CERTS cell provided")
                raise ValueError("CERTS cell required when authenticate=True")
            self._certs_cell_for_auth = certs_cell
            await self.handshake.wait_for_auth_challenge()
            await self.maybe_send_auth_response()

        await self.handshake.wait_for_responder_handshake()

        net_info_cell = await self.handshake.make_net_info(self.peer, self.local)
        await self.send_cell(net_info_cell)
        self.handshake.mark_done()

    async def tor_handshake_server(self, peer_version_cell: CellVersions, certs_cell, certs_path):
        if self.channel_handshake_state.handshake_complete:
            logger.info(f"[HS] Channel handshake already complete with {self.peer_str}; skipping server handshake")
            return
        if self._handshake_started:
            logger.info(f"[HS] Channel handshake already in progress with {self.peer_str}; ignoring duplicate request")
            return
        self._handshake_started = True

        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        self.handshake.retrieve_versions(peer_version_cell)
        await self.send_cell(certs_cell)
        self.channel_handshake_state.sent_certs = True
        logger.info(f"[HS] send CERTS to {self.peer_str}")
        auth_cell = CellAuthChallenge()
        await self.send_cell(auth_cell)
        await self.flush_ctrl()
        self.handshake._auth_challenge = auth_cell.challenge
        self.handshake._auth_chal_event.set()  # optional but useful
        self.handshake._set_state(HandshakeState.SENT_AUTH_CHAL)

        net_info_cell = await self.handshake.make_net_info(self.peer, self.socket.getsockname())
        await self.send_cell(net_info_cell)


    async def _make_authenticate_auth0003(self, *, slog: bytes, clog: bytes) -> CellAuthenticate:
        if self.handshake.auth_challenge is None:
            raise RuntimeError("No auth challenge received; cannot authenticate")
        ssl_obj = None
        if self.writer is not None:
            ssl_obj = self.writer.get_extra_info("ssl_object")
        if ssl_obj is None:
            raise RuntimeError("ssl_object is None; TLS not established")

        if self.handshake.peer_identity_digest is None:
            raise RuntimeError("Peer identity digest missing for AUTH0003")
        if self.handshake.peer_ed_identity_pub is None:
            raise RuntimeError("Peer Ed25519 identity missing for AUTH0003")
        if self.rsa_identity_key is None or self.ed_identity_key is None:
            raise RuntimeError("Local identity keys missing for AUTH0003")

        cid = self.handshake.rsa_identity_digest_pkcs1(self.rsa_identity_key)
        sid = self.handshake.peer_identity_digest
        cid_ed = self.ed_identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        sid_ed = self.handshake.peer_ed_identity_pub

        peer_cert_der = ssl_obj.getpeercert(binary_form=True)
        if not peer_cert_der:
            raise RuntimeError("Peer TLS certificate unavailable for AUTH0003")
        self.peer_tls_cert_der = peer_cert_der
        scert = hashlib.sha256(peer_cert_der).digest()


        # TLS exporter for AUTH0003
        tlssecrets = tls_exporter_auth0003(ssl_obj, cid)

        body = self.handshake.build_auth0003_body(
            cid=cid,
            sid=sid,
            cid_ed=cid_ed,
            sid_ed=sid_ed,
            slog=slog,
            clog=clog,
            scert=scert,
            tlssecrets=tlssecrets,
        )
        return CellAuthenticate(auth_type=AUTH_METHOD_ED25519_SHA256, auth_data=body)



    async def send_cells(self, cells):
        for cell in cells:
            await self.send_cell(cell)

    async def send_cell(self, cell):
        # print("send cell: ", cell)

        # Validate AUTH0003 length if present (optional)
        # if isinstance(cell, CellAuthenticate) and cell.auth_type == 0x0003:
        #     auth_len = len(cell.auth_data)
        #     self.print(f"sent AUTHENTICATE authtype=0x{cell.auth_type:04x} authlen={auth_len}")
        #     assert auth_len == 352

        if self._closing.is_set():
            self.print(f"[SendDrop] closed: {self.peer_str} {cell}")
            return False

        buf = self.protocol.serialize(cell)
        now = asyncio.get_running_loop().time()

        # Treat AUTHENTICATE(AUTH0003) as control-plane SOLO:
        # It must not be merged with other ctrl cells into a single blob.
        if isinstance(cell, CellAuthenticate) and cell.auth_type == 0x0003:
            await self._q_ctrl.put((buf, now, self._CTRL_SOLO, None))
            self._wakeup.set()
            return False

        if self._is_control_cell(cell):
            await self._q_ctrl.put((buf, now, 0, None))
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
                    item = await self._q_ctrl.get()

                    # Backward compatibility if any old tuples exist
                    # Old: (buf, enqueued_at)
                    if len(item) == 2:
                        buf, enqueued_at = item
                        flags, fut = 0, None
                    else:
                        buf, enqueued_at, flags, fut = item

                    # Barrier: flush all pending ctrl bytes then resolve the future
                    if flags & self._CTRL_BARRIER:
                        if out:
                            await self._write_once(bytes(out))
                            out.clear()
                        if fut is not None and not fut.done():
                            fut.set_result(True)
                        continue

                    # SOLO: flush pending ctrl, then write this buf alone
                    if flags & self._CTRL_SOLO:
                        if out:
                            await self._write_once(bytes(out))
                            out.clear()
                        await self._write_once(buf)
                        continue

                    out.extend(buf)
                    self._maybe_log_queue("ctrl", enqueued_at, self._q_ctrl.qsize())
                    ctrl_count += 1
                    if (loop.time() - t0) > 0.0002 or ctrl_count >= 8:
                        break

                if out:
                    await self._write_once(bytes(out))
                    continue

                # Data plane (keep your existing logic)
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
                    await self._write_once(bytes(out))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            self.print(f"[WriterLoopErr] {self.peer_str} {e}")
        finally:
            await self._abort()

    async def _send_raw_immediate(self, raw: bytes, *, update_transcript: bool = True):
        if self._closing.is_set() or self.writer is None:
            raise RuntimeError("Socket closed; cannot send raw bytes")

        try:
            if self._limiter is not None:
                await self._limiter.consume(len(raw))

            if self._inj is not None:
                await self._inj.send(raw)
            else:
                self.writer.write(raw)
                await self.writer.drain()

            if update_transcript:
                self.link_transcript.update_sent(raw)
        except Exception:
            await self._abort()
            raise

    async def _write_once(self, blob: bytes):
        if self._closing.is_set() or self.writer is None:
            return
        try:
            if self._inj is not None:
                await self._inj.send(blob)
            else:
                self.writer.write(blob)
                await self.writer.drain()

            # Update transcript only after the write has completed
            self.link_transcript.update_sent(blob)
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

        self.link_transcript.update_recv(raw)
        hdr_hex = raw[:header_len].hex() if raw else ""
        # self.print(f"[HDR] ver={self.protocol.version} hlen={header_len} circ={circ_id} cmd={cmd_num} hdr={hdr_hex}")


        if not cell_cls.is_var_len():
            expected_len = header_len + TorCell.MAX_PAYLOAD_SIZE
            if self.protocol.version >= 4 and expected_len == 514 and len(raw) != expected_len:
                raise ValueError(f"[RECV-LEN] cmd={cmd_num} raw_len={len(raw)} expected={expected_len}")
            # print(f"[RecvCell] cmd={cmd_num} raw_len={len(raw)}")
        else:
            # print(f"[RecvCell] cmd={cmd_num} raw_len={len(raw)}")
            pass
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
        self._auth_methods: list[int] = []
        self._slog_at_auth_challenge: bytes | None = None

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
            # Minimal AUTH0003 structural validation (length + TYPE marker).
            if getattr(cell, "auth_type", None) == AUTH_METHOD_ED25519_SHA256:
                signed, sig = _parse_auth0003(cell.auth_data)  # will raise if invalid

        elif isinstance(cell, CellCerts):
            if self.state.value < HandshakeState.GOT_VERSIONS.value:
                raise RuntimeError("Received CERTS before VERSIONS during handshake")
            self._set_state(HandshakeState.GOT_CERTS)
        elif isinstance(cell, CellAuthChallenge):
            if self.state.value < HandshakeState.GOT_CERTS.value:
                raise RuntimeError("Received AUTH_CHALLENGE before CERTS during handshake")
            self._set_state(HandshakeState.GOT_AUTH_CHAL)
            self._auth_challenge = cell.challenge
            self._auth_methods = list(getattr(cell, "methods", []) or [])
            self._slog_at_auth_challenge = self.tor_socket.link_transcript.snapshot_recv_digest()
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

    @property
    def auth_methods(self) -> list[int]:
        return list(self._auth_methods)

    def mark_done(self):
        if self.state == HandshakeState.DONE:
            return
        self._set_state(HandshakeState.DONE)
        self.tor_socket._mark_handshake_complete()

    @staticmethod
    def rsa_identity_digest_pkcs1(rsa_public_key) -> bytes:
        """
        Return SHA256(DER(PKCS#1 RSAPublicKey)).

        This intentionally does *not* use SubjectPublicKeyInfo.
        """

        if not hasattr(rsa_public_key, "public_bytes"):
            if hasattr(rsa_public_key, "public_key"):
                rsa_public_key = rsa_public_key.public_key()
            else:
                raise TypeError("rsa_public_key must expose public_bytes or public_key()")

        der = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )
        digest = hashlib.sha256(der).digest()
        assert len(digest) == 32
        return digest

    def build_auth0003_body(
        self,
        *,
        cid: bytes,
        sid: bytes,
        cid_ed: bytes,
        sid_ed: bytes,
        slog: bytes,
        clog: bytes,
        scert: bytes,
        tlssecrets: bytes,
    ) -> bytes:
        """

        Minimal self-test example (requires ed25519 keys and a link_auth_key)::

            fake32 = b"\x11" * 32
            body = handshake.build_auth0003_body(
                cid=fake32,
                sid=fake32,
                cid_ed=fake32,
                sid_ed=fake32,
                slog=fake32,
                clog=fake32,
                scert=fake32,
                tlssecrets=fake32,
            )

            handshake.tor_socket.link_auth_key.public_key().verify(signature, signed_part)

        """

        for name, val in (
            ("cid", cid),
            ("sid", sid),
            ("cid_ed", cid_ed),
            ("sid_ed", sid_ed),
            ("slog", slog),
            ("clog", clog),
            ("scert", scert),
            ("tlssecrets", tlssecrets),
        ):
            if len(val) != 32:
                raise AssertionError(f"{name} must be 32 bytes, got {len(val)}")

        if not isinstance(self.tor_socket.link_auth_key, ed25519.Ed25519PrivateKey):
            raise TypeError("link_auth_key must be an Ed25519PrivateKey")

        auth_type = b"AUTH0003"
        assert len(auth_type) == 8
        rand_bytes = os.urandom(24)
        signed_part = (
            auth_type
            + cid
            + sid
            + cid_ed
            + sid_ed
            + slog
            + clog
            + scert
            + tlssecrets
            + rand_bytes
        )


        assert len(signed_part) == 288

        self.tor_socket.print(
            "[AUTH0003] CID/SID/CID_ED/SID_ED"
            f" {cid[:8].hex()} {sid[:8].hex()} {cid_ed[:8].hex()} {sid_ed[:8].hex()}"
        )
        self.tor_socket.print(
            "[AUTH0003] SLOG/CLOG"
            f" {slog[:8].hex()} {clog[:8].hex()}"
        )
        self.tor_socket.print(
            "[AUTH0003] SCERT/TLSSECRETS"
            f" {scert[:8].hex()} {tlssecrets[:8].hex()}"
        )

        signature = self.tor_socket.link_auth_key.sign(signed_part)
        assert len(signature) == 64

        body = signed_part + signature
        assert len(body) == 352
        return body

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
        self.peer_identity_digest = None
        self.peer_ed_identity_pub = None
        self.peer_cert_list = cell_certs.certs

        # Reset fields to avoid stale values from previous connections
        self.peer_identity_digest = None
        self.peer_ed_identity_pub = None

        for cert_type, cert_bytes in self.peer_cert_list:
            if cert_type == CT_RSA_ID_X509:
                if self.peer_identity_digest is not None:
                    raise ValueError("Duplicate CT_RSA_ID_X509 in CERTS")

                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                pub = cert.public_key()
                if not isinstance(pub, rsa.RSAPublicKey):
                    raise ValueError(f"CT_RSA_ID_X509 is not an RSA public key: {type(pub)}")

                # Tor expects SHA256(DER(RSA public key)), often PKCS#1 RSAPublicKey DER
                self.peer_identity_digest = self.rsa_identity_digest_pkcs1(pub)


            elif cert_type == CT_RSA_TO_ED_CROSS:
                if self.peer_ed_identity_pub is not None:
                    raise ValueError("Duplicate CT_RSA_TO_ED_CROSS in CERTS")

                # CT_RSA_TO_ED_CROSS is not guaranteed to start with the ASCII prefix.
                # In Tor link certs, the Ed25519 identity key is the first 32 bytes of the crosscert body.
                self.peer_ed_identity_pub = parse_rsa_to_ed_crosscert_ed_pub(cert_bytes)

            else:
                # Ignore other cert types here if you don't need them
                continue

        if self.peer_identity_digest is None:
            raise ValueError("Missing peer RSA identity digest from CERTS (CT_RSA_ID_X509)")
        if self.peer_ed_identity_pub is None:
            raise ValueError("Missing peer Ed25519 identity pubkey from CERTS (CT_RSA_TO_ED_CROSS)")

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

def _parse_auth0003(auth_data: bytes):
    if len(auth_data) < 352:
        raise RuntimeError("AUTH0003 too short")
    if auth_data[:8] != b"AUTH0003":
        raise RuntimeError("AUTH0003 TYPE mismatch")
    signed = auth_data[:288]
    sig = auth_data[288:352]
    return signed, sig


def parse_rsa_to_ed_crosscert_ed_pub(cert_bytes: bytes) -> bytes:
    # English comments, as you prefer
    prefix = b"Tor TLS RSA/Ed25519 cross-certificate"
    if cert_bytes.startswith(prefix):
        cert_bytes = cert_bytes[len(prefix):]

    if len(cert_bytes) < 32:
        raise ValueError(f"RSA->Ed crosscert too short: {len(cert_bytes)} bytes")

    # The first 32 bytes are the Ed25519 identity public key
    return cert_bytes[:32]
