import asyncio
import ssl
import struct
import time
import contextlib
from pathlib import Path
from typing import Optional, Callable, Awaitable, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

from examples.Tor_simplified.Tor_Cell import TorCell, CellCerts, CellAuthChallenge, TorCommands,\
    CellVersions, CellNetInfo, AUTH_METHOD_ED25519_SHA256, CellAuthenticate
from examples.Tor_simplified.Tor_Router import logger
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
    CT_RSA_TO_ED_CROSS
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

        if self.reader is not None:
            # 被动连接，已经有SSL socket
            try:
                self.transport = writer.transport
                self.socket = self.transport.get_extra_info("socket")

                self.peer = self.transport.get_extra_info("peername")
                self.peer_str = f"{self.peer[0]}:{self.peer[1]}"
                self.local = self.socket.getsockname()
                self.local_str = f"{self.local[0]}:{self.local[1]}"
            except:
                self.peer = None
                self.peer_str = "unknown"

            # ★ 已有 reader/writer 的场景（被动接受），异步创建注入器
            asyncio.create_task(self._ensure_injector())
        else:
            self.peer = None
            self.peer_str = "not_connected"

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
                await self.on_cell(cell, self)
            except Exception as e:
                import traceback
                stack = traceback.format_exc()
                self.print("[STACKTRACE]", stack)
                self.print(f"[ParseErr] {e}")

    async def tor_handshake_client(self):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        net_info_cell = await self.handshake.make_net_info(self.peer, self.local)
        await self.send_cell(net_info_cell)
        self.handshake_done.set()

    async def tor_handshake_server(self, peer_version_cell: CellVersions, certs_cell, certs_path):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        self.protocol.version = self.handshake.retrieve_versions(peer_version_cell)
        await self.send_cell(certs_cell)
        auth_cell = CellAuthChallenge()
        await self.send_cell(auth_cell)
        net_info_cell = await self.handshake.make_net_info(self.peer, self.socket.getsockname())
        await self.send_cell(net_info_cell)

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
        header_len = struct.calcsize(self.protocol.header_format)
        header = await self._wait_for_bytes(header_len, consume=False)
        if header is None:
            return None
        try:
            circ_id, cmd_num = struct.unpack(self.protocol.header_format, header)
            cell_cls = TorCommands.get_by_num(cmd_num)
        except struct.error as e:
            self.print(f"Header unpack error: {e}")
            await self.buffer.pop(1)
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
        return cell.serialize(self.version)


class TorHandshake:
    def __init__(self, tor_socket, tor_protocol=TorProtocol):
        self.tor_socket = tor_socket
        self.tor_protocol = tor_protocol
        self.version_event = self._make_new_event()
        self.peer_identity_digest: bytes | None = None
        self.peer_ed_identity_pub: bytes | None = None
        self.peer_tls_cert_der: bytes | None = None
        self.peer_cert_list: list[tuple[int, bytes]] = []

    @staticmethod
    def _make_new_event():
        return asyncio.Event()

    def make_versions(self):
        version_cell = CellVersions(self.tor_protocol.SUPPORTED_VERSION)
        return version_cell

    async def make_net_info(self, remote_addr, local_addr, wait_time=60):
        await asyncio.wait_for(self.version_event.wait(), wait_time)
        logger.debug('Sending NET_INFO cell...')
        other_or = remote_addr[0]
        this_or = local_addr[0]
        net_info_cell = CellNetInfo(int(time.time()), other_or, this_or)
        return net_info_cell

    def retrieve_versions(self, cell):
        assert isinstance(cell, CellVersions)
        logger.debug('Remote protocol versions: %s', cell.versions)
        version = min(max(self.tor_protocol.SUPPORTED_VERSION), max(cell.versions))
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
