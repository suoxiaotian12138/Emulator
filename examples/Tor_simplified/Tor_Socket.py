import asyncio
import ssl
import struct
import time
import contextlib
from pathlib import Path
from typing import Optional, Callable, Awaitable
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes


from examples.Tor_simplified.Tor_Cell import TorCell, CellCerts, CellAuthChallenge, TorCommands,\
    CellVersions, CellNetInfo, AUTH_METHOD_ED25519_SHA256, CellAuthenticate
from examples.Tor_simplified.Tor_Router import logger
from tools.Packet.packet_TCP import ByteBuffer
from tools.Packet.packet_TCP import dial_tls
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
    def __init__(self,  source_ip: str, node_id: Optional[str],  reader: asyncio.StreamReader = None, writer: asyncio.StreamWriter=None, on_cell=None):
        self.protocol = TorProtocol()
        self._send_lock = asyncio.Lock()
        self.handshake = TorHandshake(self)
        self.print = print
        self.buffer = ByteBuffer()
        self.on_cell: Optional[Callable[[TorCell, Tor_Socket], Awaitable[None]]] = on_cell
        self.handshake_initiator = False
        self.source_ip = source_ip
        self.node_id = node_id
        self.handshake_done = asyncio.Event()
        self.listen_started = asyncio.Event()
        self._closing = asyncio.Event()
        self.closed = False

        # 异步I/O组件
        self.reader: Optional[asyncio.StreamReader] = reader
        self.writer: Optional[asyncio.StreamWriter] = writer

        self._q_ctrl = asyncio.Queue()  # 控制面队列（自动优先）
        self._q_data = asyncio.Queue()  # 数据面队列
        self._wakeup = asyncio.Event()  # 有新数据时唤醒 writer
        self._writer_task = None

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
        else:
            self.peer = None
            self.peer_str = "not_connected"

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

    # @classmethod
    # async def dial(cls, remote_addr: tuple[str, int],
    #                source_ip: str,
    #                on_cell,
    #                sem: asyncio.Semaphore | None = None,
    #                ssl_ctx: ssl.SSLContext | None = None):
    #     ssl_ctx = ssl_ctx or _default_client_ctx()
    #     if sem is None:
    #         sem = asyncio.Semaphore(200)
    #     async with sem:                    # 并发限流
    #         print(f"[CLIENT] dial_tls to {remote_addr} from {source_ip}")
    #
    #         reader, writer = await asyncio.open_connection(
    #             remote_addr[0], remote_addr[1],
    #             ssl=ssl_ctx,
    #             ssl_handshake_timeout=15.0,
    #             local_addr=(source_ip, 0) if source_ip else None
    #         )
    #         print(f"[CLIENT] tls handshake completed for {remote_addr}")
    #
    #     # 用已有 reader / writer 来构造对象
    #     self = cls(source_ip=source_ip, reader=reader, writer=writer, on_cell=on_cell)
    #     self.handshake_initiator = True
    #     return self

    @classmethod
    async def dial(cls, remote_addr: tuple[str, int],
                   source_ip: str,
                   on_cell,
                   sem: asyncio.Semaphore | None = None,          # 仍保留参数以兼容旧调用（不使用）
                   ssl_ctx: ssl.SSLContext | None = None,          # 兼容位（不使用）
                   node_id: Optional[str] = None):                 # ★ 新增：显式传 node_id 更稳妥
        reader, writer = await dial_tls(
            remote_addr,
            source_ip=source_ip,
            node_id=node_id,
            timeout=15.0
        )
        self = cls(source_ip=source_ip, reader=reader, writer=writer, on_cell=on_cell, node_id=node_id)
        self.handshake_initiator = True
        try:
            self.transport = writer.transport
            self.socket = self.transport.get_extra_info("socket")
            self.peer = self.transport.get_extra_info("peername")
            self.peer_str = f"{self.peer[0]}:{self.peer[1]}"
            self.local = self.socket.getsockname()
            self.local_str = f"{self.local[0]}:{self.local[1]}"
        except Exception:
            pass
        return self

    async def send(self, buf: bytes):
        """异步发送数据"""
        if self._closing.is_set():
            raise ConnectionError("AsyncTor_Socket already closed")

        async with self._send_lock:
            if self._closing.is_set():
                raise ConnectionError("AsyncTor_Socket already closed")

            try:
                if self.writer is None:
                    raise ConnectionError("Writer not initialized")

                self.writer.write(buf)
                await self.writer.drain()

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

        # 正确关闭writer
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()  # 会自动flush pending data

        self.reader = None
        self.writer = None

    async def start_listen(self) -> asyncio.Task:
        if self.reader is None or self.writer is None:
            raise RuntimeError("Streams not set; call setup_socket_async() first or wait for setup completion")

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
                    # 使用16KB缓冲区，减少epoll次数
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
        auth_cell = CellAuthChallenge()        # For simplicity, no verification is performed at this time

        await self.send_cell(auth_cell)

        net_info_cell = await self.handshake.make_net_info(self.peer, self.socket.getsockname())
        await self.send_cell(net_info_cell)

    async def send_cells(self, cells):
        if not cells:
            return
        ba = bytearray()
        ser = self.protocol.serialize
        for cell in cells:
            ba.extend(ser(cell))
        await self.send(bytes(ba))  # send() 内部只 drain 一次

    async def send_cell(self, cell):
        if self._closing.is_set():
            # 不再把上层炸掉；记录并忽略（统一由 _abort 管生命周期）
            self.print(f"[SendDrop] closed: {self.peer_str} {cell}")
            return
        buf = self.protocol.serialize(cell)
        # 自动分类
        if self._is_control_cell(cell):
            await self._q_ctrl.put(buf)
        else:
            await self._q_data.put(buf)
        self._wakeup.set()

    def _is_control_cell(self, cell) -> bool:
        # —— 按 Tor 语义把“握手/控制/建立/关闭/流控”都算控制面 ——
        from examples.Tor_simplified.Tor_Cell import (
            CellVersions, CellCerts, CellAuthChallenge, CellNetInfo,
            Cell_Create2, CellCreated2,
            CellRelayExtend2, CellRelayExtended2,
            CellRelayBegin, CellRelayConnected, CellRelayEnd,
            CellRelaySendMe, CellDestroy,
            Cell_RelayEarly, CellRelay  # 用于判断内部类型
        )

        # 1) link-level
        if isinstance(cell, (CellVersions, CellCerts, CellAuthChallenge, CellNetInfo, CellDestroy)):
            return True

        # 2) circuit 建立/扩展
        if isinstance(cell, (Cell_Create2, CellCreated2, CellRelayExtend2, CellRelayExtended2, Cell_RelayEarly)):
            return True

        # 3) 流建立/关闭/流控
        if isinstance(cell, (CellRelayBegin, CellRelayConnected, CellRelayEnd, CellRelaySendMe)):
            return True

        # 4) 其他 Relay：
        #    只有“纯数据”才算数据面。若是 CellRelay，但 inner 是 Data 以外，也归控制面。
        try:
            # 你自己的 CellRelay 类型里应能区分 inner 类型；保守起见：
            return getattr(cell, "is_data", False) is False
        except Exception:
            return False

    async def _writer_loop(self):
        loop = asyncio.get_running_loop()
        try:
            while not self._closing.is_set():
                # 等待有数据
                if self._q_ctrl.empty() and self._q_data.empty():
                    self._wakeup.clear()
                    try:
                        await asyncio.wait_for(self._wakeup.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        continue

                # 优先把控制面取空（微批窗口：例如 200 微秒）
                out = bytearray()
                t0 = loop.time()
                ctrl_count = 0
                while not self._q_ctrl.empty():
                    out.extend(await self._q_ctrl.get())
                    ctrl_count += 1
                    # 微批：给极短时间让同阶段的几个包入队
                    if (loop.time() - t0) > 0.0002 or ctrl_count >= 8:
                        break
                # 如果刚刚发了控制面，立即冲刷（保证握手/控制低延迟）
                if out:
                    await self._write_once(bytes(out))
                    continue

                # 否则处理数据面：较大窗口合并（例如 2ms / 64KB / 128 cells）
                out.clear()
                t0 = loop.time()
                total = 0
                cells = 0
                while not self._q_data.empty():
                    buf = await self._q_data.get()
                    out.extend(buf)
                    total += len(buf)
                    cells += 1
                    if (loop.time() - t0) > 0.002 or total >= 64 * 1024 or cells >= 128:
                        break
                if out:
                    await self._write_once(bytes(out))
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
            self.writer.write(blob)
            await self.writer.drain()
        except Exception as e:
            self.print(f"[WriteErr] {self.peer_str} {e}")
            await self._abort()

    async def _wait_for_bytes(self, size: int, consume: bool) -> bytes | None:
        """
        等到 ByteBuffer ≥ size 字节后：
          - consume=True  : pop 并返回
          - consume=False : peek 并返回（不弹出）
        """
        if consume:
            return await self.buffer.pop(size)
        else:
            await self.buffer.wait_for(size)
            return await self.buffer.peek(size)

    async def recv_and_parse_cell(self):
        """一次性确保整包就绪后再解析，避免错位。"""
        header_len = struct.calcsize(self.protocol.header_format)

        # 1) 预读 header
        header = await self._wait_for_bytes(header_len, consume=False)
        if header is None:
            return None

        try:
            circ_id, cmd_num = struct.unpack(self.protocol.header_format, header)
            cell_cls = TorCommands.get_by_num(cmd_num)
            # if cell_cls is None:
            #     # 非法命令：丢 1 字节，让流对齐后继续
            #     await self.buffer.pop(1)
            #     self.print(f"Unknown command {cmd_num}, drop 1 byte to resync")
            #     return None
        except struct.error as e:
            self.print(f"Header unpack error: {e}")
            await self.buffer.pop(1)
            return None

        # 2) 计算总长度
        if cell_cls.is_var_len():
            # 先确保 header + 2 字节长度字段可用
            hdr_plus = await self._wait_for_bytes(header_len + 2, consume=False)
            if hdr_plus is None:
                return None
            (payload_len,) = struct.unpack(self.protocol.length_format, hdr_plus[-2:])
            total_len = header_len + 2 + payload_len
        else:
            total_len = header_len + TorCell.MAX_PAYLOAD_SIZE

        # 3) 真正取走整包
        raw = await self._wait_for_bytes(total_len, consume=True)
        if raw is None:
            return None

        # 4) 反序列化
        payload_offset = header_len + (2 if cell_cls.is_var_len() else 0)
        payload = raw[payload_offset:]
        try:
            return self.protocol.deserialize(cell_cls, payload, circ_id)
        except Exception as e:
            self.print(f"Cell parse error: {e}")
            return None

    async def _recv_header(self):
        """接收并解析cell header"""
        header_size = struct.calcsize(self.protocol.header_format)
        header = await self.buffer.extract_by_size(header_size)
        if not header:
            return None

        try:
            circuit_id, command_num = struct.unpack(self.protocol.header_format, header)
            # print(f"[IN ] circ={circuit_id} cmd=0x{command_num:02x}")  # 加这一行
            cell_type = TorCommands.get_by_num(command_num)
            if not cell_type:
                raise ValueError(f"Unknown command number: {command_num}")
            return circuit_id, command_num, cell_type
        except (struct.error, ValueError) as e:
            self.print(f"Header parsing error: {e}")
            return None

    async def _recv_var_length(self):
        """接收变长cell的长度字段"""
        len_size = struct.calcsize(self.protocol.length_format)
        len_bytes = await self.buffer.extract_by_size(len_size)
        if not len_bytes:
            return None

        try:
            (payload_len,) = struct.unpack(self.protocol.length_format, len_bytes)
            # 验证长度合理性
            if payload_len > 65535:  # Tor规范的最大变长cell大小
                raise ValueError(f"Invalid payload length: {payload_len}")
            return payload_len
        except (struct.error, ValueError) as e:
            self.print(f"Length parsing error: {e}")
            return None

    async def _recv_payload(self, payload_len: int):
        """接收cell payload"""
        if payload_len == 0:
            return b''
        payload = bytes(await self.buffer.extract_by_size(payload_len))
        if not payload:
            return None
        if len(payload) != payload_len:
            self.print(f"Payload length mismatch: expected {payload_len}, got {len(payload)}")
            return None

        return payload


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
        #    CircuitID                          [CIRCUIT_ID_LEN octets]
        #    Command                            [1 byte]
        if self.version < 4:
            return '!HB'
        else:
            # Link protocol 4 increases circuit ID width to 4 bytes.
            return '!IB'

    @property
    def length_format(self):
        #    Length                             [2 octets; big-endian integer]
        return '!H'

    def deserialize(self, command, payload, circuit_id=0):
        # parse depending on version
        # ...
        return TorCell.deserialize(command, circuit_id, payload, self.version)

    def serialize(self, cell):
        # get bytes depending on version
        # ...
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
        """If version 2 or higher is negotiated, each party sends the other a NETINFO cell."""
        logger.debug('Sending NET_INFO cell...')
        # 对端地址
        other_or = remote_addr[0]
        # 本地监听地址
        this_or = local_addr[0]
        net_info_cell = CellNetInfo(int(time.time()), other_or, this_or)
        return net_info_cell

    def retrieve_versions(self, cell):
        assert isinstance(cell, CellVersions)

        logger.debug('Remote protocol versions: %s', cell.versions)
        version = min(max(self.tor_protocol.SUPPORTED_VERSION), max(cell.versions))
        self.version_event.set()

        # Choose maximum supported by both
        return version

    def retrieve_certs(self, cell_certs: CellCerts):
        """
        在收到 CERTS Cell 时被调用：
          1) 保存原始证书列表
          2) 从 RSA_ID_X509 提取对端 RSA 身份公钥摘要
          3) 从 RSA→ED crosscert (type 7) 中提取对端 Ed25519 公钥（32B）
        """
        # 1) 保存原始列表
        self.peer_cert_list = cell_certs.certs

        for cert_type, cert_bytes in self.peer_cert_list:
            # 2) RSA 身份证书 => 计算并保存 Digest（32B SHA256 of SPKI）
            if cert_type == CT_RSA_ID_X509:
                cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
                spki = cert.public_key().public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                digest.update(spki)
                self.peer_identity_digest = digest.finalize()

            # 3) RSA->ED crosscert => 直接 slice 出 32B Ed 公钥
            elif cert_type == CT_RSA_TO_ED_CROSS:
                # crosscert 格式：CROSSCERT_PREFIX (固定) | ED_PUB(32B) | EXP(4B) | SIGLEN(1B) | SIG(...)
                CROSSCERT_PREFIX = b"Tor TLS RSA/Ed25519 cross-certificate"
                prefix_len = len(CROSSCERT_PREFIX)
                ed_pub = cert_bytes[prefix_len : prefix_len + 32]
                self.peer_ed_identity_pub = ed_pub


    def retrieve_net_info(self, cell):
        logger.debug('Retrieving NET_INFO cell...')

    def recv_authenticate(self, cell):
        logger.debug('Retrieving authenticate cell...')



def load_cert_for_cellcerts(path: str):
    """
    读取 PEM 或 DER 格式证书，转换为 Tor CellCerts 的格式元组 (type, cert_bytes)

    :param path: 证书文件路径（支持 .crt / .pem / .der）
    :param cert_type: 对应的 Tor 证书类型（如 2 表示 Link cert）
    :return: (cert_type, cert_bytes)
    """
    file_path = Path(path)
    cert_bytes = file_path.read_bytes()

    try:
        # 尝试解析为 PEM
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        raw = cert.public_bytes(encoding=serialization.Encoding.DER)
    except ValueError:
        # 可能是 DER 格式，直接返回原始数据
        raw = cert_bytes

    return raw

def make_ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # 可按需加载根证书 / 设置 cipher 等
    return ctx

def _default_client_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=1")  # 可选：降低安全等级以兼容自签证书
    return ctx

