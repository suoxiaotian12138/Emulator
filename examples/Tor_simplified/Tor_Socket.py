import asyncio
import socket
import ssl
import struct
from contextlib import suppress
from typing import Tuple
import time
import hashlib
import os
import contextlib
from pathlib import Path
from typing import Optional, Callable, Awaitable
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from tools.Packet.packet_TCP import send_tcp, ByteBuffer, monitor_connection_tls


from examples.Tor_simplified.Tor_Cell import TorCell, CellCerts, CellAuthChallenge, TorCommands,\
    CellVersions, CellNetInfo, AUTH_METHOD_ED25519_SHA256, CellAuthenticate
from examples.Tor_simplified.Tor_Router import logger

from tools.Packet.packet_TCP import send_any
from tools.Crypt.crypt_common import (
    rsa_identity_digest,
    debug_build_crosscert,
    CT_RSA_ID_X509,
    CT_RSA_TO_ED_CROSS
)

# class Tor_Socket():
#     def __init__(self, source_ip , on_cell=None, sock=None):
#         self.protocol = TorProtocol()
#         self.socket = sock
#         self._send_lock = asyncio.Lock()
#         self.handshake = TorHandshake(self)
#         self.print = print
#         self.buffer = ByteBuffer()
#         self.on_cell: Optional[Callable[[TorCell, Tor_Socket], Awaitable[None]]] = on_cell
#         self.handshake_initiator = False
#         self.source_ip = source_ip
#         self.handshake_done = asyncio.Event()
#         self.listen_started = asyncio.Event()
#
#         self._loop = asyncio.get_running_loop()
#         if sock is not None:
#             # 被动接受：sock 已经是 ssl.SSLSocket
#             self.socket = sock
#             self.send = lambda _s, buf: send_any(self._loop, self.socket, buf)
#         else:
#             # 主动连接：稍后在 setup_socket() 里绑定 writer‑send
#             self.socket = None
#             self.send = None
#
#     async def setup_socket(self, remote_addr):
#         """
#         **替换版**：只做 TLS 握手，之后所有 I/O 走同一把 SSLSocket
#         """
#         self.handshake_initiator = True
#         loop = asyncio.get_running_loop()
#
#         # 1) 拿到已握手、非阻塞的 SSLSocket
#         self.socket = await dial_tls(
#             loop,
#             remote_addr,
#             local_ip=self.source_ip  # 沿用原来的本地地址绑定
#         )
#         if self.socket is None:
#             raise RuntimeError("dial_tls returned None — socket creation failed")
#         # 2) 发送函数保持旧签名：send(sock, data)
#         self.send = lambda _unused, buf: send_any(loop, self.socket, buf)
#
#
#     async def tor_handshake_client(self):
#         version_cell = self.handshake.make_versions()
#         await self.send_cell(version_cell)
#         net_info_cell = await self.handshake.make_net_info(self.socket.getpeername(), self.socket.getsockname())
#         await self.send_cell(net_info_cell)
#
#         self.handshake_done.set()
#         print("handshake has done")
#
#
#     async def tor_handshake_server(self, peer_version_cell: CellVersions, certs_cell, certs_path):
#         version_cell = self.handshake.make_versions()
#         await self.send_cell(version_cell)
#         self.protocol.version = self.handshake.retrieve_versions(peer_version_cell)
#
#         await self.send_cell(certs_cell)
#         auth_cell = CellAuthChallenge()        # For simplicity, no verification is performed at this time
#
#         await self.send_cell(auth_cell)
#
#         net_info_cell = await self.handshake.make_net_info(self.socket.getsockname(), self.socket.getpeername())
#         await self.send_cell(net_info_cell)
#
#     async def start_listen(self) -> asyncio.Task:
#         """
#         启动监听、处理、监控三大任务，并返回生命周期句柄 task。
#         """
#         loop = asyncio.get_running_loop()
#         # 启动监听和处理任务
#         self._recv_task = loop.create_task(
#             monitor_connection_tls(
#                 conn=self.socket,
#                 addr=self.socket.getpeername(),
#                 buffer=self.buffer
#             )
#         )
#         self._process_task = loop.create_task(self.process())
#         self._handle_task = loop.create_task(self.monitor_handle())
#         self.listen_started.set()
#         return self._handle_task  # ⬅ 上层 await 这个任务就可以知道连接是否中断
#
#     async def monitor_handle(self):
#         """
#         监控监听与处理任务，一旦有一方结束，就统一清理并打印 peer
#         """
#         peer = None
#         try:
#             peer = self.socket.getpeername()
#         except Exception:
#             pass
#
#         try:
#             await asyncio.wait(
#                 [self._recv_task, self._process_task],
#                 return_when=asyncio.FIRST_COMPLETED,
#             )
#         finally:
#             try:
#                 local = self.socket.getsockname() if self.socket else None
#             except Exception as e:
#                 local = f"<err: {e}>"
#
#             try:
#                 peer = self.socket.getpeername() if self.socket else peer
#             except Exception:
#                 pass
#
#             self.print(f"[CLOSE-{'CLI' if self.handshake_initiator else 'SRV'}] {self.source_ip} <---> {peer}")
#             self.print(f"[CLOSE] {local} <---> {peer}")
#
#             # 清理任务
#             self._recv_task.cancel()
#             self._process_task.cancel()
#
#             # 安全关闭 socket
#             if self.socket:
#                 try:
#                     self.socket.shutdown(socket.SHUT_RDWR)
#                 except Exception:
#                     pass
#                 try:
#                     self.socket.close()
#                 except Exception:
#                     pass
#                 self.socket = None  # 标记为关闭
#
#     async def process(self):
#         """主处理循环"""
#         while True:
#             try:
#                 cell = await self.recv_and_parse_cell()
#                 if not cell:
#                     continue
#                 await self.on_cell(cell, self)
#             except Exception as e:
#                 self.print(f"Cell parse error: {e}")
#
#     async def send_cells(self, cells):
#         for cell in cells:
#             print("send cell:", cell)
#             cell = self.protocol.serialize(cell)
#             print("send cell content:", cell)
#
#             async with self._send_lock:
#                 try:
#                     await self.send(self.socket, cell)
#                 except OSError as e:
#                     print(f"[Error] Socket send failed: {e}")
#
#     async def send_cell(self, cell):
#         print(self.source_ip, "send cell:", self.socket.getpeername(), cell)
#         buffer = self.protocol.serialize(cell)
#         print("send cell content:", buffer)
#
#         async with self._send_lock:
#             try:
#                 await self.send(self.socket, buffer)
#             except OSError as e:
#                 print(f"[Error] Socket send failed: {e}")
#                 raise
#
#     async def _wait_for_bytes(self, size: int, consume: bool) -> bytes | None:
#         """
#         等到 ByteBuffer ≥ size 字节后：
#           - consume=True  : pop 并返回
#           - consume=False : peek 并返回（不弹出）
#         """
#         if consume:
#             return await self.buffer.pop(size)
#         else:
#             await self.buffer.wait_for(size)
#             return await self.buffer.peek(size)
#
#     async def recv_and_parse_cell(self):
#         """一次性确保整包就绪后再解析，避免错位。"""
#         header_len = struct.calcsize(self.protocol.header_format)
#
#         # 1) 预读 header
#         header = await self._wait_for_bytes(header_len, consume=False)
#         if header is None:
#             return None
#
#         try:
#             circ_id, cmd_num = struct.unpack(self.protocol.header_format, header)
#             cell_cls = TorCommands.get_by_num(cmd_num)
#             # if cell_cls is None:
#             #     # 非法命令：丢 1 字节，让流对齐后继续
#             #     await self.buffer.pop(1)
#             #     self.print(f"Unknown command {cmd_num}, drop 1 byte to resync")
#             #     return None
#         except struct.error as e:
#             self.print(f"Header unpack error: {e}")
#             await self.buffer.pop(1)
#             return None
#
#         # 2) 计算总长度
#         if cell_cls.is_var_len():
#             # 先确保 header + 2 字节长度字段可用
#             hdr_plus = await self._wait_for_bytes(header_len + 2, consume=False)
#             if hdr_plus is None:
#                 return None
#             (payload_len,) = struct.unpack(self.protocol.length_format, hdr_plus[-2:])
#             total_len = header_len + 2 + payload_len
#         else:
#             total_len = header_len + TorCell.MAX_PAYLOAD_SIZE
#
#         # 3) 真正取走整包
#         raw = await self._wait_for_bytes(total_len, consume=True)
#         print(self.source_ip ,"recv raw:", raw)
#         if raw is None:
#             return None
#
#         # 4) 反序列化
#         payload_offset = header_len + (2 if cell_cls.is_var_len() else 0)
#         payload = raw[payload_offset:]
#         try:
#             return self.protocol.deserialize(cell_cls, payload, circ_id)
#         except Exception as e:
#             self.print(f"Cell parse error: {e}")
#             return None
#
#     async def _recv_header(self):
#         """接收并解析cell header"""
#         header_size = struct.calcsize(self.protocol.header_format)
#         header = await self.buffer.extract_by_size(header_size)
#         if not header:
#             return None
#
#         try:
#             circuit_id, command_num = struct.unpack(self.protocol.header_format, header)
#             # print(f"[IN ] circ={circuit_id} cmd=0x{command_num:02x}")  # 加这一行
#             cell_type = TorCommands.get_by_num(command_num)
#             if not cell_type:
#                 raise ValueError(f"Unknown command number: {command_num}")
#             return circuit_id, command_num, cell_type
#         except (struct.error, ValueError) as e:
#             self.print(f"Header parsing error: {e}")
#             return None
#
#     async def _recv_var_length(self):
#         """接收变长cell的长度字段"""
#         len_size = struct.calcsize(self.protocol.length_format)
#         len_bytes = await self.buffer.extract_by_size(len_size)
#         if not len_bytes:
#             return None
#
#         try:
#             (payload_len,) = struct.unpack(self.protocol.length_format, len_bytes)
#             # 验证长度合理性
#             if payload_len > 65535:  # Tor规范的最大变长cell大小
#                 raise ValueError(f"Invalid payload length: {payload_len}")
#             return payload_len
#         except (struct.error, ValueError) as e:
#             self.print(f"Length parsing error: {e}")
#             return None
#
#     async def _recv_payload(self, payload_len: int):
#         """接收cell payload"""
#         if payload_len == 0:
#             return b''
#         payload = bytes(await self.buffer.extract_by_size(payload_len))
#         if not payload:
#             return None
#         if len(payload) != payload_len:
#             self.print(f"Payload length mismatch: expected {payload_len}, got {len(payload)}")
#             return None
#
#         return payload


class Tor_Socket():
    def __init__(self, source_ip , on_cell=None, sock=None):
        self.protocol = TorProtocol()
        self.socket = sock
        self._send_lock = asyncio.Lock()
        self.handshake = TorHandshake(self)
        self.print = print
        self.buffer = ByteBuffer()
        self.on_cell: Optional[Callable[[TorCell, Tor_Socket], Awaitable[None]]] = on_cell
        self.handshake_initiator = False
        self.source_ip = source_ip
        self.handshake_done = asyncio.Event()
        self.listen_started = asyncio.Event()
        self._closing = asyncio.Event()
        self.closed = False

        self._loop = asyncio.get_running_loop()
        if sock is not None:
            # passive side, already TLS‑wrapped
            sock.setblocking(False)
            self._raw_send = lambda buf: send_any(self._loop, self.socket, buf)
            self.peer = sock.getpeername()
        else:
            self.socket = None
            self._raw_send = None
            self.peer = None

    async def send(self, buf: bytes):
        """
        Thread‑safe + close‑aware send wrapper.
        """
        if self._closing.is_set():
            raise ConnectionError("Tor_Socket already closed")

        async with self._send_lock:
            if self._closing.is_set():
                raise ConnectionError("Tor_Socket already closed")

            try:
                await self._raw_send(buf)
            except Exception as e:
                self.print(f"[SendErr] {self.peer} {e}")
                await self._abort()
                raise
    async def _abort(self):
        """
        Idempotent connection closing.
        """
        if self._closing.is_set():
            return

        self._closing.set()
        self.closed = True

        if self.socket:
            with contextlib.suppress(Exception):
                self.socket.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(Exception):
                self.socket.close()
        self.socket = None
        self._raw_send = None
    async def setup_socket(self, remote_addr: Tuple[str, int]):
        """
        Active side: perform TCP+TLS connect and bind _raw_send.
        """
        self.handshake_initiator = True
        self.socket = await dial_tls(self._loop, remote_addr, local_ip=self.source_ip)

        if self.socket is None:
            raise RuntimeError("dial_tls returned None — socket creation failed")

        self.socket.setblocking(False)
        self._raw_send = lambda buf: send_any(self._loop, self.socket, buf)
        self.peer = self.socket.getpeername()


    async def tor_handshake_client(self):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        net_info_cell = await self.handshake.make_net_info(self.socket.getpeername(), self.socket.getsockname())
        await self.send_cell(net_info_cell)

        self.handshake_done.set()
        print("handshake has done")


    async def tor_handshake_server(self, peer_version_cell: CellVersions, certs_cell, certs_path):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        self.protocol.version = self.handshake.retrieve_versions(peer_version_cell)

        await self.send_cell(certs_cell)
        auth_cell = CellAuthChallenge()        # For simplicity, no verification is performed at this time

        await self.send_cell(auth_cell)

        net_info_cell = await self.handshake.make_net_info(self.socket.getsockname(), self.socket.getpeername())
        await self.send_cell(net_info_cell)

    async def start_listen(self) -> asyncio.Task:
        """
        Spawn recv / process / monitor tasks and return handle of monitor.
        """
        if self.socket is None:
            raise RuntimeError("Socket not set; call setup_socket() first")

        self.peer = self.socket.getpeername()

        loop = asyncio.get_running_loop()
        self._recv_task = loop.create_task(
            monitor_connection_tls(conn=self.socket,
                                   addr=self.peer,
                                   buffer=self.buffer)
        )
        self._process_task = loop.create_task(self._process_loop())
        self._handle_task = loop.create_task(self.monitor_handle())

        self.listen_started.set()
        return self._handle_task

    async def monitor_handle(self):
        """
        Wait until either recv or process task finishes, then close socket safely.
        """
        try:
            await asyncio.wait(
                [self._recv_task, self._process_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            await self._abort()
            # cancel siblings
            for t in (self._recv_task, self._process_task):
                with contextlib.suppress(Exception):
                    t.cancel()

            self.print(f"[CLOSE-{'CLI' if self.handshake_initiator else 'SRV'}]"
                       f" {self.source_ip} <---> {self.peer}")
    async def _process_loop(self):
        """
        Read bytes from ByteBuffer, parse Tor cells and call on_cell().
        Keep running until buffer / recv task ends.
        """
        while not self._closing.is_set():
            try:
                cell = await self.recv_and_parse_cell()
                if cell is None:
                    continue
                await self.on_cell(cell, self)
            except Exception as e:
                # Keep connection alive; just log and continue
                import traceback, sys
                stack = traceback.format_exc()
                self.print("[STACKTRACE]", stack)
                self.print(f"[ParseErr] {e}")

    async def send_cells(self, cells):
        for cell in cells:
            await self.send_cell(cell)

    async def send_cell(self, cell):
        print(self.source_ip, "send cell:", self.peer, cell)
        buffer = self.protocol.serialize(cell)
        print("send cell content:", buffer)
        await self.send(buffer)

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
        print(self.source_ip ,"recv raw:", raw)
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

async def dial_tls(loop: asyncio.AbstractEventLoop,
                   remote: tuple[str, int],
                   local_ip: Optional[str] = None,
                   ctx: Optional[ssl.SSLContext] = None,
                   sock_opts: Optional[list[tuple[int, int, int]]] = None,
                   timeout: float = 10.0) -> socket.socket:
    """
    支持：
    - TCP连接
    - TLS握手（线程池）
    - 超时控制
    - sockopts 设置
    """
    ctx = ctx or make_ssl_context()
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if local_ip:
        raw.bind((local_ip, 0))

    raw.setblocking(False)

    if sock_opts:
        for lev, opt, val in sock_opts:
            with suppress(OSError):
                raw.setsockopt(lev, opt, val)

    try:
        print(f"[dial_tls] Connecting to {remote} from {local_ip or 'default'}")
        await asyncio.wait_for(loop.sock_connect(raw, remote), timeout=timeout)
        print(f"[dial_tls] TCP connected to {remote}")
    except Exception as e:
        print(f"[dial_tls] TCP connect failed: {e}")
        raw.close()
        raise

    def _wrap():
        try:
            raw.setblocking(True)
            print(f"[dial_tls] Starting TLS handshake to {remote}")
            tls_sock = ctx.wrap_socket(raw, do_handshake_on_connect=True)
            print(f"[dial_tls] TLS handshake completed with {remote}")
            tls_sock.setblocking(False)
            return tls_sock
        except Exception as e:
            print(f"[dial_tls] TLS handshake failed: {e}")
            raw.close()
            raise

    try:
        # TLS 也加超时
        return await asyncio.wait_for(loop.run_in_executor(None, _wrap), timeout=timeout)
    except Exception as e:
        print(f"[dial_tls] TLS failed for {remote}: {e}")
        raise