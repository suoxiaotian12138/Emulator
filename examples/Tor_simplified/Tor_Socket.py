import asyncio
import socket
import ssl
import struct
import time
from pathlib import Path
from typing import Optional, Callable, Awaitable

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from torpy.cell_socket import TorProtocol
from torpy.cells import CellVersions, CellNetInfo

from tools.Packet.packet_TCP import send_tcp, ByteBuffer, monitor_connection_tls


from examples.Tor_simplified.Tor_Cell import TorCell, CellCerts, CellAuthChallenge, TorCommands
from examples.Tor_simplified.Tor_Router import logger


class Tor_Socket():
    def __init__(self, on_cell=None, sock=None):
        self.protocal = TorProtocol()
        self.socket = sock
        self._send_lock = asyncio.Lock()
        self.handshake = TorHandshake(socket)
        self.send = send_tcp
        self.print = print
        self.buffer = ByteBuffer()
        self.on_cell: Optional[Callable[[TorCell, Tor_Socket], Awaitable[None]]] = on_cell
        self.handshake_initiator = False

    async def setup_socket(self, remote_addr, sock=None):
        if sock is None:
            self.handshake_initiator = True
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            await loop.sock_connect(sock, remote_addr)

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            def tls_wrap():
                # 握手期间 socket 必须阻塞！
                sock.setblocking(True)
                ssl_sock = ctx.wrap_socket(sock, server_hostname=None, do_handshake_on_connect=True)
                ssl_sock.setblocking(False)  # 握手后恢复非阻塞（可选）
                return ssl_sock

            sock = await loop.run_in_executor(None, tls_wrap)
        print("create socket successfully")
        self.socket = sock

    async def tor_handshake_client(self):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        net_info_cell = await self.handshake.make_net_info(self.socket.getsockname(), self.socket.getpeername())
        await self.send_cell(net_info_cell)

    async def tor_handshake_server(self, cell: CellVersions, certs_path):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)
        self.protocal.version = self.handshake.retrieve_versions(cell)
        certs = load_cert_for_cellcerts(certs_path)
        certs_cell = CellCerts([(3, certs)])
        await self.send_cell(certs_cell)
        auth_cell = CellAuthChallenge()        # For simplicity, no verification is performed at this time

        await self.send_cell(auth_cell)

        net_info_cell = await self.handshake.make_net_info(self.socket.getsockname(), self.socket.getpeername())
        await self.send_cell(net_info_cell)

    async def start_listen(self) -> asyncio.Task:
        """
        启动监听、处理、监控三大任务，并返回生命周期句柄 task。
        """
        loop = asyncio.get_running_loop()
        # 启动监听和处理任务
        self._recv_task = loop.create_task(
            monitor_connection_tls(
                conn=self.socket,
                addr=self.socket.getpeername(),
                buffer=self.buffer
            )
        )
        self._process_task = loop.create_task(self.process())
        self._handle_task = loop.create_task(self.monitor_handle())
        return self._handle_task  # ⬅ 上层 await 这个任务就可以知道连接是否中断



    async def monitor_handle(self):
        """
        监控监听与处理任务是否异常退出，一旦断开连接自动清理资源。
        """
        try:
            # 监听与处理任务哪个先崩就触发
            done, pending = await asyncio.wait(
                [self._recv_task, self._process_task],
                return_when=asyncio.FIRST_COMPLETED,
            )
        finally:
            # 一旦任何任务崩溃或断开，就关闭 socket 并取消另一个任务
            self._recv_task.cancel()
            self._process_task.cancel()

            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.socket.close()

            self.print(f"[Tor_Socket] Connection closed: {self.socket.getpeername()}")

    async def process(self):
        """主处理循环"""
        while True:
            try:
                cell = await self.recv_and_parse_cell()
                if not cell:
                    continue
                await self.on_cell(cell, self)
            except Exception as e:
                self.print(f"Cell parse error: {e}")

    async def send_cells(self, cells):
        for cell in cells:
            print("send cell_type:", type(cell))
            print("send cell:", cell)
            cell = self.protocal.serialize(cell)
            async with self._send_lock:
                try:
                    await self.send(self.socket, cell)
                except OSError as e:
                    print(f"[Error] Socket send failed: {e}")

    async def send_cell(self, cell):
        print("send cell_type:", type(cell))
        print("send cell:", cell)
        buffer = self.protocal.serialize(cell)
        async with self._send_lock:
            try:
                await self.send(self.socket, buffer)
            except OSError as e:
                print(f"[Error] Socket send failed: {e}")

    async def recv_and_parse_cell(self):
        """
        一次性完成cell的接收和解析，避免重复工作
        """
        try:
            # Step 1: 读取并解析header
            header_info = await self._recv_header()
            if not header_info:
                return None

            circuit_id, command_num, cell_type = header_info

            # Step 2: 根据类型读取payload
            if cell_type.is_var_len():
                payload_len = await self._recv_var_length()
                if payload_len is None:
                    return None
            else:
                payload_len = TorCell.MAX_PAYLOAD_SIZE


            # Step 3: 读取payload
            payload = await self._recv_payload(payload_len)
            if payload is None:
                return None

            # Step 4: 直接构造并返回cell对象
            cell = self.protocal.deserialize(cell_type, payload, circuit_id)
            print("return cell successfully")
            return cell

        except struct.error as e:
            self.print(f"Struct unpacking error: {e}")
            return None
        except Exception as e:
            self.print(f"Cell reception error: {e}")
            return None

    async def _recv_header(self):
        """接收并解析cell header"""
        header_size = struct.calcsize(self.protocal.header_format)
        header = await self.buffer.extract_by_size(header_size)
        if not header:
            return None

        try:
            circuit_id, command_num = struct.unpack(self.protocal.header_format, header)
            cell_type = TorCommands.get_by_num(command_num)
            if not cell_type:
                raise ValueError(f"Unknown command number: {command_num}")
            return circuit_id, command_num, cell_type
        except (struct.error, ValueError) as e:
            self.print(f"Header parsing error: {e}")
            return None

    async def _recv_var_length(self):
        """接收变长cell的长度字段"""
        len_size = struct.calcsize(self.protocal.length_format)
        len_bytes = await self.buffer.extract_by_size(len_size)
        if not len_bytes:
            return None

        try:
            (payload_len,) = struct.unpack(self.protocal.length_format, len_bytes)
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


class TorHandshake:
    def __init__(self, tor_socket, tor_protocol=TorProtocol):
        self.tor_socket = tor_socket
        self.tor_protocol = tor_protocol
        self.version_event = self._make_new_event()

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

    def retrieve_certs(self, cell_certs):
        logger.debug('Retrieving AUTH_CHALLENGE cell...')

    def retrieve_net_info(self, cell):
        logger.debug('Retrieving NET_INFO cell...')


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
