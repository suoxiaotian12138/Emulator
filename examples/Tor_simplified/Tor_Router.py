from torpy.crypto_common import b64decode
from torpy.keyagreement import NtorKeyAgreement
from torpy.crypto_state import CryptoState
from torpy.consesus import Descriptor
from torpy.parsers import RouterDescriptorParser
from torpy.cells import TorCell, CellCerts, CellNetInfo, TorCommands, CellVersions, CellAuthChallenge
import time
from torpy.cell_socket import TorProtocol
import asyncio
import logging
from torpy.stream import TorWindow
logger = logging.getLogger(__name__)

class Tor_Router:
    def __init__(self, router: dict):
        self.nickname = router['nickname']

        fingerprint = router['fingerprint']
        self.fingerprint_str = fingerprint
        if type(fingerprint) is not bytes:
            fingerprint = b64decode(fingerprint)
        self.fingerprint = fingerprint
        self.digest = b64decode(router['digest']) if router['digest'] else None
        self.ip = router['ip']
        self.or_port = router['or_port']
        self.addr = (self.ip, self.or_port)
        self.dir_port = router['dir_port']
        self.version = router['version']
        self.flags = router['flags']

        self.window = TorWindow()
        self._consensus = None
        self._service_key = None

        self.key_agreement_cls = NtorKeyAgreement(self)
        self._crypto_state = None
        self.descriptor_str = None
    def create_onion_skin(self):
        return self.key_agreement_cls.handshake

    def complete_handshake(self, handshake_response):
        shared_secret = self.key_agreement_cls.complete_handshake(handshake_response)
        self._crypto_state = CryptoState(shared_secret)

    def encrypt_forward(self, relay_cell):
        self._crypto_state.encrypt_forward(relay_cell)

    def decrypt_backward(self, relay_cell):
        self._crypto_state.decrypt_backward(relay_cell)
        self.key_agreement_cls = NtorKeyAgreement(self)

    @property
    def descriptor(self):

        descriptor_info = RouterDescriptorParser.parse(self.descriptor_str)
        return Descriptor(**descriptor_info)

    def set_descriptor(self, descriptor_str):
        self.descriptor_str = descriptor_str



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



import ssl
import socket
import struct
from tools.Packet.packet_TCP import send_tcp, recv_tcp, ByteBuffer, handle_tcp, monitor_connection_tls
from typing import Optional, Tuple, Callable, Awaitable


class Tor_Socket():
    def __init__(self, remote_addr, on_cell=None, sock=None):
        self.protocal = TorProtocol()
        self.socket = self.create_socket(remote_addr, sock)
        self._send_lock = asyncio.Lock()
        self.handshake = TorHandshake(socket)
        self.send = send_tcp
        self.print = print
        self.buffer = ByteBuffer()
        self.on_cell: Optional[Callable[[TorCell], Awaitable[None]]] = on_cell


    def create_socket(self, remote_addr, sock=None):
        if sock is None:
            sock = ssl.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_TLSv1_2
            )
            sock.connect(remote_addr)
        return sock

    async def tor_handshake(self):
        version_cell = self.handshake.make_versions()
        await self.send_cell(version_cell)

        # await self.handshake.retrieve_certs()
        # await self.handshake.retrieve_net_info()

        net_info_cell = await self.handshake.make_net_info(self.socket.getsockname(), self.socket.getpeername())
        await self.send_cell(net_info_cell)

    async def start_all(self) -> asyncio.Task:
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

        await self.tor_handshake()
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
                print("cell content:", cell)
                if not cell:
                    continue
                await self.handle_cell_router(cell)
            except Exception as e:
                self.print(f"Cell parse error: {e}")

    async def handle_cell_router(self, cell):
        if isinstance(cell, CellVersions):
            self.protocal.version = self.handshake.retrieve_versions(cell)
        elif isinstance(cell, CellCerts):
            self.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellAuthChallenge):
            self.handshake.retrieve_certs(cell)
        elif isinstance(cell, CellNetInfo):
            self.handshake.retrieve_net_info(cell)
        else:
            self.print("client cell_type:", type(cell))
            await self.on_cell(cell)

    async def send_cells(self, cells):
        for cell in cells:
            print("send cell_type:", type(cell))
            print("send cell:",cell)
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
        print("size of cell", len(buffer))
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
            print("command num：", command_num)
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

from torpy.http.client import recv_all