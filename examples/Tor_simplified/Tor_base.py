import os

from urllib.parse import urlparse
from typing import Literal

import socket
import asyncio
from typing import Optional
from tools.Network_Management.tls_registry import (
    register_server_ctx,
)

from tools.Log.LogPrinter import LogPrinter
from tools.Log.bus import EventBus, NoOpBus, GlobalBus
from tools.Packet.packet_TCP import accept_tls_connections, TLSConnector
from tools.Crypt.key_generator import create_server_context, ed25519_setup, rsa_setup, generate_cert_and_key_from_ed25519, generate_tls_rsa_cert

from examples.Tor_simplified.Tor_Socket import Tor_Socket
from tools.Network_Management.delay_env import get_args

class Tor_base:

    def __init__(self, name: str, host: str, port: int, model: Literal["sim", "real"] = "sim", sim_ip: str | None = None):

        self.host = host
        self.port = port
        self.name = name
        self.addr = (host, port)

        self.lock = asyncio.Lock()
        self.routing_table = {}

        self.socket = self.socket_recv_set(self.host, self.port)   # Used to accept socket connections,not to send or receive data directly.
        self.socket_map = {}   # dict[Tuple[str, int], socket.socket]
        self.dire_ip, self.dire_port = self.get_directory_address()
        self.model = model
        self.tasks = {}  # save handles
        self.running = True
        self.node_id = f"{self.name}@{self.host}:{self.port}"

        self.tls_privt, self.tls_pubk = ed25519_setup()
        self.rsa_pvk, _ = rsa_setup()
        self.rsa_tls_pvk, self.rsa_tls_puk = rsa_setup()

        self.cert_file, self.key_file = generate_tls_rsa_cert(self.rsa_tls_pvk)
        register_server_ctx(self.node_id, self.cert_file, self.key_file)

        # self.context = create_server_context(self.cert_file, self.key_file)
        self.listener_ready = asyncio.Event()
        self.tls_connector = TLSConnector(
            certfile=self.cert_file,  # self.cert_file
            keyfile=self.key_file,  # self.key_file
            max_concurrent_tls=2000,  # 服务端并发TLS握手限制
            handshake_timeout=15.0  # 适当的握手超时
        )

        # Unified log output format
        printer = LogPrinter(name)
        self.print = printer.print

        # 默认给 NoOpBus，确保永不为 None（零侵入调用）
        self.event_bus: EventBus | NoOpBus = NoOpBus()
        # 绑定常用方法引用，减少属性查找开销（微优化）
        self._ev = self.event_bus.ev
        self._circuit = self.event_bus.circuit
        self._path = self.event_bus.path
        self._stream = self.event_bus.stream

        self.sim_ip = sim_ip
    def attach_bus(self, bus: Optional[EventBus]):
        """在启动脚本里调用；忘记传就用全局默认。"""
        self.event_bus = bus
        # 重新绑定快捷引用（避免每次 getattr）
        self._ev = bus.ev
        self._circuit = bus.circuit
        self._path = bus.path
        self._stream = bus.stream


    def sign_message(self, private_key, message):
        signature = private_key.sign(message)
        return signature

    def verify_sign(self, public_key, message, signature):
        public_key.verify(signature, message)

    @staticmethod
    def socket_recv_set(host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(2048)  # backlog >= max_concurrent_tls
        sock.setblocking(False)
        return sock

    @staticmethod
    def get_directory_address(default=None):
        addr = os.environ.get('DIRECTORY_ADDR', default)
        if not addr:
            return None  # ✅ 改为返回 None 而不是抛错

        if "://" not in addr:
            addr = "http://" + addr

        parsed = urlparse(addr)
        host = parsed.hostname
        port = parsed.port

        if host is None or port is None:
            raise ValueError(f"Invalid DIRECTORY_ADDR format: {addr}")

        return (host, port)

    # examples/Tor_simplified/Tor_base.py

    from tools.Network_Management.delay_env import get_args  # 顶部已有就不用再加

    async def monitor_tor_socket(self):
        def on_accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            tor_sock = Tor_Socket(
                reader=reader,
                writer=writer,
                source_ip=self.host,
                on_cell=self.handle_cell,
                node_id=self.node_id,
                **get_args(sim_ip=self.sim_ip)
            )
            asyncio.create_task(tor_sock.start_listen())

        self.print(f"[LISTEN] Node {self.name} listening on {self.host}:{self.port}")
        await accept_tls_connections(
            self.socket,
            self.tls_connector,
            on_accept,
            node_id=self.node_id,
            on_server_ready=self.listener_ready.set
        )

    async def handle_connection(self, addr, tor_sock):
        try:
            self.socket_map[addr] = tor_sock
            # 等待streams设置完成
            while tor_sock.reader is None or tor_sock.writer is None:
                if tor_sock._closing.is_set():
                    return
                await asyncio.sleep(0.01)

            handle = await tor_sock.start_listen()
            await handle
        finally:
            self.socket_map.pop(addr, None)
            self.print(f"[AsyncMonitor] Connection {addr} closed and removed from map.")

    def handle_cell(self, cell, sock):
        pass

    async def stop_protocol(self):
        """停止所有任务"""
        self.running = False
        for task in self.tasks.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)


