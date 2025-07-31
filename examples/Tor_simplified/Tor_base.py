import os

from urllib.parse import urlparse
from typing import Literal

import socket
import asyncio

from tools.Log.LogPrinter import LogPrinter
from tools.Packet.packet_TCP import accept_tls_connections, TLSConnector
from tools.Crypt.key_generator import create_server_context, ed25519_setup, rsa_setup, generate_cert_and_key_from_ed25519, generate_tls_rsa_cert

from examples.Tor_simplified.Tor_Socket import Tor_Socket


class Tor_base:

    def __init__(self, name: str, host: str, port: int, model: Literal["sim", "real"] = "sim"):

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

        self.tls_privt, self.tls_pubk = ed25519_setup()
        self.rsa_pvk, _ = rsa_setup()
        self.rsa_tls_pvk, self.rsa_tls_puk = rsa_setup()

        self.cert_file, self.key_file = generate_tls_rsa_cert(self.rsa_tls_pvk)
        self.context = create_server_context(self.cert_file, self.key_file)
        self.tls_connector = TLSConnector(certfile=self.cert_file, keyfile=self.key_file)

        # Unified log output format
        printer = LogPrinter(name)

        self.print = printer.print


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
        sock.listen(512)
        sock.setblocking(False)  # ★ 关键：非阻塞，供 loop.sock_accept 使用
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

    async def monitor_tor_socket(self):
        """
        持续监听 TLS 连接；握手一成功就启动 Tor_Socket.listen()
        """

        def on_accept(tls_sock, addr):
            self.print("accept a new socket from:", addr)
            tor_sock = Tor_Socket(source_ip=self.host, sock=tls_sock, on_cell=self.handle_cell)
            asyncio.create_task(self.handle_connection(addr, tor_sock))

        await accept_tls_connections(self.socket, self.tls_connector, on_accept)

    async def handle_connection(self, addr, tor_sock):
        try:
            self.socket_map[addr] = tor_sock
            handle = await tor_sock.start_listen()  # 返回 monitor_handle task
            await handle  # 等连接断开
        finally:
            self.socket_map.pop(addr, None)
            self.print(f"[Monitor] Connection {addr} closed and removed from map.")

    def handle_cell(self, cell, sock):
        pass

    async def stop_protocol(self):
        """停止所有任务，包括TCP服务器"""
        self.running = False
        for task in self.tasks.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)


