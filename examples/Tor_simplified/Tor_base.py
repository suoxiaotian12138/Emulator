import os
import ssl
import numpy as np
import time
import random
import hashlib
import itertools
from urllib.parse import urlparse

import socket
import asyncio

from tools.Log.LogPrinter import LogPrinter
from tools.Packet.packet_TCP import send_tcp, listen_to_tls, ByteBuffer, handle_tcp,listen_to_tcp
from tools.Crypt.key_generator import generate_cert_and_key_from_ed25519, create_server_context, ed25519_setup
from tools.Monitor.LocalMonitor import LocalMonitor
from torpy.cells import TorCell

from baselib.json_reader import JSONReader



class Tor_base:
    def __init__(self, name: str, host: str, port: int):
        self.version = 4

        self.host = host
        self.port = port
        self.name = name
        self.addr = (host, port)

        self.buffer = ByteBuffer()
        self.lock = asyncio.Lock()
        self.routing_table = {}

        # self.config = self.config_set()
        self.socket = self.socket_recv_set(self.host, self.port)   # Used to accept socket connections,not to send or receive data directly.
        self.socket_map = {}   # dict[Tuple[str, int], socket.socket]
        self.directory_address = self.get_directory_address()
        self.tasks = {}  # save handles

        self.tls_privt, self.tls_pubk = ed25519_setup()
        self.cert_file, self.key_file = generate_cert_and_key_from_ed25519(self.tls_privt)
        self.context = create_server_context(self.cert_file, self.key_file)

        self.send = send_tcp
        self.put_into_buffer = handle_tcp

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
        sock.listen()
        return sock

    def create_tls_connection(self, local_addr=None, remote_addr=None):
        if remote_addr is None:
            raise ValueError("remote_addr must be specified")
        context = ssl.create_default_context()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if local_addr is not None:
            sock.bind(local_addr)
        server_hostname = remote_addr[0]
        sock = context.wrap_socket(sock, server_hostname=server_hostname)
        self.socket_map[remote_addr] = sock
        self.tor_handshake(sock)
        return sock

    def tor_handshake(self, socket):
        from torpy.cell_socket import TorHandshake, TorProtocol
        protocal = TorProtocol()
        handshake = TorHandshake(socket, protocal)
        handshake.initiate()

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

    async def listener(self):
        """将您的listen_to_tcp包装成一个任务"""
        await listen_to_tls(
            listener_socket=self.socket,
            connection_map=self.socket_map,
            lock=self.lock,
            buffer=self.buffer,
            ssl_context=self.context,
            handler=self.put_into_buffer,

        )

    async def stop_protocol(self):
        """停止所有任务，包括TCP服务器"""
        self.running = False
        for task in self.tasks.values():
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks.values(), return_exceptions=True)

    @property
    def header_format(self):
        #    CircuitID                          [CIRCUIT_ID_LEN octets]
        #    Command                            [1 byte]
        if self.version < 4:
            return '!HB'
        else:
            # Link protocol 4 increases circuit ID width to 4 bytes.
            return '!IB'

    def deserialize(self, command, payload, circuit_id=0):
        # parse depending on version
        # ...
        return TorCell.deserialize(command, circuit_id, payload, self.version)

    def serialize(self, cell):
        # get bytes depending on version
        # ...
        return cell.serialize(self.version)


