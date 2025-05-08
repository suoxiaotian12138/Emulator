import os
import numpy as np
import time
import random
import hashlib
from urllib.parse import urlparse

import socket
import asyncio
from tools.Packet.packet_UDP import send_udp, recv_udp, handle_udp, PacketQueue
from tools.Crypt.key_generator import SECP256R1_setup
from tools.Packet.make_packet import make_sphinx_packet, RoutingInfo

from baselib.sphinxmix.SphinxParams import SphinxParams
from baselib.json_reader import JSONReader


class Loopix_Base():

    def __init__(self, name: str, host: str, port: int):
        self.host = host
        self.port = port
        self.name = name

        self.directory_address = self.get_directory_address()

        self.buffer = PacketQueue()

        self.privk, self.pubk = self.key_set()
        self.config = self.config_set()
        self.params = self.sphinx_params_set()
        self.socket = self.socket_set(self.host, self.port)
        self.tasks = {}  # save handles

        self.send = send_udp
        self.recv = recv_udp
        self.put_into_buffer = handle_udp

    @staticmethod
    def config_set(params_type="parametersMixnodes"):
        json_reader = JSONReader(os.path.join(os.path.dirname(__file__), 'config.json'))
        config = json_reader.get_loopix_config_params(params_type)
        return config

    @staticmethod
    def sphinx_params_set(header_len=1024, body_len=1024):
        return SphinxParams(header_len=header_len, body_len=body_len)

    @staticmethod
    def key_set():
        curve, private_key, public_key, generator = SECP256R1_setup()
        return private_key, public_key

    @staticmethod
    def socket_set(host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.setblocking(False)
        return sock

    @staticmethod
    def get_directory_address():
        addr = os.environ.get('DIRECTORY_ADDR')
        if not addr:
            raise EnvironmentError("Missing DIRECTORY_ADDR environment variable.")

        # Add scheme if missing (so urlparse works correctly)
        if "://" not in addr:
            addr = "http://" + addr
        parsed = urlparse(addr)
        host = parsed.hostname
        port = parsed.port

        if host is None or port is None:
            raise ValueError(f"Invalid DIRECTORY_ADDR format: {addr}")

        return (host, port)

    async def listener(self, sock: socket.socket, interval: float = 0.01):
        """Asynchronously listen to UDP socket and print received messages"""
        loop = asyncio.get_running_loop()
        while True:
            result = await loop.run_in_executor(None, self.recv, sock)
            if result:
                data, addr = result
                self.put_into_buffer((data, addr), self.buffer)
            await asyncio.sleep(interval)  # 避免死循环占满 CPU

    def build_routing_info(self, path, trace_id=None, drop_flag=False):
        routing_info = []
        for node in path:
            delay = self.generate_random_delay(self.config.EXP_PARAMS_DELAY)
            extra = {'trace_id': trace_id, 'drop_flag': drop_flag, 'delay': delay}
            routing_info.append(RoutingInfo(host=node.host, port=node.port, name=node.name, extra=extra))
        return routing_info

    def construct_full_path_loop(self, receiver=None):
        """构造完整路径"""
        # 后续可能会修改loop message的路径生成逻辑
        group = self.group
        path = []
        num_all_layers = len(self.routing_table['mixnode'])
        layer = self.group + 1
        while layer != self.group:
            mix = random.choice(self.routing_table['mixnode'][layer % num_all_layers])
            path.append(mix)
            layer = (layer + 1) % num_all_layers
        path.insert(num_all_layers - 1 - self.group, random.choice(self.routing_table['mixnode']))

        return path

    def generate_trace_id(self) -> str:
        raw = f"{self.name}-{'9999'}-{time.time_ns()}-{random.randint(0, 1 << 16)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]  # 12位16进制

    async def delayed_send(self, packet, host, port, delay: float):
        """Delay execution of send_func(packet, addr) by delay seconds."""
        await asyncio.sleep(delay)
        await self.send(self.socket, packet, host, port)

    @staticmethod
    def take_nodes_keys(nodes):
        return [n.pubk for n in nodes]

    @staticmethod
    def generate_random_delay(delay_param):
        if float(delay_param) == 0.0:
            return 0.0
        else:
            return np.random.exponential(delay_param, size=None)

    def generate_dummy_messages(self, num):
        dummy_messages = [('DUMMY', self.generate_random_string(self.config.NOISE_LENGTH),
                           self.generate_random_string(self.config.NOISE_LENGTH)) for _ in range(num)]
        return dummy_messages

    def generate_random_string(self, length):
        return np.random.bytes(length)
