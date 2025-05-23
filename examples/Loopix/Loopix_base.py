import os
import numpy as np
import time
import random
import hashlib
import itertools
from urllib.parse import urlparse

import socket
import asyncio

from tools.Log.LogPrinter import LogPrinter
from tools.Packet.packet_UDP import send_udp_async, recv_udp_async, handle_udp, PacketQueue
from tools.Packet.make_packet import make_sphinx_packet, RoutingInfo, make_sphinx_packet_with_surb
from tools.Crypt.key_generator import SECP256R1_setup, sphinx_SECP256R1_setup
from tools.Monitor.LocalMonitor import LocalMonitor


from baselib.sphinxmix.SphinxParams import SphinxParams
from baselib.json_reader import JSONReader


class Loopix_Base():

    def __init__(self, name: str, host: str, port: int):
        self.host = host
        self.port = port
        self.name = name

        self.buffer = PacketQueue()

        self.routing_table = {}
        self.params = self.sphinx_params_set(body_len=2048)
        self.privk, self.pubk = self.key_set(self.params)
        self.config = self.config_set()
        self.socket = self.socket_set(self.host, self.port)
        self.directory_address = self.get_directory_address()
        self.tasks = {}  # save handles

        self.send = send_udp_async
        self.recv = recv_udp_async
        self.put_into_buffer = handle_udp

        # Unified log output format
        printer = LogPrinter(name)
        self.print = printer.print
        self.monitor = LocalMonitor(self.socket)
        self.monitor.disable()


    async def listener(self, sock: socket.socket, interval: float = 0.01):
        """Asynchronously listen to UDP socket and print received messages"""
        while True:
            result = await self.recv(sock)
            if result:
                data, addr = result
                await self.put_into_buffer((data, addr), self.buffer)
            await asyncio.sleep(interval)  # 避免死循环占满 CPU

    @staticmethod
    def config_set(params_type="parametersMixnodes"):
        json_reader = JSONReader(os.path.join(os.path.dirname(__file__), 'config.json'))
        config = json_reader.get_loopix_config_params(params_type)
        return config

    @staticmethod
    def sphinx_params_set(header_len=1024, body_len=1024):
        # The default body length is 1024. If you need to use surb, you need to increase it to 2048.
        return SphinxParams(header_len=header_len, body_len=body_len)

    @staticmethod
    def key_set(params):
        curve, private_key, public_key, generator = sphinx_SECP256R1_setup(params)
        return private_key, public_key

    @staticmethod
    def socket_set(host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        sock.setblocking(False)
        return sock

    async def routing_request(self, interval=1):
        while True:
            message = ["ROUTING", {}]  # Empty dict means request full table
            try:
                # Send to known directory server address
                host, port = self.directory_address  # should be set externally
                await self.send(self.socket, message, host, port)
            except Exception as e:
                self.print(f"[ERROR] Failed to send routing request: {e}")
            await asyncio.sleep(interval)  # 3 minutes interval

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

    @staticmethod
    def group_layered_topology(mixes):
        sorted_mixes = sorted(mixes, key=lambda x: x["group"])

        grouped_mixes = [list(group) for _, group in itertools.groupby(
            sorted_mixes, key=lambda x: x["group"])]

        return grouped_mixes


    def build_routing_info(self, path, trace_id=None, drop_flag=False):
        routing_info = []
        for node in path:
            delay = self.generate_random_delay(self.config.EXP_PARAMS_DELAY)
            extra = [trace_id, drop_flag, delay]
            routing_info.append(RoutingInfo(host=node['host'], port=node['port'], name=node['name'], extra=extra))
        return routing_info


    def generate_trace_id(self) -> str:
        raw = f"{self.name}-{'9999'}-{time.time_ns()}-{random.randint(0, 1 << 16)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]  # 12位16进制

    async def delayed_send(self, packet, host, port, delay: float):
        """Delay execution of send_func(packet, addr) by delay seconds."""
        await asyncio.sleep(delay)
        await self.send(self.socket, packet, host, port)

    async def extra_process(self, flag, decrypted_packet, trace_id, addr):
        if flag == "ROUT":
            event = 'recv'
        else:
            event = 'dest'
        await self.monitor.log_event(trace_id=trace_id, event=event, src=addr)

    @staticmethod
    def take_nodes_keys(nodes):
        return [n.get("pubk", "") for n in nodes]

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
    @staticmethod
    def generate_random_string(length):
        return np.random.bytes(length)

    @staticmethod
    def build_node_info(node):
        node_info = {
            "host": node.host,
            "port": node.port,
            "pubk": node.pubk,
            "name": node.name,
        }
        return node_info

    @staticmethod
    def build_client_info(node):
        node_info = {
            "host": node.host,
            "port": node.port,
            "pubk": node.pubk,
            "name": node.name,
            "provider": node.provider
        }
        return node_info

    async def make_packet(self, message, path):
        trace_id = self.generate_trace_id()
        message = [message, trace_id]
        keys = self.take_nodes_keys(path)
        routing_info = self.build_routing_info(path=path, trace_id=trace_id)
        header, body = make_sphinx_packet(params=self.params, message=message, keys=keys, routing_info=routing_info)
        await self.monitor.log_event(trace_id=trace_id, event="send", dst=(path[0]['host'], path[0]['port']))

        return (header, body)

    async def make_packet_with_surb(self, message, path, surb_path, surbkeys_storage):
        trace_id = self.generate_trace_id()
        message = [message, trace_id]
        keys = self.take_nodes_keys(path)
        routing_info = self.build_routing_info(path=path, trace_id=trace_id)
        surb_trace_id = self.generate_trace_id()
        surb_keys = self.take_nodes_keys(surb_path)
        surb_routing_info = self.build_routing_info(path=surb_path, trace_id=surb_trace_id)
        header, body = make_sphinx_packet_with_surb(self.params, keys, message, routing_info,
                                                    surb_keys, surb_routing_info, surbkeys_storage)
        await self.monitor.log_event(trace_id=trace_id, event="send", dst=(path[0]['host'], path[0]['port']))

        return (header, body)