

from support_formats import Origin
import json

import hashlib
import time
import random
import numpy as np
import weakref
from Routing.RoutingStrategy import execute_routing_strategy
from tools.sphinxmix import SphinxClient

class Loopix_message_maker():
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None
        self.crypto = loopixnode.crypto_node
        self.config_params = loopixnode.config_params
        self.output_buffer = loopixnode.receiver.output_buffer
        self.routingtable = loopixnode.routingtable
        self.reactor = loopixnode.reactor
        self.name = loopixnode.name
        self.count = 1

    def make_stream(self, mode="LOOP", **kwargs):
        loopix_node = self._node_ref()
        trace_id = self.generate_trace_id()
        info = {}
        delay = 0
        event = "send"
        if mode == "REAL":
            if not self.output_buffer.empty():
                message, receiver = self.output_buffer.get()
                path = self.construct_full_path(receiver)
                surb_trace_id = self.generate_trace_id()
                header, body = self.crypto.make_sphinx_packet(receiver, path, message, trace_id=trace_id,
                                                              need_surb=True, surb_trace_id=surb_trace_id)

                packet = (header, body)
                host = self.routingtable["provider_info"].host
                port = self.routingtable["provider_info"].port
            else:
                mode = "DROP"
                receiver = random.choice(self.routingtable["clients"])
                path = self.construct_full_path(receiver)
                drop_message = self.generate_random_string(self.config_params.NOISE_LENGTH)
                header, body = self.crypto.make_sphinx_packet(receiver, path, drop_message, drop_flag=False,
                                                              trace_id=trace_id)


                packet = (header, body)
                host = path[0].host
                port = path[0].port

            # self.schedule_next_task(self.config_params.EXP_PARAMS_LOOPS, lambda: self.make_stream(mode="REAL"))

        elif mode == "LOOP":
            path = self.construct_full_path()
            loop_message = b'HT' + self.generate_random_string(self.config_params.NOISE_LENGTH)
            header, body = self.crypto.make_sphinx_packet(loopix_node, path, loop_message, trace_id=trace_id)
            packet = (header, body)
            host = path[0].host
            port = path[0].port

            self.schedule_next_task(self.config_params.EXP_PARAMS_LOOPS, lambda: self.make_stream(mode="LOOP"))

        elif mode == "REPLY":
            surb = kwargs.get('surb')
            message = kwargs.get('message')
            if surb is None or message is None:
                raise ValueError("REPLY mode requires surb and message")

            surb_id = surb['id']
            surb_header = surb['header']

            raw_data = surb_header[0]
            routing_info = json.loads(raw_data.decode('utf-8'))
            trace_id = routing_info[1][2]
            info = {"surb_id": surb_id}

            # 构造回复内容
            reply_message = self.generate_reply_message(message)

            reply_header, reply_body = SphinxClient.package_surb(loopix_node.sec_params, surb_header, reply_message)
            packet = (reply_header, reply_body)

            host = self.routingtable["provider_info"].host
            port = self.routingtable["provider_info"].port
        elif mode == "FORWARD":
            event = "forward"
            header, body = kwargs.get('packet')
            host,port = kwargs.get('addr')
            delay = kwargs.get('delay')
            trace_id = kwargs.get('traceid')
            packet = (header, body)

        else:  # 其他情况
            message_function = kwargs.get('message_function')
            packet_function = kwargs.get('packet_function')
            receiver = random.choice(self.routingtable["clients"])
            path = self.construct_full_path(receiver)

            if callable(message_function):
                message = message_function(self)
            else:
                raise ValueError(f"不支持的 mode 类型：{mode}，且 packet_function 未定义。")

            if callable(packet_function):
                packet, host, port = packet_function(self, message, path)
            else:
                raise ValueError(f"不支持的 mode 类型：{mode}，且 packet_function 未定义。")



        self.reactor.callLater(delay, loopix_node.sender.send, packet, host, port)
        loopix_node.monitor.log_event(
            trace_id=trace_id,
            event=event,
            dst=(host, port),
            info=info
        )
        print(f"send a {mode} message")

    @staticmethod
    def generate_reply_message(message):

        if message.startswith(b'FILE_START:'):
            file_id = message[len(b'FILE_START:'):].decode()
            reply_message = b'FILE_START:' + (str(file_id) + "received").encode('utf-8')
        elif message.startswith(b'FILE_DATA:'):
            _, file_id, seq, data = message.split(b':', 3)
            file_id = file_id.decode()
            seq = int(seq.decode())
            reply_message = b'FILE_START:' + (str(file_id) + str(seq) + "received").encode('utf-8')
        elif message.startswith(b'FILE_END:'):
            file_id = message[len(b'FILE_END:'):].decode()
            reply_message = b'FILE_END:' + (str(file_id) + "received").encode('utf-8')
        else:
            reply_message = b'received'

        return reply_message



    def generate_dummy_messages(self, num):
        dummy_messages = [('DUMMY', self.generate_random_string(self.config_params.NOISE_LENGTH),
                    self.generate_random_string(self.config_params.NOISE_LENGTH)) for _ in range(num)]
        return dummy_messages


    def generate_trace_id(self) -> str:
        """
        node_name: 当前节点名称或ID
        counter: 本地递增计数（确保唯一）
        """
        raw = f"{self.name}-{self.count}-{time.time_ns()}-{random.randint(0, 1 << 32)}"
        self.count += 1
        return hashlib.sha256(raw.encode()).hexdigest()[:12]  # 12位16进制

    @staticmethod
    def generate_random_string(length):
        return np.random.bytes(length)

    def construct_full_path(self, receiver=None):
        """构造完整路径"""
        #后续可能会修改loop message的路径生成逻辑
        loopix_node = self._node_ref()
        group = loopix_node.group
        mix_chain = execute_routing_strategy("Loopix",self.routingtable["mixnodes"],group)

        if receiver is not None:
            return [self.routingtable["provider_info"]] + mix_chain + [receiver.provider] + [receiver]
        else:
            Zero_hop = Origin(loopix_node.name, loopix_node.port, loopix_node.host, loopix_node.pubk)

            return mix_chain + [random.choice(self.routingtable["providers"])] + [Zero_hop]


    def schedule_next_task(self, delay_param, method):
        """通用的定时任务调度"""
        interval = self.sample_from_exponential(delay_param)
        self.reactor.callLater(interval, method)

    def sample_from_exponential(self, lambda_param):
        interval = np.random.exponential(lambda_param)
        return interval