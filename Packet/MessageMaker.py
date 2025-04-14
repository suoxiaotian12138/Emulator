
import random
from os import error
from support_formats import Origin

import numpy as np
import weakref
from Routing.RoutingStrategy import execute_routing_strategy
from tools.sphinxmix import SphinxClient

class Loopix_message_maker():
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None
        self.config_params = loopixnode.config_params
        self.crypto = loopixnode.crypto_node
        self.output_buffer = loopixnode.receiver.output_buffer
        self.routingtable = loopixnode.routingtable
        self.reactor = loopixnode.reactor

        self.count = 1

    def make_stream(self, mode="LOOP", message_function=None, packet_function=None):
        """
        发送消息：
        - mode="real"  发送真实消息
        - mode="loop"  发送Loop消息
        - mode="drop"  发送Drop消息
        """

        loopix_node = self._node_ref()
        if mode == "REAL":
            if not self.output_buffer.empty():
                message,receiver = self.output_buffer.get()
                type_flag = loopix_node.name + str(self.count)

                # receiver = random.choice(self.routingtable["clients"])
                # print(receiver)
                path = self.construct_full_path(receiver)
                header, body = self.crypto.make_sphinx_packet(receiver, path, message, drop_flag=False,type_flag=type_flag,need_surb=True)
                packet = (header, body)
                host = self.routingtable["provider_info"].host
                port = self.routingtable["provider_info"].port
            else:
                mode = "DROP"
                receiver = random.choice(self.routingtable["clients"])
                path = self.construct_full_path(receiver)
                drop_message = self.generate_random_string(self.config_params.NOISE_LENGTH)
                type_flag = loopix_node.name + str(self.count)
                header, body = self.crypto.make_sphinx_packet(receiver, path, drop_message, drop_flag=True,type_flag=type_flag)
                self.count+=1
                packet = (header, body)
                host = path[0].host
                port = path[0].port
            self.schedule_next_task(self.config_params.EXP_PARAMS_LOOPS, lambda: self.make_stream(mode="REAL"))

        elif mode == "LOOP":
            path = self.construct_full_path()
            loop_message = b'HT' + self.generate_random_string(self.config_params.NOISE_LENGTH)
            type_flag = loopix_node.name + str(self.count)

            header, body = self.crypto.make_sphinx_packet(loopix_node, path, loop_message,type_flag=type_flag)
            packet = (header, body)
            host = path[0].host
            port = path[0].port
            self.schedule_next_task(self.config_params.EXP_PARAMS_LOOPS, lambda: self.make_stream(mode="LOOP"))

        else:
            receiver = random.choice(self.routingtable["clients"])
            path = self.construct_full_path(receiver)
            if callable(message_function):
                message = message_function(self)
            else:
                raise ValueError(f"不支持的 mode 类型：{mode}，且 packet_function 未定义。")
            if callable(packet_function):
                custom_arg1 = "数据1"
                custom_arg2 = 42
                packet, host, port = packet_function(self, message, path)
            else:
                raise ValueError(f"不支持的 mode 类型：{mode}，且 packet_function 未定义。")

        print(f"send a {mode} message")
        print(type_flag)
        self.reactor.callLater(0, loopix_node.sender.send, packet, host, port)


    def make_reply_message(self,surb, packet):
        loopix_node = self._node_ref()
        surb_id = surb['id']
        surb_header = surb['header']

        if packet.startswith(b'FILE_START:'):
            file_id = packet[len(b'FILE_START:'):].decode()
            reply_message = b'FILE_START:' + (str(file_id) + "received").encode('utf-8')

        elif packet.startswith(b'FILE_DATA:'):
            _, file_id, seq, data = packet.split(b':', 3)
            file_id = file_id.decode()
            seq = int(seq.decode())
            reply_message = b'FILE_START:' + (str(file_id) + str(seq) + "received").encode('utf-8')

        elif packet.startswith(b'FILE_END:'):
            file_id = packet[len(b'FILE_END:'):].decode()
            reply_message = b'FILE_END:' + (str(file_id) + "received").encode('utf-8')

        # reply_message = "self.generate_random_string(self.config_params.NOISE_LENGTH)"
        # reply_message = reply_message.encode('utf-8') + surb_id

        reply_header, reply_body = SphinxClient.package_surb(loopix_node.sec_params, surb_header, reply_message)
        packet = (reply_header, reply_body)
        print("send a reply message")

        if 'provider_info' in loopix_node.routingtable:
            provider = loopix_node.routingtable['provider_info']
            host=provider.host
            port=provider.port
            loopix_node.sender.send(packet, host, port)
        else:
            raise "node is not a client"

    def generate_dummy_messages(self, num):
        dummy_messages = [('DUMMY', self.generate_random_string(self.config_params.NOISE_LENGTH),
                    self.generate_random_string(self.config_params.NOISE_LENGTH)) for _ in range(num)]
        return dummy_messages

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