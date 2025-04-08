
import random
import numpy as np
import weakref
from Routing.RoutingStrategy import execute_routing_strategy


class Loopix_message_maker():
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None
        self.config_params = loopixnode.config_params
        self.crypto = loopixnode.crypto_node
        self.output_buffer = loopixnode.output_buffer
        self.routingtable = loopixnode.routingtable
        self.sender = loopixnode.sender
        self.reactor = loopixnode.reactor


    # def make_real_stream(self):
    #     """发送真实流量或Drop消息"""
    #     if not self.output_buffer.empty():
    #         packet = self.output_buffer.get()
    #         self.sender.send(packet,self.routingtable["provider_info"].host,self.routingtable["provider_info"].port)
    #     else:
    #         self.send_message(mode="drop")
    #
    #     self.schedule_next_task(self.config_params.EXP_PARAMS_PAYLOAD, self.make_real_stream)
    #
    # def make_loop_or_drop_stream(self, mode="loop"):
    #     """循环发送Loop或Drop消息"""
    #     self.send_message(mode=mode)
    #     print(f"send a {mode} message")
    #     delay = self.config_params.EXP_PARAMS_LOOPS if mode == "loop" else self.config_params.EXP_PARAMS_DROP
    #     self.schedule_next_task(delay, lambda: self.make_loop_or_drop_stream(mode))

    def make_stream(self, mode="DROP", message_function=None, packet_function=None):
        """
        发送消息：
        - mode="real"  发送真实消息
        - mode="loop"  发送Loop消息
        - mode="drop"  发送Drop消息
        """

        loopix_node = self._node_ref()
        if mode == "REAL":
            if not self.output_buffer.empty():
                print(1)
                packet = self.output_buffer.get()
                host = self.routingtable["provider_info"].host
                port = self.routingtable["provider_info"].port
            else:
                print(2)
                receiver = random.choice(self.routingtable["clients"])
                path = self.construct_full_path(receiver, group=loopix_node.group)
                print(len(path))
                drop_message = self.generate_random_string(self.config_params.NOISE_LENGTH)
                header, body = self.crypto.make_sphinx_packet(receiver, path, drop_message, drop_flag=True)
                packet = (header, body)
                host = path[0].host
                port = path[0].port

        elif mode == "LOOP":
            path = self.construct_full_path(group=loopix_node.group)
            loop_message = b'HT' + self.generate_random_string(self.config_params.NOISE_LENGTH)
            header, body = self.crypto.make_sphinx_packet(loopix_node, path, loop_message,type_flag="slslsls")
            packet = (header, body)
            host = path[0].host
            port = path[0].port
        elif mode == "DROP":
            receiver = random.choice(self.routingtable["clients"])
            path = self.construct_full_path(receiver, group=loopix_node.group)
            drop_message = self.generate_random_string(self.config_params.NOISE_LENGTH)
            header, body = self.crypto.make_sphinx_packet(receiver, path, drop_message, drop_flag=True)
            packet = (header, body)
            host = path[0].host
            port = path[0].port
        else:
            receiver = random.choice(self.routingtable["clients"])
            path = self.construct_full_path(receiver, group=loopix_node.group)
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
        loopix_node.sender.send(packet, host, port)
        self.schedule_next_task(self.config_params.EXP_PARAMS_LOOPS, self.make_stream)


    def generate_dummy_messages(self, num):
        dummy_messages = [('DUMMY', self.generate_random_string(self.config_params.NOISE_LENGTH),
                    self.generate_random_string(self.config_params.NOISE_LENGTH)) for _ in range(num)]
        return dummy_messages

    @staticmethod
    def generate_random_string(length):
        return np.random.bytes(length)

    def construct_full_path(self, receiver=None, group=0):
        """构造完整路径"""
        #后续可能会修改loop message的路径生成逻辑
        loopix_node = self._node_ref()
        mix_chain = execute_routing_strategy("Loopix",self.routingtable["mixnodes"],group)
        if receiver is not None:
            return [self.routingtable["provider_info"]] + mix_chain + [receiver.provider] + [receiver]
        else:
            return mix_chain + [random.choice(self.routingtable["providers"])]


    def schedule_next_task(self, delay_param, method):
        """通用的定时任务调度"""
        print(f"Scheduling next task with delay {delay_param}")
        interval = self.sample_from_exponential(delay_param)
        self.reactor.callLater(interval, method)

    def sample_from_exponential(self, lambda_param):
        interval = np.random.exponential(lambda_param)
        print(f"Sampled delay interval: {interval}")
        return interval