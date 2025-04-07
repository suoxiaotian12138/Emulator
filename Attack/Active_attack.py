
import random
import numpy as np
from functools import wraps
from Routing.RoutingStrategy import execute_routing_strategy
from tools.Serialization import encode,decode
from twisted.internet import reactor, task, abstract

class Flooding_attack():
    def __init__(self, loopixnode):
        self.loopix_node = loopixnode
        self.config_params = loopixnode.config_params
        self.crypto = loopixnode.crypto_node
        self.output_buffer = loopixnode.output_buffer
        self.routingtable = loopixnode.routingtable
        self.reactor = loopixnode.reactor

    @staticmethod
    def generate_random_string(length):
        return np.random.bytes(length)

    def schedule_next_task(self, delay_param, method):
        """通用的定时任务调度"""
        interval = self.sample_from_exponential(delay_param)
        self.reactor.callLater(interval, method)

    @staticmethod
    def sample_from_exponential(lambda_param):
        return np.random.exponential(lambda_param, size=None)

    def make_attack_stream(self, mode="flooding"):
        """快速发送大量数据包"""
        self.send_message(mode=mode)
        print(f"send a {mode} message")
        delay = "0.001"
        self.schedule_next_task(delay, lambda: self.make_attack_stream(mode))

    def send_message(self, message=None, receiver=None, mode="real"):
        receiver = random.choice(self.routingtable["clients"])

        path = self.construct_full_path(receiver)
        loop_message = b'HT' + self.generate_random_string(self.config_params.NOISE_LENGTH)
        header, body = self.crypto.make_sphinx_packet(receiver, path, loop_message)
        host = path[0].host
        port = path[0].port

        self.loopix_node.sender.send((header, body), host, port)

    def construct_full_path(self, receiver=None):
        """构造完整路径"""
        mix_chain = execute_routing_strategy("Loopix", self.routingtable["mixnodes"])
        if self.loopix_node.type == 'client':
            return [self.routingtable["provider_info"]] + mix_chain + [receiver.provider] + [receiver]
        else:
            return mix_chain + [receiver.provider] + [receiver]

class Creeping_death():

    #仅适用于provider和mixnode节点
    def __init__(self, loopixnode, node_list=None, drop_probability=1.0):

        self.loopix_node = loopixnode
        self.config_params = loopixnode.config_params
        self.crypto = loopixnode.crypto_node
        self.output_buffer = loopixnode.output_buffer
        self.routingtable = loopixnode.routingtable
        self.reactor = loopixnode.reactor
        self.drop_probability = drop_probability  # 设定丢包概率

        if node_list is None:
            node_list = []
        self.attack_nodes = node_list

    def set_node_list(self, add_list):
        self.attack_nodes.extend(add_list)

    def random_choose_node(self, num=1):
        from Databasemanage.LoopixDatamanager import LoopixDatamanager
        self.manager = LoopixDatamanager("database.db")
        mixnodelist = self.manager.select_all_mixnodes()

        if not mixnodelist:
            raise ValueError("nodelist 不能是空的")

        for i in range(min(num, len(mixnodelist))):
            mix = random.choice(mixnodelist)
            self.attack_nodes.append((mix.host, mix.port))

    def _should_drop(self):
        """基于 drop_probability 判断是否丢弃数据包"""
        return random.random() < self.drop_probability

    def attack(self, node_number=0):

        if node_number == 0:
            self._patch_methods_send_all()
        elif node_number > 0:
            self._patch_methods()
        else:
            raise ValueError("不进行丢包行为")

    def _patch_methods_send_all(self):
        self._target = self.loopix_node.loopix_sender
        """拦截目标对象的 send 方法"""
        if hasattr(self._target, "send"):
            self._target.send = self.drop_all_packets

    def _patch_methods(self):
        """拦截 Loopix_sender.send 方法，使其有条件地丢弃数据包"""
        self._target = self.loopix_node.loopix_sender
        if hasattr(self._target, "send"):
            self._target.send = self._conditional_drop_packets

    def drop_all_packets(self, packet, host, port, resolved_adrs=None):
        """(概率)丢弃所有数据包"""
        if self._should_drop():
            print(f"[Interceptor] Dropped ALL packets to {host}:{port} with probability {self.drop_probability}")
            return  # 丢弃数据包

        # 否则正常发送
        encoded_packet = encode(packet)  # 继续执行原来的加密过程
        if abstract.isIPAddress(host):
            self._target.transport.write(encoded_packet, (host, port))
        else:
            def send_to_ip(ip_addr):
                self._target.transport.write(encoded_packet, (ip_addr, port))

            try:
                self._target.transport.write(encoded_packet, (resolved_adrs[host], port))
            except KeyError:
                d = self._target.reactor.resolve(host)
                d.addCallback(send_to_ip)
                d.addErrback(lambda failure_obj: print(f"DNS 解析失败: {host} - {failure_obj}"))

    def _conditional_drop_packets(self, packet, host, port, resolved_adrs=None):
        """(概率)丢弃特定目标的数据包"""
        if (host, port) in self.attack_nodes and self._should_drop():
            print(
                f"[Interceptor] Conditionally dropped packet to {host}:{port} with probability {self.drop_probability}")
            return  # 丢弃数据包

        # 否则正常发送数据包
        print(f"[Interceptor] Allowed packet to {host}:{port}")
        encoded_packet = encode(packet)
        if abstract.isIPAddress(host):
            self._target.transport.write(encoded_packet, (host, port))
        else:
            def send_to_ip(ip_addr):
                self._target.transport.write(encoded_packet, (ip_addr, port))

            try:
                self._target.transport.write(encoded_packet, (resolved_adrs[host], port))
            except KeyError:
                d = self._target.reactor.resolve(host)
                d.addCallback(send_to_ip)
                d.addErrback(lambda failure_obj: print(f"DNS 解析失败: {host} - {failure_obj}"))



