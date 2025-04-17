from Node.LoopixNodes import Loopix_Client
from collections import defaultdict
from itertools import product, combinations
import numpy as np
from Crypto.CryptoNode import LoopixCrypto
import random
from twisted.internet import reactor
import time
import hashlib


def find_rank_n_paths(matrix, all_paths, n):
    num_paths = matrix.shape[0]
    indices = range(num_paths)

    # 尝试从所有路径中组合出 N 条路径
    for rows in combinations(indices, n):
        sub_matrix = matrix[list(rows), :]
        rank = np.linalg.matrix_rank(sub_matrix)
        if rank == n:
            selected_paths = [all_paths[i] for i in rows]
            return selected_paths, sub_matrix  # 找到就返回
    return None, None


def sample_from_exponential(lambda_param):
    interval = np.random.exponential(lambda_param)
    return interval


class LoopixSenderWithMixBarrage(Loopix_Client):

    def __init__(self, sec_params, name, port, host, privk, pubk, group=None):
        super().__init__(sec_params, name, port, host, privk, pubk, group)

        self.crypto = LoopixCrypto(self)
        # 备份网络状态
        self.all_node_dict = {}

        # 引导每次探测
        self.now_node_list = []
        self.probe_matrix = []
        self.probe_matrix_path = []
        self.probe_frequency = {}
        self.now_probe_round = 0
        self.init_frequency = 20
        # second
        self.round_time = 20
        self.target_server = None
        self.flow_frequency = {}
        self.flow_id_pair = {}
        self.nameHash = 'xxxxxxxxxx'

    def startProtocol(self):
        print("[%s] > Started" % self.name)
        self.plugin_initial()
        self.turn_on_processing()
        self.message_maker.make_stream("REAL")
        self.get_graph()
        for client in self.routingtable["clients"]:
            if client.name == 'client2':
                self.target_server = client
        for node in self.now_node_list:
            self.probe_frequency[node.name] = self.init_frequency
        self.generate_probe_matrix()
        reactor.callLater(20, self.probe_interest_scope)

    def probe_interest_scope(self):
        if len(self.probe_matrix_path) > 1 and self.target_server is not None:
            packet_pool = []
            for pindex in range(len(self.probe_matrix_path)):
                path = self.probe_matrix_path[pindex]
                path_frequency = 0
                for node in path:
                    if self.probe_frequency[node.name] > path_frequency:
                        path_frequency = self.probe_frequency[node.name]

                self.flow_frequency[pindex] = path_frequency
                self.flow_id_pair[pindex] = path

                for i in range(path_frequency):
                    tag = 'rd' + str(self.now_probe_round)
                    content = tag + ':flow' + str(pindex) + ':' + str(i) + ':' + str(self.nameHash)
                    if isinstance(content, str):
                        content = content.encode('utf-8')
                    path1 = [self.routingtable["provider_info"]] + list(path) + [self.target_server.provider] + [
                        self.target_server]

                    packet = self.generate_packet(content, path1)
                    packet_pool.append(packet)

            if len(packet_pool) > 0:
                print('probing')
                self.send_packets_with_interval(packet_pool)
            reactor.callLater(self.round_time, self.get_counter_result)

    def send_packets_with_interval(self, packet_pool):
        print(len(packet_pool))
        if not packet_pool:
            return  # 所有包发送完了

        packet = packet_pool.pop(random.randrange(len(packet_pool)))
        host = self.routingtable["provider_info"].host
        port = self.routingtable["provider_info"].port

        self.sender.send(packet, host, port)

        interval = sample_from_exponential(0.1)
        reactor.callLater(interval, self.send_packets_with_interval, packet_pool)

    def get_counter_result(self):
        pool = []
        print('collecting')
        for pindex in range(len(self.probe_matrix_path)):
            path = self.probe_matrix_path[pindex]
            tag = 'GR' + str(self.now_probe_round)
            content = tag + ':flow' + str(pindex) + ':' + str(self.nameHash)
            if isinstance(content, str):
                content = content.encode('utf-8')
            path = [self.routingtable["provider_info"]] + list(path) + [self.target_server.provider] + [
                self.target_server]

            packet = self.generate_packet(content, path)
            host = self.routingtable["provider_info"].host
            port = self.routingtable["provider_info"].port
            pool.append(packet)
        if len(pool) > 0:
            self.send_packets_with_interval(pool)

    def generate_trace_id(self) -> str:
        """
        node_name: 当前节点名称或ID
        counter: 本地递增计数（确保唯一）
        """
        raw = f"{self.name}-{'9999'}-{time.time_ns()}-{random.randint(0, 1 << 16)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]  # 12位16进制

    # 生成探测任务，包括探测频率、路径、TAG等
    def generate_packet(self, content, path):
        header, body = self.crypto.make_sphinx_packet(self.target_server, path, content, False, False, None)
        packet = (header, body)

        return packet

    def get_graph(self):
        tb = self.routingtable['mixnodes']
        for node in tb:
            self.all_node_dict[node.name] = node
            self.now_node_list.append(node)

    def generate_probe_matrix(self):
        group_to_nodes = defaultdict(list)

        for node in self.now_node_list:
            group_to_nodes[node.group].append(node)

        sorted_groups = sorted(group_to_nodes.keys())

        grouped_node_lists = [group_to_nodes[group] for group in sorted_groups]
        all_node_names = sorted(set(node.name for node in self.now_node_list))

        # 构建一个路径列表（之前 product 得到的）
        all_paths = list(product(*grouped_node_lists))

        # 初始化矩阵：行数为路径数，列数为节点数
        matrix = np.zeros((len(all_paths), len(all_node_names)), dtype=int)

        # 节点名到列索引的映射
        node_to_col = {name: idx for idx, name in enumerate(all_node_names)}

        # 填矩阵
        for row_idx, path in enumerate(all_paths):
            for node in path:
                col_idx = node_to_col[node.name]
                matrix[row_idx][col_idx] = 1

        # 打印矩阵（可选）

        for group in grouped_node_lists:
            if len(group) < 2:
                print('存在某层，节点数不足2，不满足要求,请选择更大的拓扑')
                return
        n = len(self.now_node_list)
        l = len(grouped_node_lists)
        rank_of_path_matrix = n - l + 1
        print("rank_of_path_matrix:", rank_of_path_matrix)
        self.probe_matrix_path, self.probe_matrix = find_rank_n_paths(matrix, all_paths, rank_of_path_matrix)
        print("路径-节点矩阵:\n", self.probe_matrix)
