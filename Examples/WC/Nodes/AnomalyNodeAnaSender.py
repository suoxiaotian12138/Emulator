from Node.LoopixNodes import Loopix_Client
from collections import defaultdict
from itertools import product, combinations
import numpy as np
from Crypto.CryptoNode import LoopixCrypto
import random
from twisted.internet import reactor
import time
import hashlib
import copy
import math
from scipy.optimize import lsq_linear

import numpy as np
import random
from itertools import combinations

output_path = "your_output_file.txt"


def find_rank_n_paths(matrix, all_paths, n, top_k_candidates=5):
    num_paths = matrix.shape[0]
    indices = list(range(num_paths))

    # 所有可能组合（先列出再 shuffle）
    all_combos = list(combinations(indices, n))
    random.shuffle(all_combos)  # 加入随机性

    # 得分函数：标准差越小越均衡
    def path_rarity_score(path_indices):
        sub_matrix = matrix[list(path_indices), :]
        col_sums = np.sum(sub_matrix, axis=0)
        return -np.std(col_sums)

    candidate_results = []

    for rows in all_combos:
        sub_matrix = matrix[list(rows), :]
        rank = np.linalg.matrix_rank(sub_matrix)
        if rank == n:
            score = path_rarity_score(rows)
            candidate_results.append((score, rows, sub_matrix))

    if not candidate_results:
        return None, None

    # 按得分排序，选前 top_k 个候选
    candidate_results.sort(reverse=True, key=lambda x: x[0])
    top_candidates = candidate_results[:top_k_candidates]

    # 从 top-k 里随机选一个
    selected_score, selected_rows, selected_matrix = random.choice(top_candidates)
    selected_paths = [all_paths[i] for i in selected_rows]

    return selected_paths, selected_matrix


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
        self.init_frequency = 30
        # second
        self.round_time = 30
        self.target_server = None
        self.flow_frequency = {}
        self.flow_id_pair = {}
        self.nameHash = 'xxxxxxxxxx'
        self.surbkey = {}
        self.log_gather = {}
        self.begin_gather = False

    def startProtocol(self):
        print("[%s] > Started" % self.name)
        self.plugin_initial()
        self.turn_on_processing()
        self.message_maker.make_stream("REAL")
        # self.begin_probe()

    def begin_probe(self):
        self.surbkey = {}
        self.log_gather = {}
        self.begin_gather = False
        self.flow_frequency = {}
        self.flow_id_pair = {}
        self.all_node_dict = {}
        self.now_probe_round += 1
        # 引导每次探测
        self.now_node_list = []
        self.probe_matrix = []
        self.probe_matrix_path = []
        self.probe_frequency = {}
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
        if len(packet_pool) % 10 == 0:
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

            packet = self.generate_packet_withsurb(content, path)
            host = self.routingtable["provider_info"].host
            port = self.routingtable["provider_info"].port
            for i in range(10):
                pool.append(packet)

        if len(pool) > 0:
            self.send_packets_with_interval(pool)

    def check_malicious(self):
        print('check_malicious', self.log_gather)
        node_to_id = {node.name: idx for idx, node in enumerate(self.now_node_list)}
        id_to_node = {idx: node for node, idx in node_to_id.items()}

        K = len(self.now_node_list)
        M = []
        for flow_id in sorted(self.flow_id_pair.keys()):
            row = [0] * K
            for node in self.flow_id_pair[flow_id]:
                row[node_to_id[node.name]] = 1
            M.append(row)
        M = np.array(M)
        b = []
        for flow_id in sorted(self.flow_id_pair.keys()):
            vv = self.log_gather.get(str(flow_id), 0.00001)
            val = float(vv)
            ratio = val / self.init_frequency
            b.append(math.log(ratio))

        b = np.array(b)

        K = M.shape[1]
        lower_bounds = [-20] * K  # log(x) 的下界，对应 x ≈ 2e-9
        upper_bounds = [0] * K  # log(x) 的上界，对应 x ≤ 1

        # 求解 log(x)
        res = lsq_linear(M, b, bounds=(lower_bounds, upper_bounds), lsmr_tol='auto')

        log_x = res.x
        x = np.exp(log_x)  # 恢复出 x ∈ [0,1]
        # 第五步：输出 node.name 与 x
        badnode = []
        for idx, val in enumerate(x):
            if val < 0.9:
                badnode.append(f"{id_to_node[idx]}({val:.2f})")
            print(f"{id_to_node[idx]}: {val:.4f}")

        with open(output_path, "w") as f:
            f.write(", ".join(badnode))
        self.begin_probe()

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        info = None
        try:
            _, _, info = self.process.read_packet_client(packet, False, self.surbkey)
        except Exception as e:
            print('eee', e)
        if isinstance(info, tuple):
            msg, decrypted_packet = info[0], info[1]
            try:
                if not isinstance(msg, str):
                    msg = msg.decode('utf-8')
                if msg.startswith('RECV'):
                    if not self.begin_gather:
                        self.begin_gather = True
                        reactor.callLater(10, self.check_malicious)

                    r = msg.split(':')
                    roundid = r[1].replace('R', '')
                    flowid = r[2].replace('F', '')
                    num = r[3]
                    # print('TD-10', roundid, flowid, num)
                    self.log_gather[flowid] = num
            except Exception as e:
                print('eee', e)
        else:
            pass
        try:
            # print('=========GT2=========')
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")

    def generate_trace_id(self) -> str:
        raw = f"{self.name}-{'9999'}-{time.time_ns()}-{random.randint(0, 1 << 16)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:12]  # 12位16进制

    # 生成探测任务，包括探测频率、路径、TAG等
    def generate_packet(self, content, path):
        header, body = self.crypto.make_sphinx_packet(self.target_server, path, content, False, False, None)
        packet = (header, body)

        return packet

    def generate_packet_withsurb(self, content, path):
        surbid = self.generate_trace_id()
        header, body = self.crypto.make_sphinx_packet(self.target_server, path, content, True, False, None,
                                                      surb_trace_id=surbid)
        packet = (header, body)

        for key in self.crypto.surb_key_list.keys():
            v = self.crypto.surb_key_list[key]
            self.surbkey[key] = copy.deepcopy(v)

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
