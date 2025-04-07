from Crypto.Crypto_Tor import Cryptp_Tor
from typing import Optional
import time




def router_can_choose_node(node, flags):
    """检查节点是否可选"""
    return True

def nodelist_get_list():
    nodes = [Node(i) for i in range(10)]
    return nodes

def exit_nodelist_get_list():
    nodes = [Node(i) for i in range(10)]
    return nodes

class Node:
    """
    表示 Tor 网络中的一个路由器节点，等价于 C 中的 node_t 结构体。
    封装了路由器状态、描述符和微描述符，并记录本地状态。
    """

    # 常量定义，模拟 C 中的 DIGEST_LEN
    DIGEST_LEN = 20  # RSA 身份摘要长度（SHA-1）

    def __init__(self, id):
        """
        初始化 Node 对象。

        :param identity: 节点的 RSA 身份摘要（20字节）
        """

        # 索引信息
        self.id = id
        self.port = 9999


        self.ht_ent = None  # 哈希表条目（Python 中可省略，或用字典实现）
        self.ed_ht_ent = None  # Ed25519 哈希表条目
        self.nodelist_idx = -1  # 在节点列表中的索引，初始为 -1

        # 身份信息
        crypto = Cryptp_Tor()
        self.identity = crypto.generate_rsa_key() # RSA 身份摘要
        self.ed25519_id = None  # Ed25519 身份公钥

        # 原始数据引用
        self.md = None  # 微描述符
        self.ri = None  # 路由器描述符
        self.rs = None  # 路由器状态
        self.bandwidth_kb = 1000

        # 本地状态（布尔标志）
        self.is_running = True  # 是否正在运行
        self.is_valid = True  # 是否有效
        self.is_fast = True  # 是否快速
        self.is_stable = True  # 是否稳定
        self.is_possible_guard = True  # 是否适合做守卫
        self.is_exit = True  # 是否适合做出口
        self.is_bad_exit = False  # 是否为不良出口
        self.has_bandwidth = True
        self.is_middle_only = False  # 是否仅适合中间节点
        self.is_dir = False  # 是否为目录服务器
        self.is_hs_dir = False  # 是否为隐藏服务目录
        self.has_guardfraction = True

        # 策略状态
        self.rejects_all = False  # 是否拒绝所有流量

        # 派生信息
        self.ipv6_preferred = False  # IPv6 是否优先
        self.country = None  # 国家代码（类型待定义，例如 str）

        # 目录服务器专用字段
        self.last_reachable = 0  # 上次 IPv4 可达时间（Unix 时间戳）
        self.last_reachable6 = 0  # 上次 IPv6 可达时间

        # 隐藏服务目录索引
        self.hsdir_index = None

    def set_running(self, running: bool):
        """设置节点的运行状态"""
        self.is_running = running

    def set_valid(self, valid: bool):
        """设置节点的有效性"""
        self.is_valid = valid

    def update_reachability(self, ipv4: bool = True, timestamp: Optional[int] = None):
        """更新节点的最后可达时间"""
        if timestamp is None:
            timestamp = int(time.time())
        if ipv4:
            self.last_reachable = timestamp
        else:
            self.last_reachable6 = timestamp

if __name__ == "__main__":
    # 创建一个示例节点
    node = Node(0)
    print(node)
    print(f"Last reachable (IPv4): {node.last_reachable}")
    print(f"Ed25519 ID: {node.ed25519_id.key.hex() if node.ed25519_id else 'None'}")