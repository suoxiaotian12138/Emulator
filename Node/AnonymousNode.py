from Node.LoopixNodes import *



class AnonymousNode:
    def __init__(self, ip:str, name, port, privk=None, pubk=None):
        self.name = name
        self.port = port
        self.ip = ip
        self.privk = privk
        self.pubk = pubk
    """
    Methods for selecting transmission paths in anonymous networks
    Must be implemented by subclasses
    :nodelist Anonymous nodes to choose from
    :receiver The receiver of the packet
    """

    def startProtocol(self):
        return

anonymous_networks = {
    "Loopix": {
        "Client": Loopix_Client,
        "Mixnode": Loopix_Mixnode,
        "Provider": Loopix_Provider,
    },
}

# **动态创建匿名网络节点的工厂方法**
def Create_anonymous_node(network_type, node_type, *args, **kwargs):
    """根据 network_type 选择匿名网络，再根据 node_type 选择具体的节点类型"""
    if network_type not in anonymous_networks:
        raise ValueError(f"未知的匿名网络类型: {network_type}")

    if node_type not in anonymous_networks[network_type]:
        raise ValueError(f"未知的 {network_type} 节点类型: {node_type}")

    # 创建节点对象
    return anonymous_networks[network_type][node_type](*args, **kwargs)