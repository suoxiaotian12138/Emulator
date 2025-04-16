from operator import attrgetter
import itertools
from time import sleep

from Databasemanage.LoopixDatamanager import LoopixDatamanager
#用于初始化匿名网络内的节点保存的路由表

class LoopixRoutingTable:
    def __init__(self, nodetype, name, provider=None):
        """
        初始化 Loopix 路由表
        :param nodetype: 节点类型 ('mixnode' 或 'client')
        :param provider: 仅在 nodetype 为 'client' 时使用
        """
        self.nodetype = nodetype
        self.manager = LoopixDatamanager("database.db")
        self.name = name

        if nodetype == "mixnode" or nodetype == "provider":
            self.routing_table = self._initialize_mixnode()
        elif nodetype == "client":
            self.routing_table = self._initialize_client(provider)
        else:
            raise ValueError(f"不支持的 nodetype: {nodetype}")

    def _initialize_mixnode(self):
        """初始化 Mixnode 的路由表"""
        mixnodelist = self.manager.select_all_mixnodes()
        providerlist = self.manager.select_all_providers()
        return {
            "mixnodes": mixnodelist,
            "providers": providerlist,
            "layer": self.get_layer_number(mixnodelist)
        }

    def _initialize_client(self, provider=None):
        """初始化 Client 的路由表"""
        provider_info = self.manager.select_provider_by_name(provider)
        mixnodelist = self.manager.select_all_mixnodes()
        providerlist = self.manager.select_all_providers()
        clientlist = self.manager.select_all_clients(self.name)

        return {
            "mixnodes": mixnodelist,
            "providers": providerlist,
            "clients": clientlist,
            "provider_info": provider_info,
            "layer": self.get_layer_number(mixnodelist)
        }
    def get_layer_number(self, mixnodelist):
        return len(self.group_layered_topology(mixnodelist))

    def group_layered_topology(self, mixes):
        sorted_mixes = sorted(mixes, key=attrgetter('group'))
        grouped_mixes = [list(group) for _, group in itertools.groupby(sorted_mixes,
                                                                       lambda x: x.group)]
        return grouped_mixes
    def get_routing_table(self):
        """返回当前节点的路由表"""
        return self.routing_table




class TorConnectionTable:
    #1.记录电路的状况和会话密钥 2.记录自身的描述符 3.维护和相邻节点的连接
    def __init__(self):
        self.table = []