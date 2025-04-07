import abc
from operator import attrgetter
import itertools
import math

"""
Methods for selecting transmission paths in anonymous networks
Must be implemented by subclasses
:nodelist Anonymous nodes to choose from
:receiver The receiver of the packet
"""

import random

class RoutingStrategies:
    """包含不同路由策略的类"""

    @staticmethod
    def tor_routing_strategy(nodelist: list, receiver):
        """Tor 路由策略"""
        if len(nodelist) < 3:
            raise ValueError("nodelist 必须至少包含 3 个节点")

        # 随机选取三个不同的节点
        path = random.sample(nodelist, 3)
        return path

    @staticmethod
    def loopix_routing_strategy(nodelist: list, from_layer=0):

        if not nodelist:
            raise ValueError("nodelist 不能是空的")

        if any(not sublist for sublist in nodelist):
            raise ValueError("nodelist 中的所有子列表都必须包含至少一个节点")

        # 将节点按 group 分组，先排序
        sorted_mixes = sorted(nodelist, key=attrgetter('group'))
        grouped = {}
        for key, group in itertools.groupby(sorted_mixes, key=lambda x: x.group):
            grouped[key] = list(group)

        all_layers = sorted(grouped.keys())
        if not all_layers:
            raise ValueError("节点没有有效的 group 属性")

        max_layer = max(all_layers)
        # 构造层的顺序：从 from_layer+1 到 max_layer，再从 1 到 from_layer-1（循环，不含 from_layer）
        ordered_layers = list(range(from_layer + 1, max_layer + 1)) + list(range(1, from_layer))
        # 过滤掉 nodelist 中没有的层
        ordered_layers = [layer for layer in ordered_layers if layer in grouped]

        mix_chain = []
        for layer in ordered_layers:
            mix = random.choice(grouped[layer])
            mix_chain.append(mix)

        return mix_chain


# 使用字典存储策略
routing_strategies = {
    "Tor": RoutingStrategies.tor_routing_strategy,
    "Loopix": RoutingStrategies.loopix_routing_strategy
}


# 统一调用策略的方法
def execute_routing_strategy(strategy_name, *args, **kwargs):
    """通用策略执行器"""
    if strategy_name not in routing_strategies:
        raise ValueError(f"未知的路由策略: {strategy_name}")

    return routing_strategies[strategy_name](*args, **kwargs)


