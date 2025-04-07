import random

# 模拟节点类
class Node:
    def __init__(self, name, group):
        self.name = name
        self.group = group

    def __repr__(self):
        return f"{self.name}(G{self.group})"

# 替换为你的 Loopix 类
class Loopix:
    @staticmethod
    def loopix_routing_strategy(nodelist: list, from_layer=0):
        if not nodelist:
            raise ValueError("nodelist 不能是空的")

        if any(not sublist for sublist in nodelist):
            raise ValueError("nodelist 中的所有子列表都必须包含至少一个节点")

        import itertools
        from operator import attrgetter

        sorted_mixes = sorted(nodelist, key=attrgetter('group'))
        grouped = {}
        for key, group in itertools.groupby(sorted_mixes, key=lambda x: x.group):
            grouped[key] = list(group)

        all_layers = sorted(grouped.keys())
        if not all_layers:
            raise ValueError("节点没有有效的 group 属性")

        max_layer = max(all_layers)
        ordered_layers = list(range(from_layer + 1, max_layer + 1)) + list(range(1, from_layer))
        ordered_layers = [layer for layer in ordered_layers if layer in grouped]

        mix_chain = []
        for layer in ordered_layers:
            mix = random.choice(grouped[layer])
            mix_chain.append(mix)

        return mix_chain

# 🔧 测试函数
def a_loopix_routing_strategy():
    # 准备节点：group=1~4，每组2个
    nodes = [
        Node("A1", 1), Node("A2", 1),
        Node("B1", 2), Node("B2", 2),
        Node("C1", 3), Node("C2", 3),
        Node("D1", 4), Node("D2", 4),
    ]

    # 设定 from_layer=2，预期应该选 group=3 → 4 → 1
    from_layer = 4
    result = Loopix.loopix_routing_strategy(nodes, from_layer=from_layer)

    print(f"from_layer={from_layer}, routing result:")
    for node in result:
        print(f"  {node}")

    selected_groups = [node.group for node in result]
    expected_groups = [3, 4, 1]

    assert selected_groups == expected_groups, f"Test failed! Got {selected_groups}, expected {expected_groups}"
    print("✅ Test passed!")

# 运行测试
a_loopix_routing_strategy()
