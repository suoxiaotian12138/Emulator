from Routing.Node_verification_Tor import Node
from Routing.Circuit_Tor import *
from typing import List
from dataclasses import dataclass

# === 模拟 Tor 中的枚举，用于选择加权规则 ===

jsonReader = JSONReader(
    os.path.join(os.path.dirname(os.path.dirname(__file__)), 'D:\project\Oniverse\config.json'))
bandwidth_params = jsonReader.get_tor_config_params("bandwidth")

def networkstatus_get_bw_weight(key: str, default: float) -> float:
    """
    模拟 networkstatus_get_bw_weight(NULL, key, -1)。
    返回一些预定义的测试值或从配置中读取。
    """
    # 这里简单用字典演示，不同 key 对应不同权重。
    # 如果找不到就返回 default（这里通常是 -1）。
    mock_weights = {
        "Wgg": 9000,  # Guard->Guard
        "Wgm": 8000,  # Guard->(bridge)
        "Wgd": 7000,  # Guard->Dir
        "Wmg": 9500,  # Mid->Guard
        "Wmm": 10000,  # Mid->Mid
        "Wme": 7000,  # Mid->Exit
        "Wmd": 6000,  # Mid->Dir
        "Wee": 9000,  # Exit->Exit
        "Wem": 5000,  # Exit->Mid
        "Wed": 5000,  # Exit->Dir
        "Weg": 4000,  # Exit->Guard
        "Wbe": 12000,  # Dir->Exit
        "Wbm": 12000,  # Dir->Mid
        "Wbd": 12000,  # Dir->Dir
        "Wbg": 12000,  # Dir->Guard
        "Wgb": 10000,  # 下面是一些 "Wxxb" -> *bridge 的示例值
        "Wmb": 10000,
        "Web": 10000,
        "Wdb": 10000,
    }
    return mock_weights.get(key, default)


# === 守卫节点带宽结构，用来演示 guardfraction 的计算 ===
@dataclass
class GuardFractionBandwidth:
    guard_bw: float     # F * B
    non_guard_bw: float # (1-F) * B

# 模拟 guard_get_guardfraction_bandwidth：根据节点带宽和 guardfraction 百分比计算拆分带宽
def guard_get_guardfraction_bandwidth(bw: int, guardfraction_percentage: float) -> GuardFractionBandwidth:
    """
    假设 guardfraction_percentage 是一个 [0, 100] 之间的值，表示节点在 Guard 时占带宽的比例。
    这里简单演示。
    """
    if guardfraction_percentage < 0:
        guardfraction_percentage = 0
    elif guardfraction_percentage > 100:
        guardfraction_percentage = 100

    frac = guardfraction_percentage / 100.0
    guard_bw = frac * bw
    non_guard_bw = (1 - frac) * bw
    return GuardFractionBandwidth(guard_bw, non_guard_bw)

def compute_weighted_bandwidths(nodes: List[Node], rule: int):
    """
    结合 Tor 源码中 compute_weighted_bandwidths() 的核心逻辑，计算各节点加权带宽并返回：
    1) 每个节点对应的加权带宽列表

    rule 可取：
      NO_WEIGHTING, WEIGHT_FOR_EXIT, WEIGHT_FOR_GUARD,
      WEIGHT_FOR_MID, WEIGHT_FOR_DIR
    """

    # 1. 获取全局权重缩放参数（Tor中通常 >= 1）
    weight_scale = 10000

    # 2. 根据 rule 不同，获取对应的权重值

    Wg = Wm = We = Wd = -1.0
    Wgb = Wmb = Web = Wdb = -1.0

    if rule == bandwidth_params.WEIGHT_FOR_GUARD:
        Wg  = networkstatus_get_bw_weight("Wgg", -1)
        Wm  = networkstatus_get_bw_weight("Wgm", -1)  # bridges?
        We  = 0
        Wd  = networkstatus_get_bw_weight("Wgd", -1)

        Wgb = networkstatus_get_bw_weight("Wgb", -1)
        Wmb = networkstatus_get_bw_weight("Wmb", -1)
        Web = networkstatus_get_bw_weight("Web", -1)
        Wdb = networkstatus_get_bw_weight("Wdb", -1)

    elif rule == bandwidth_params.WEIGHT_FOR_MID:
        Wg  = networkstatus_get_bw_weight("Wmg", -1)
        Wm  = networkstatus_get_bw_weight("Wmm", -1)
        We  = networkstatus_get_bw_weight("Wme", -1)
        Wd  = networkstatus_get_bw_weight("Wmd", -1)

        Wgb = networkstatus_get_bw_weight("Wgb", -1)
        Wmb = networkstatus_get_bw_weight("Wmb", -1)
        Web = networkstatus_get_bw_weight("Web", -1)
        Wdb = networkstatus_get_bw_weight("Wdb", -1)

    elif rule == bandwidth_params.WEIGHT_FOR_EXIT:
        We  = networkstatus_get_bw_weight("Wee", -1)
        Wm  = networkstatus_get_bw_weight("Wem", -1)
        Wd  = networkstatus_get_bw_weight("Wed", -1)
        Wg  = networkstatus_get_bw_weight("Weg", -1)

        Wgb = networkstatus_get_bw_weight("Wgb", -1)
        Wmb = networkstatus_get_bw_weight("Wmb", -1)
        Web = networkstatus_get_bw_weight("Web", -1)
        Wdb = networkstatus_get_bw_weight("Wdb", -1)

    elif rule == bandwidth_params.WEIGHT_FOR_DIR:
        We  = networkstatus_get_bw_weight("Wbe", -1)
        Wm  = networkstatus_get_bw_weight("Wbm", -1)
        Wd  = networkstatus_get_bw_weight("Wbd", -1)
        Wg  = networkstatus_get_bw_weight("Wbg", -1)

        # dir -> bridge(不一定严格存在，但为对齐结构，设成 weight_scale)
        Wgb = Wmb = Web = Wdb = float(weight_scale)

    elif rule == bandwidth_params.NO_WEIGHTING:
        # 不进行任何特殊加权，直接全部设为 weight_scale
        Wg = Wm = We = Wd = float(weight_scale)
        Wgb = Wmb = Web = Wdb = float(weight_scale)

    # 3. 如果有任何权重为负，说明读取失败或无效，回退到 naive 算法
    #    (Tor 里常见做法：Wg=Wm=We=Wd=weight_scale; Wgb=Wmb=Web=Wdb=weight_scale)
    if any(w < 0 for w in [Wg, Wm, We, Wd, Wgb, Wmb, Web, Wdb]):
        print("Got negative bandwidth weights. Defaulting to naive selection.")
        Wg = Wm = We = Wd = float(weight_scale)
        Wgb = Wmb = Web = Wdb = float(weight_scale)

    # 4. 将权重都除以 weight_scale 做归一化
    Wg /= weight_scale
    Wm /= weight_scale
    We /= weight_scale
    Wd /= weight_scale
    Wgb /= weight_scale
    Wmb /= weight_scale
    Web /= weight_scale
    Wdb /= weight_scale

    # 准备返回值
    weighted_bandwidths = [0.0] * len(nodes)

    # 记录是否出现过缺失带宽的警告
    warned_missing_bw = False

    # 5. 遍历节点，计算加权带宽
    for i, node in enumerate(nodes):
        if not node.has_bandwidth:
            # 若共识等信息缺失带宽，这在 Tor 中非常罕见，会发出警告
            if not warned_missing_bw:
                print("Consensus is missing some bandwidths. Using a naive router selection.")
                warned_missing_bw = True
            this_bw = 30000  # Tor 中 “Chosen arbitrarily” 的做法
        else:
            this_bw = node.bandwidth_kb * 1024

        if this_bw < 0:
            this_bw = 0

        is_exit = node.is_exit and (not node.is_bad_exit)
        is_guard = node.is_possible_guard
        is_dir = node.is_dir

        # 默认权重
        weight = 1.0
        # 用于 guardfraction 计算：不按 Guard 标记时节点的权重
        weight_without_guard_flag = 0.0

        # 6. 根据节点自身属性（Exit/Guard/Dir）分配基础权重
        if is_guard and is_exit:
            # guard + exit + dir?
            if is_dir:
                # 当节点同时是 guard+exit+dir 时，用 Wdb*Wd 作为一种组合
                weight = Wd
                weight_without_guard_flag = We  # 不算 Guard 标记时看作 exit
                # 同时还要乘以“bridge”系数? 源码是 (is_dir ? Wdb*Wd : Wd)，
                # 这里可视需求决定，示例中先保持一致。
                weight *= Wdb
                weight_without_guard_flag *= Web
            else:
                weight = Wd
                weight_without_guard_flag = We
        elif is_guard:
            if is_dir:
                weight = Wg * Wgb
                weight_without_guard_flag = Wm * Wmb
            else:
                weight = Wg
                weight_without_guard_flag = Wm
        elif is_exit:
            if is_dir:
                weight = We * Web
            else:
                weight = We
        else:
            # middle
            if is_dir:
                weight = Wm * Wmb
            else:
                weight = Wm

        if weight < 0:
            weight = 0
        if weight_without_guard_flag < 0:
            weight_without_guard_flag = 0

        final_weight = 0.0
        if node.has_guardfraction and is_guard and rule != bandwidth_params.WEIGHT_FOR_GUARD:
            gf_bw = guard_get_guardfraction_bandwidth(this_bw, node.guardfraction_percentage)
            final_weight = gf_bw.guard_bw * weight + gf_bw.non_guard_bw * weight_without_guard_flag
        else:
            # 无 guardfraction 或正在选 Guard
            final_weight = weight * this_bw

        weighted_bandwidths[i] = final_weight

    return weighted_bandwidths


def choose_by_weight(weights: List[float]) -> int:
    if not weights or sum(weights) == 0:
        return -1  # 如果权重列表为空或所有权重为 0，则返回 -1

    indices = list(range(len(weights)))
    chosen_index = random.choices(indices, weights=weights, k=1)[0]
    return chosen_index

def choose_good_exit_server_general(nodelist: List[Node], circ:Circuit):
    n_supported = {}
    best_support = -1
    supporting_nodes = []
    excluded_ids = circ.excluded_ids


    # 如果找到了支持节点，根据带宽权重选择
    if best_support > 0 and supporting_nodes:
        return router_choose_random_node(supporting_nodes, circ)

    return None  # 如果没有找到合适的节点，返回 None

def router_choose_random_node(nodelist: List[Node], circ:Circuit, is_internal = False):
    """
    根据节点列表、电路状态和标志选择一个节点，结合 Tor 的带宽权重逻辑。
    返回: 选中的节点，或 None
    """
    # 解析标志
    need_uptime = circ.state.need_uptime
    need_capacity = circ.state.need_capacity
    need_guard = circ.state.need_guard
    excluded_ids = circ.excluded_ids
    rule = None

    if is_internal == False:
        if circ.state.need_guard:
            return None  # 不允许要求 Guard 特性
        if circ.state.onehop_tunnel:
            return None  # 不允许单跳连接
        if circ.state.is_ipv6_selftest:
            return None  # 不支持 IPv6 拓展
        rule = bandwidth_params.WEIGHT_FOR_EXIT

    else:
        # 确定权重规则
        rule = (bandwidth_params.WEIGHT_FOR_GUARD if circ.state.need_guard
                else bandwidth_params.WEIGHT_FOR_MID)

    # 排除节点
    if excluded_ids is None:
        excluded_ids = set()
    excluded_ids.add(0)  # 假设 0 是自身节点

    def is_candidate(node: Node) -> bool:
        if node.id in excluded_ids or not node.is_running:
            return False
        if need_uptime and not node.is_stable:
            return False
        if need_capacity and not node.is_fast:
            return False
        if need_guard and not node.is_guard:
            return False
        return True

    candidates = [node for node in nodelist if is_candidate(node)]

    # 如果没有候选节点，放宽限制
    if not candidates and (need_uptime or need_capacity or need_guard):
        print(f"No live nodes with required flags, relaxing constraints.")
        candidates = [node for node in nodelist
                      if node.id not in excluded_ids and node.is_running]

    if not candidates:
        print("No available nodes found.")
        return None

    # 计算加权带宽并转换为整数权重
    bandwidths_dbl = compute_weighted_bandwidths(candidates, rule)

    # 根据权重选择节点
    idx = choose_by_weight(bandwidths_dbl)
    if idx < 0:
        return None

    return candidates[idx]


# 示例用法
if __name__ == "__main__":
    nodes = [
        Node(1, 10, 0.3, True, True, True, False, True, False, True, False,False,False),  # 稳定、高带宽、非守卫
        Node(2, 50, 0.4, True, False, True, False,True, False, True, False, True, False),  # 高带宽、非稳定、非守卫
        Node(3, 200, 0.5, True, True, True, True, True, True,True, True, True, True),  # 稳定、高带宽、守卫
        Node(4, 10, 0.6, False, True, False, False,False, False,True, True,False, False),  # 不运行

    ]

    build_state = CpathBuildState(
        desired_path_len=3,
        need_uptime=False,
        need_capacity=True,
        need_conflux=True,
        expiry_time=time.time() + 3600  # 1 小时后过期
    )
    # 生成电路，自动完成基础初始化和全局列表注册
    circ1 = Circuit(build_state)

    selected = router_choose_random_node(nodes, circ1)
    print(f"Selected node: {selected.id if selected else None}")


    build_state1 = CpathBuildState(
        desired_path_len=3,
        need_uptime=False,
        need_capacity=False,
        need_conflux=False,
        expiry_time=time.time() + 3600  # 1 小时后过期
    )
    # 生成电路，自动完成基础初始化和全局列表注册
    circ2 = Circuit(build_state1)

    selected = router_choose_random_node(nodes, circ2)
    print(f"Selected node: {selected.id if selected else None}")