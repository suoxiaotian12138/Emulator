import random
import time
import os
from dataclasses import dataclass
from tools.json_reader import JSONReader

jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json'))
circuit_params = jsonReader.get_tor_config_params("circuitParams")

# 全局电路列表（模拟 Tor 中 circuitlist 全局结构）
global_circuit_list = []

def networkstatus_get_param(param_name, default_val, min_val, max_val):
    """
    简化版本的 networkstatus_get_param。
    直接返回 default_val（忽略 min_val 和 max_val），
    或可进一步自定义逻辑。
    """
    return default_val

def circuit_initial_package_window():
    """
    获取初始 package_window（若从共识中获取到的值 < 0 则使用默认）。
    """
    num = networkstatus_get_param("circwindow",
                                  circuit_params.CIRCWINDOW_START,
                                  circuit_params.CIRCWINDOW_START_MIN,
                                  circuit_params.CIRCWINDOW_START_MAX)
    return circuit_params.CIRCWINDOW_START if num < 0 else num

def circuit_reset_sendme_randomness(circ):
    """
    重置电路中用于 sendme 随机性的变量。
    """
    circ.have_sent_sufficiently_random_cell = 0
    # 在 Tor 中实际会使用快速 RNG，这里用 Python 的 random.randint 简化
    half = circuit_params.CIRCWINDOW_INCREMENT // 2
    circ.send_randomness_after_n_cells = half + random.randint(0, half)

def predicted_ports_time_remaining():
    """
    返回预测端口还需保持的时间（秒）。
    这里为了示例，固定返回 3600 秒（1 小时）。
    """
    return 3600

def log_warn(msg):
    print("WARN:", msg)

def log_info(msg):
    print("INFO:", msg)

def tor_trace(subsys, event, circuit_id):
    print(f"TRACE[{subsys}][{event}]: Circuit ID {circuit_id}")

@dataclass
class CpathBuildState:
    """
    电路构建所需的参数配置。
    """
    desired_path_len: int
    chosen_exit: any = None
    need_uptime: bool = False
    need_capacity: bool = False
    need_guard: bool = False
    is_internal: bool = False
    is_ipv6_selftest: bool = False
    onehop_tunnel: bool = False
    need_conflux: bool = False
    conflux_nonce: int = 0
    failure_count: int = 0
    expiry_time: float = 0.0  # 直接用 float 表示过期时间戳
    purpose: int = 0

class Circuit:
    """
    模拟 Tor 中从用户开始到网络的电路结构
    """
    global_counter = 1  # 为了给每个电路分配唯一的标识
    jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'D:\project\Oniverse\config.json'))
    circuit_params = jsonReader.get_tor_config_params("circuitParams")

    def __init__(self, build_state: CpathBuildState = None, purpose=circuit_params.CIRCUIT_PURPOSE_C_GENERAL):



        self.purpose = purpose
        # 电路内 cell 队列，用列表模拟
        self.n_chan_cells = []

        # 分配一个全局唯一标识
        self.global_identifier = Circuit.global_counter
        Circuit.global_counter += 1

        # 随机生成 16 位 Stream ID
        self.next_stream_id = random.randint(0, (1 << 16) - 1)

        # 随机减少 0~1 个早期 Relay cell 的可用数量
        self.remaining_relay_early_cells = circuit_params.MAX_RELAY_EARLY_CELLS_PER_CIRCUIT - random.randint(0, 1)

        # 生成一个 nonce（用于握手等用途）
        self.rend_circ_nonce = os.urandom(circuit_params.DIGEST_LEN)

        # 获取当前时间作为创建和开始时间
        now = time.time()
        self.timestamp_created = now
        self.timestamp_began = now

        # 设置 package_window 和 deliver_window
        self.package_window = circuit_params.CIRCWINDOW_START
        self.deliver_window = circuit_params.CIRCWINDOW_START

        # 重置 sendme 随机性
        circuit_reset_sendme_randomness(self)

        # 将电路加入全局列表，并记录其索引
        global_circuit_list.append(self)
        self.global_circuitlist_idx = len(global_circuit_list) - 1

        # 根据预测情况设置电路空闲超时
        prediction_time = predicted_ports_time_remaining()
        # 增加一点随机扰动
        extra = random.randint(0, prediction_time // 20 + 1)
        self.circuit_idle_timeout = prediction_time + 1 + extra

        if self.circuit_idle_timeout <= 0:
            log_warn("Circuit chose a negative idle timeout.")
            self.circuit_idle_timeout = circuit_params.DFLT_IDLE_TIMEOUT_WHILE_LEARNING

        log_info(f"Circuit {self.global_identifier} chose an idle timeout of "
                 f"{self.circuit_idle_timeout} based on {prediction_time} seconds prediction.")

        tor_trace("circuit", "new_origin", self.global_identifier)

        self.state = build_state
        self.excluded_ids = None

    def __str__(self):
        return (
            f"Circuit(ID={self.global_identifier}, next_stream_id={self.next_stream_id}, "
            f"remaining_relay_early_cells={self.remaining_relay_early_cells}, "
            f"idle_timeout={self.circuit_idle_timeout}, "
            f"desired_path_len={self.state.desired_path_len}, chosen_exit={self.state.chosen_exit}, "
            f"need_uptime={self.state.need_uptime}, need_capacity={self.state.need_capacity}, "
            f"is_internal={self.state.is_internal}, is_ipv6_selftest={self.state.is_ipv6_selftest}, "
            f"onehop_tunnel={self.state.onehop_tunnel}, need_conflux={self.state.need_conflux}, "
            f"failure_count={self.state.failure_count}, expiry_time={self.state.expiry_time})"
        )

class Path:
    def __init__(self):


if __name__ == "__main__":
    # 在调用前可以自行设置随机数种子
    random.seed(time.time())

    # 假设需要建造一个有 3 个节点的电路，且需要 uptime/capacity/conflux 等
    build_state = CpathBuildState(
        desired_path_len=3,
        need_uptime=True,
        need_capacity=True,
        need_conflux=True,
        expiry_time=time.time() + 3600  # 1 小时后过期
    )

    # 生成电路，自动完成基础初始化和全局列表注册
    new_circuit = Circuit(build_state)
    print(new_circuit)
