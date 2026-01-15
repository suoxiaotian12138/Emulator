import sys
from examples.Tor_simplified.Tor_Node import Tor_Node
import concurrent.futures
import asyncio, threading, psutil, os

from tools.Log.writer import AsyncJsonlWriter
from tools.Log.bus import EventBus
from tools.Log.resources import resource_probe
from tools.Network_Management.delay_env import configure
from tools.Network_Management.geo_delay_injector import GeoDelayModel

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

MAX_TLS_THREADS = 128
loop = asyncio.get_event_loop()
loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_TLS_THREADS,
    thread_name_prefix="tls-worker"
))


async def register_all_guards(guard_configs):
    guards = []
    for name, ip, port, role, flags, exit_policy in guard_configs:
        guard = Tor_Node(name, ip, port, flags, exit_policy=exit_policy)
        guards.append(guard)

    # 启动所有guard但不等待完成
    for guard in guards:
        guard.event_bus.ev("node_start_protocol")
        asyncio.create_task(guard.start_protocol())

    return guards


def generate_specific_nodes(n_guard, n_middle, n_exit):
    """
    分别指定 Guard, Middle, Exit 的数量生成配置。

    Args:
        n_guard (int): Guard 节点的数量
        n_middle (int): Middle 节点的数量
        n_exit (int): Exit 节点的数量

    Returns:
        list: 配置元组列表
    """
    configs = []
    base_port = 9000

    # 找出最大数量，决定循环多少轮
    max_count = max(n_guard, n_middle, n_exit)

    for i in range(1, max_count + 1):
        suffix = f"{i:02d}"
        port = base_port + i

        # --- 1. 判断是否生成 Guard ---
        if i <= n_guard:
            configs.append((
                f"guard{suffix}",
                "192.168.66.242",
                port,
                'Guard',
                ["Running", "Valid", "Guard", "Fast", "Stable"],
                'reject 1-65535'
            ))

        # --- 2. 判断是否生成 Middle ---
        if i <= n_middle:
            configs.append((
                f"Middle{suffix}",
                "192.168.66.244",
                port,
                'Middle',
                ["Running", "Valid", "MiddleOnly", "Fast", "Stable"],
                'reject 1-65535'
            ))

        # --- 3. 判断是否生成 Exit ---
        if i <= n_exit:
            configs.append((
                f"Exit{suffix}",
                "192.168.66.243",
                port,
                'Exit',
                ["Running", "Valid", "Exit", "Fast", "Stable"],
                'accept 1-65535'
            ))

    return configs
async def main():
    # 启动目录服务器
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))

    # 固定延迟注入（仅启用此选项时生效）
    model = GeoDelayModel(fixed_owd_ms=100.0, jitter_ratio=0.0, jitter_cap=0.0, floor_ms=1.0)
    configure(enabled=False, mapping=None, model=model, delay_mode="scheduled")

    # 3. 其他初始化（线程池、任务等）
    max_workers = 128
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(max_workers=max_workers,
                                              thread_name_prefix="tls-worker")
    )
    os.environ["DIRECTORY_ADDR"] = "192.168.66.241:9030"
    # 多个 guard 配置
    guard_configs = generate_specific_nodes(n_guard=1, n_middle=1, n_exit=1)

    # 注册所有 guard
    await register_all_guards(guard_configs)

    try:
        await asyncio.sleep(30000)
    finally:
        print("[Main] Listener task cancelled.")

    # 阻塞等待
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())