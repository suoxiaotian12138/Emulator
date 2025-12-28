import sys
from examples.Tor_simplified.Tor_Node import Tor_Node
import concurrent.futures
import asyncio, threading, psutil, os

from tools.Log.writer import AsyncJsonlWriter
from tools.Log.bus import EventBus
from tools.Log.resources import resource_probe

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

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

async def main():
    # 启动目录服务器
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))


    # 3. 其他初始化（线程池、任务等）
    max_workers = 128
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(max_workers=max_workers,
                                              thread_name_prefix="tls-worker")
    )
    os.environ["DIRECTORY_ADDR"] = "192.168.66.241:9030"
    # 多个 guard 配置
    guard_configs = [
        ("guard1", "192.168.66.242", 9001, 'Guard', ["Running", "Valid", "Guard","Fast","Stable"], 'reject 1-65535'),
        # ("guard2", "192.168.66.242", 9002, 'Guard', ["Running", "Valid", "Guard", "Fast", "Stable"], 'reject 1-65535'),
        ("Middle1", "192.168.66.244", 9003, 'Middle',["Running", "Valid", "MiddleOnly", "Fast", "Stable"], 'reject 1-65535'),
        # ("Middle2", "192.168.66.244", 9004, 'Middle',["Running", "Valid", "MiddleOnly", "Fast","Stable"], 'reject 1-65535'),
        ("Exit1", "192.168.66.243", 9005, 'Exit',["Running", "Valid", "Exit","Fast","Stable"], 'accept 1-65535'),
        # ("Exit2", "192.168.66.243", 9006, 'Exit',["Running", "Valid", "Exit","Fast","Stable"], 'accept 1-65535'),

    ]

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
