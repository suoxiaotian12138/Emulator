import asyncio
import sys
import ssl
import socket

from examples.Tor_simplified.Tor_Node import Tor_Node
from examples.Tor_simplified.Tor_Directory import TorDirectoryServer
from examples.Tor_simplified.Tor_Client import Tor_Client
import aiohttp
import asyncio, concurrent.futures, os, logging

# os.environ["PYTHONASYNCIODEBUG"] = "1"
# logging.basicConfig(level=logging.DEBUG)
import asyncio, threading, psutil, os


if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

MAX_TLS_THREADS = 128
loop = asyncio.get_event_loop()
loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_TLS_THREADS,
    thread_name_prefix="tls-worker"
))

async def _debug_watchdog(interval=10):
    while True:
        await asyncio.sleep(interval)
        print(f"\n[Watchdog] Dumping task stack frames every {interval}s:")
        for t in asyncio.all_tasks():
            if not t.done():
                coro_name = t.get_coro().__qualname__
                frames = t.get_stack(limit=3)
                print(f"↪ Task: {coro_name}")
                for f in frames:
                    print(f"   • {f.f_code.co_name} @ {f.f_lineno} in {f.f_code.co_filename}")

async def register_all_guards(guard_configs):
    guards = []
    for name, ip, port, role, flags in guard_configs:
        guard = Tor_Node(name, ip, port, flags)
        guards.append(guard)

    # 启动所有guard但不等待完成
    for guard in guards:
        asyncio.create_task(guard.start_protocol())

    return guards

async def dump_task_stacks(limit: int = 6):
    """
    打印所有未结束任务的栈帧（兼容 Py 3.8 → 3.12）
    """
    loop = asyncio.get_running_loop()
    print("\n=== TASK STACKS ===")
    for task in asyncio.all_tasks(loop):
        if task.done():
            continue

        coro = task.get_coro()
        print(f"• {coro.__qualname__:<40}  [{task._state}]")

        for frame in task.get_stack(limit=limit):
            # frame 是 types.FrameType；取文件名需访问 f_code
            fname = frame.f_code.co_filename
            lineno = frame.f_lineno
            func  = frame.f_code.co_name
            print(f"   ↳ {fname}:{lineno}  {func}")
    print("="*40)

def dump_stats():
    loop = asyncio.get_running_loop()
    executor = getattr(loop, "_default_executor", None)  # 可能为 None
    max_workers = executor._max_workers if executor else "n/a"
    queued = executor._work_queue.qsize() if executor else "n/a"

    print(f"live coroutines : {len(asyncio.all_tasks(loop))}")
    print(f"executor threads: {len(threading.enumerate())} / {max_workers}")
    print(f"executor queue  : {queued}")
    print(f"rss memory      : {psutil.Process(os.getpid()).memory_info().rss // (1024*1024)} MiB")


async def periodic_dump(interval=30):
    while True:
        dump_stats()
        await dump_task_stacks()   # <<< 加这一行
        await asyncio.sleep(interval)

async def main():
    # 启动目录服务器
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))

    # # 1. 打开调试模式
    # loop.set_debug(True)
    #
    # # 2. 定义“慢回调”阈值（秒）
    # loop.slow_callback_duration = 0.5   # >0.5 s 即打印 “Executing … took …”
    # asyncio.create_task(periodic_dump(30))

    # 3. 其他初始化（线程池、任务等）
    max_workers = 128
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(max_workers=max_workers,
                                              thread_name_prefix="tls-worker")
    )



    os.environ["DIRECTORY_ADDR"] = "192.168.66.241:9030"
    # asyncio.create_task(_debug_watchdog())
    # 多个 guard 配置
    guard_configs = [
        ("guard1", "192.168.66.241", 9001, 'Guard', ["Running", "Valid", "Guard","Fast","Stable"]),
        ("guard2", "192.168.66.242", 9002, 'Guard', ["Running", "Valid", "Guard", "Fast", "Stable"]),
        ("Middle1", "192.168.66.243", 9003, 'Middle',["Running", "Valid", "Fast","Stable"]),
        ("Middle2", "192.168.66.244", 9004, 'Middle',["Running", "Valid", "Fast","Stable"]),
        ("Exit1", "192.168.66.241", 9005, 'Exit',["Running", "Valid", "Exit","Fast","Stable"]),
        ("Exit2", "192.168.66.241", 9006, 'Exit',["Running", "Valid", "Exit","Fast","Stable"]),

    ]

    # 注册所有 guard
    guards = await register_all_guards(guard_configs)


    try:
        await asyncio.sleep(30000)
    finally:
        print("[Main] Listener task cancelled.")

    # 阻塞等待
    await asyncio.Event().wait()




if __name__ == "__main__":
    asyncio.run(main())
    # asyncio.run(direct_join_test())