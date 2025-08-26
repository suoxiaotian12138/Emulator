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


async def register_all_guards(guard_configs, bus_factory):
    guards = []
    for name, ip, port, role, flags in guard_configs:
        guard = Tor_Node(name, ip, port, flags)

        guard.attach_bus(bus_factory(name, role.lower()))
        # 可选：让节点内部也能直接写 JSONL（方便你在类里调用）
        guard.emit = guard.event_bus.emit  # 或者 writer.emit_nowait
        # <<< NEW


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
        ("guard1", "192.168.66.241", 9001, 'Guard', ["Running", "Valid", "Guard","Fast","Stable"]),
        ("guard2", "192.168.66.242", 9002, 'Guard', ["Running", "Valid", "Guard", "Fast", "Stable"]),
        ("Middle1", "192.168.66.243", 9003, 'Middle',["Running", "Valid", "Fast","Stable"]),
        ("Middle2", "192.168.66.244", 9004, 'Middle',["Running", "Valid", "Fast","Stable"]),
        ("Exit1", "192.168.66.241", 9005, 'Exit',["Running", "Valid", "Exit","Fast","Stable"]),
        ("Exit2", "192.168.66.241", 9006, 'Exit',["Running", "Valid", "Exit","Fast","Stable"]),

    ]

    # >>> NEW: 启动一个进程级日志写手 + 资源探针
    writer = AsyncJsonlWriter(out_dir="exp/logs", rotate_mb=100, batch_size=200, flush_every_ms=100)
    writer.start()
    # 进程级资源探针：只开一次（CPU/内存/FD/loop lag）
    probe_task = asyncio.create_task(resource_probe(
        node_id="proc:nodes", role="relay-proc",
        emit=writer.emit_nowait, interval_s=1.0, lag_tick_ms=100
    ))

    # 给每个节点创建自己的 bus（node_id=节点名、role=guard/middle/exit）
    def bus_factory(node_name: str, role: str) -> EventBus:
        return EventBus(writer.emit_nowait, node_id=node_name, role=role)

    # 注册所有 guard
    await register_all_guards(guard_configs, bus_factory)

    try:
        await asyncio.sleep(30000)
    finally:
        print("[Main] Listener task cancelled.")

    # 阻塞等待
    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
