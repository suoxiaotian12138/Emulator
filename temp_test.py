
from examples.Tor_simplified.Tor_Client import Tor_Client
import signal, faulthandler, sys, traceback
import asyncio, concurrent.futures, os, logging
import asyncio, threading, psutil, os



import concurrent.futures

# os.environ["PYTHONASYNCIODEBUG"] = "1"
#
# # 启用 debug 日志输出
# logging.basicConfig(level=logging.DEBUG)

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

MAX_TLS_THREADS = 128
loop = asyncio.get_event_loop()
loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_TLS_THREADS,
    thread_name_prefix="tls-worker"
))

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

async def periodic_dump(interval=30):
    while True:
        dump_stats()
        await dump_task_stacks()   # <<< 加这一行
        await asyncio.sleep(interval)


def dump_stats():
    loop = asyncio.get_running_loop()
    executor = getattr(loop, "_default_executor", None)  # 可能为 None
    max_workers = executor._max_workers if executor else "n/a"
    queued = executor._work_queue.qsize() if executor else "n/a"

    print(f"live coroutines : {len(asyncio.all_tasks(loop))}")
    print(f"executor threads: {len(threading.enumerate())} / {max_workers}")
    print(f"executor queue  : {queued}")
    print(f"rss memory      : {psutil.Process(os.getpid()).memory_info().rss // (1024*1024)} MiB")




async def main():
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))

    # # 调试设置
    # loop.set_debug(True)
    # loop.slow_callback_duration = 0.5

    # 设置线程池
    max_workers = 128
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker"
        )
    )

    # 环境变量设置
    os.environ["DIRECTORY_ADDR"] = "192.168.66.241:9030"

    # 配置参数
    total_batches = 1
    clients_per_batch = 10
    # delay_before_stream_send = 10  # 每批建立连接后等多少秒再发流
    delay_between_batches = 20      # 每批之间间隔几秒

    all_clients = []
    client_index = 0

    message = b"HEAD / HTTP/1.1\r\nHost: www.baidu.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    addr = ("www.baidu.com", 443)
    hop = 3

    for batch in range(total_batches):
        print(f"[Main] Creating batch {batch + 1}...")

        # 1. 创建本批客户端
        batch_clients = []
        for _ in range(clients_per_batch):
            name = f"client{client_index}"
            port = 9102 + client_index
            client = Tor_Client(name=name, host="192.168.66.242", port=port, model='sim')
            batch_clients.append(client)
            all_clients.append(client)
            client_index += 1

        # 2. 启动协议任务
        for client in batch_clients:
            asyncio.create_task(client.start_protocol())

        # print(f"[Main] Batch {batch + 1} created. Waiting {delay_before_stream_send}s before sending streams...")
        # await asyncio.sleep(delay_before_stream_send)

        # 3. 执行发流任务
        print(f"[Main] Sending streams for batch {batch + 1}...")
        for client in batch_clients:
            asyncio.create_task(client.make_stream(message=message, addr=addr, hops_count=hop))

        print(f"[Main] Batch {batch + 1} completed. Waiting {delay_between_batches}s before next batch...")
        await asyncio.sleep(delay_between_batches)

    print(f"[Main] All batches processed. Total clients: {len(all_clients)}")

    # 保持运行
    try:
        await asyncio.sleep(800)
    finally:
        print("[Main] Finished.")

    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
