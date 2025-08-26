import os, sys, asyncio, concurrent.futures
from examples.Tor_simplified.Tor_Client import Tor_Client

# >>> NEW
from tools.Log.writer import AsyncJsonlWriter
from tools.Log.bus import EventBus
from tools.Log.resources import resource_probe
# <<< NEW



async def main():
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))

    # 线程池保持你的设定
    max_workers = 128
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker"
        )
    )

    os.environ["DIRECTORY_ADDR"] = "192.168.66.241:9030"

    total_batches = 1
    clients_per_batch = 1000
    delay_between_batches = 20

    # >>> NEW: 进程级日志写手 + 资源探针（只开一次）
    writer = AsyncJsonlWriter(out_dir="exp/logs", rotate_mb=100, batch_size=200, flush_every_ms=100)
    writer.start()

    probe_task = asyncio.create_task(resource_probe(
        node_id="proc:clients", role="client-proc",
        emit=writer.emit_nowait, interval_s=1.0, lag_tick_ms=100
    ))

    def bus_factory(node_name: str) -> EventBus:
        return EventBus(writer.emit_nowait, node_id=node_name, role="client")
    # <<< NEW

    all_clients = []
    client_index = 0

    message = (b"HEAD / HTTP/1.1\r\nHost: www.baidu.com\r\n"
               b"User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n")
    addr = ("www.baidu.com", 443)
    hop = 3

    for batch in range(total_batches):
        print(f"[Main] Creating batch {batch + 1}...")

        batch_clients = []
        for _ in range(clients_per_batch):
            name = f"client{client_index}"
            port = 9102 + client_index
            client = Tor_Client(name=name, host="192.168.66.242", port=port, model='sim')

            # >>> NEW: 挂事件总线，类内部就能随时埋点
            client.attach_bus(bus_factory(name))
            # 可选：暴露 emit 方便内部直接写 JSONL
            client.emit = client.event_bus.emit
            # <<< NEW

            batch_clients.append(client)
            all_clients.append(client)
            client_index += 1

        # 启动协议任务
        for client in batch_clients:
            asyncio.create_task(client.start_protocol())

        # 发流
        print(f"[Main] Sending streams for batch {batch + 1}...")
        for client in batch_clients:
            asyncio.create_task(client.make_stream(message=message, addr=addr, hops_count=hop))

        print(f"[Main] Batch {batch + 1} completed. Waiting {delay_between_batches}s before next batch...")
        await asyncio.sleep(delay_between_batches)

    print(f"[Main] All batches processed. Total clients: {len(all_clients)}")

    try:
        await asyncio.sleep(800)
    finally:
        print("[Main] Finished.")
        # >>> NEW: 清理
        probe_task.cancel()
        try: await probe_task
        except asyncio.CancelledError: pass
        await writer.stop()
        # <<< NEW

    await asyncio.Event().wait()

if __name__ == "__main__":
    asyncio.run(main())
