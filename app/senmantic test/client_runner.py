# client_runner.py
# Single-run driver for Tor/TorBox semantic validation.
# Goal: make one run deterministic and complete: build circuit -> send enough payload -> teardown.

from examples.Tor_simplified.Tor_Client import Tor_Client
import sys
import concurrent.futures
import asyncio
import os
import time
import contextlib
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# =========================
# 0) Embedded "set ..." defaults
# =========================
# If the user already set an env var outside, we keep it.
DEFAULT_ENV = {
    "DIRECTORY_ADDR": "192.168.66.241:9030",
    "NODE_ADDR": "192.168.66.242",
    "TARGET_HOST": "192.168.66.243",
    "TARGET_PORT": "8000",
    "PAYLOAD_MB": "20",
    # Optional knobs (safe defaults)
    "CLIENTS_PER_BATCH": "1",
    "TOTAL_BATCHES": "1",
    "BATCH_DELAY": "2",
    "HOPS": "3",
    "CHUNK_KB": "32",
    "WARMUP_KB": "4",
    "START_TIMEOUT_S": "30",
    "INTER_CHUNK_SLEEP_MS": "0",
    "MAX_TLS_THREADS": "128",
}

for k, v in DEFAULT_ENV.items():
    os.environ.setdefault(k, v)

def env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)

def env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v

async def run_one_client(client: Tor_Client, addr, hop: int,
                         payload_mb: int, chunk_kb: int,
                         warmup_kb: int,
                         start_timeout_s: int,
                         inter_chunk_sleep_ms: int):
    t0 = time.time()
    proto_task = asyncio.create_task(client.start_protocol())

    try:
        try:
            await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)
        except asyncio.TimeoutError:
            print(f"[ClientRunner] ready_to_send timeout after {start_timeout_s}s for {client.name}")
            return

        print(f"[ClientRunner] {client.name} ready_to_send set")
        print(f"[ClientRunner] {client.name} protocol started in {time.time() - t0:.2f}s")

        # open once
        circuit, stream = await client.open_stream(addr=addr, hops_count=hop)

        # warmup on same stream
        warmup = b"W" * (warmup_kb * 1024)
        await client.stream_write(circuit, stream, warmup)
        print(f"[ClientRunner] {client.name} warmup sent {warmup_kb} KB")

        # bulk on same stream
        total_bytes = payload_mb * 1024 * 1024
        chunk_bytes = chunk_kb * 1024
        base = (b"TorBoxSemanticValidation" * 1024)

        sent = 0
        chunks = 0
        while sent < total_bytes:
            n = min(chunk_bytes, total_bytes - sent)
            msg = (base * (n // len(base) + 1))[:n]

            await client.stream_write(circuit, stream, msg)

            sent += n
            chunks += 1
            if chunks % 32 == 0:
                print(f"[ClientRunner] {client.name} bulk progress: {sent / (1024 * 1024):.2f} MB")

            if inter_chunk_sleep_ms > 0:
                await asyncio.sleep(inter_chunk_sleep_ms / 1000)

        print(f"[ClientRunner] {client.name} bulk finished: {sent / (1024 * 1024):.2f} MB in {chunks} chunks")

        # graceful teardown
        with contextlib.suppress(Exception):
            await client.close_stream(circuit, stream)

        with contextlib.suppress(Exception):
            if hasattr(client, "close_circuit"):
                await client.close_circuit(circuit)

        await asyncio.sleep(0.2)
        print(f"[ClientRunner] {client.name} done (graceful teardown complete)")

    finally:
        with contextlib.suppress(Exception):
            await client.stop_protocol()

        if not proto_task.done():
            proto_task.cancel()

            with contextlib.suppress(asyncio.CancelledError):
                await proto_task


async def main():
    loop = asyncio.get_running_loop()
    max_workers = env_int("MAX_TLS_THREADS", 128)
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker"
        )
    )

    # Core config
    directory_addr = env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
    os.environ["DIRECTORY_ADDR"] = directory_addr

    node_addr = env_str("NODE_ADDR", "192.168.66.242")

    clients_per_batch = env_int("CLIENTS_PER_BATCH", 1)
    total_batches = env_int("TOTAL_BATCHES", 1)
    delay_between_batches = env_int("BATCH_DELAY", 2)

    # Workload config
    hop = env_int("HOPS", 3)
    target_host = env_str("TARGET_HOST", "192.168.66.243")
    target_port = env_int("TARGET_PORT", 8000)
    addr = (target_host, target_port)

    payload_mb = env_int("PAYLOAD_MB", 20)
    chunk_kb = env_int("CHUNK_KB", 32)
    warmup_kb = env_int("WARMUP_KB", 4)
    start_timeout_s = env_int("START_TIMEOUT_S", 30)
    inter_chunk_sleep_ms = env_int("INTER_CHUNK_SLEEP_MS", 0)

    print(f"[Config] DIRECTORY_ADDR={directory_addr}")
    print(f"[Config] NODE_ADDR={node_addr}")
    print(f"[Config] clients_per_batch={clients_per_batch} total_batches={total_batches}")
    print(f"[Config] target={addr} hop={hop}")
    print(f"[Config] payload_mb={payload_mb} chunk_kb={chunk_kb} warmup_kb={warmup_kb}")
    print(f"[Config] start_timeout_s={start_timeout_s} inter_chunk_sleep_ms={inter_chunk_sleep_ms}")
    print(f"[Config] max_tls_threads={max_workers}")

    client_index = 0
    all_tasks = []
    clients = []  # ★保存 client 以便 stop

    for batch in range(total_batches):
        print(f"[Main] Batch {batch + 1}/{total_batches}")

        for _ in range(clients_per_batch):
            name = f"client{client_index}"
            port = 9102 + client_index

            client = Tor_Client(name=name, host=node_addr, port=port, model="sim")
            clients.append(client)

            task = asyncio.create_task(
                run_one_client(
                    client=client,
                    addr=addr,
                    hop=hop,
                    payload_mb=payload_mb,
                    chunk_kb=chunk_kb,
                    warmup_kb=warmup_kb,
                    start_timeout_s=start_timeout_s,
                    inter_chunk_sleep_ms=inter_chunk_sleep_ms
                )
            )
            all_tasks.append(task)
            client_index += 1

        await asyncio.sleep(delay_between_batches)

    await asyncio.gather(*all_tasks, return_exceptions=True)

    # ★二次兜底 stop，防止 run_one_client 未执行到 finally
    for c in clients:
        try:
            await c.stop_protocol()
        except Exception as e:
            print("[Main] stop_protocol error:", e)

    await asyncio.sleep(0)
    print("[Main] All clients finished. Exiting.")


if __name__ == "__main__":
    asyncio.run(main())
