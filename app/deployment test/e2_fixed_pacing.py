"""Deployment test driver for E2 fixed-pacing circuits and streams.

This script follows the tor-client execution style of ``client_runner.py``
and mirrors the E2 requirements:

- launch a new 3-hop circuit every 500 ms from the global start time
- first 2 minutes are warmup (not counted in stats), then 6 minutes counted
- each circuit immediately attempts to build, with no retries on failure
- upon successful build, send 4 streams in two concurrent batches (2 + 2)
- batches are separated by 100 ms; each stream sends a single 256 KB payload
- after all 4 streams finish (or fail), close the circuit immediately

Randomness only affects payload contents; circuit construction uses the
``Tor_Client`` defaults and always requests a fresh circuit instance
(``prefer_new=True``). The script is intentionally deterministic about launch
cadence and stream counts so repeated runs share the same timing profile.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import List

from examples.Tor_simplified.Tor_Client import Tor_Client
from tools.Log.bus import EventBus
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# -------------------------------
# Workload constants (fixed by spec)
# -------------------------------
CIRCUIT_PERIOD_MS = 500
WARMUP_DURATION_S = 2 * 60
MEASURE_DURATION_S = 6 * 60
TOTAL_DURATION_S = WARMUP_DURATION_S + MEASURE_DURATION_S
STREAMS_PER_CIRCUIT = 4
STREAM_CONCURRENCY = 2
GAP_BETWEEN_STREAM_BATCHES_MS = 100
PAYLOAD_BYTES_PER_STREAM = 256 * 1024
HOPS = 3
MAX_CONCURRENT_CIRCUITS = 10

# -------------------------------
# Helpers
# -------------------------------

def ensure_seed() -> int:
    seed_env = os.environ.get("RANDOM_SEED")
    if seed_env is None:
        seed_env = str(int(time.time()))
        os.environ["RANDOM_SEED"] = seed_env
    seed = int(seed_env)
    random.seed(seed)
    return seed


def build_writer(log_dir: str) -> AsyncJsonlWriter:
    writer = AsyncJsonlWriter(out_dir=log_dir, rotate_mb=50, batch_size=200, flush_every_ms=100)
    writer.start()
    return writer


def env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)


def env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


async def open_stream_on_circuit(client: Tor_Client, circuit, addr: tuple[str, int]):
    socket = client.socket_map.get(client.guard.addr, None)
    if socket is None:
        raise RuntimeError("no socket to guard")

    stream = circuit.create_stream()

    stream_id = stream.id
    stream_uid = f"{client.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
    dst = f"{addr[0]}:{addr[1]}"
    client.stream_tracker.start(stream_uid, src=client.name, dst=dst)

    if stream_id is not None:
        client._sid2uid[stream_id] = stream_uid  # noqa: SLF001

    try:
        connect_cell = stream.make_connect(addr)
        await socket.send_cell(connect_cell)
        await stream.wait_connect_ack()
    except Exception:
        client.stream_tracker.set_status(stream_uid, "connect_fail")
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        raise

    return stream_uid, stream


async def send_stream_payload(client: Tor_Client, circuit, stream, payload: bytes, stream_uid: str):
    try:
        await client.stream_write(circuit, stream, payload)
        client.stream_tracker.set_status(stream_uid, "ok")
    except Exception:
        client.stream_tracker.set_status(stream_uid, "error")
        raise
    finally:
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        with contextlib.suppress(Exception):
            await client.close_stream(circuit, stream)


async def run_stream_batch(
    client: Tor_Client,
    circuit,
    addr: tuple[str, int],
    payload_bytes: int,
    batch_size: int,
    rng: random.Random,
    label: str,
):
    tasks: List[asyncio.Task] = []
    successes = 0
    attempts = 0
    max_attempts = max(batch_size * 3, batch_size + 1)
    while successes < batch_size and attempts < max_attempts:
        attempts += 1
        payload = rng.randbytes(payload_bytes)
        try:
            stream_uid, stream = await open_stream_on_circuit(client, circuit, addr)
        except Exception as exc:  # noqa: BLE001 - log and continue
            print(f"[{label}] stream open failed (attempt {attempts}): {exc}")
            continue

        successes += 1
        tasks.append(asyncio.create_task(send_stream_payload(client, circuit, stream, payload, stream_uid)))

    if successes < batch_size:
        print(f"[{label}] launched {successes}/{batch_size} streams after {attempts} attempts")

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                print(f"[{label}] stream send error: {res}")


async def run_circuit(
    client: Tor_Client,
    circ_seq: int,
    addr: tuple[str, int],
    payload_bytes: int,
    rng: random.Random,
    label: str,
):
    iso_key = f"circ-{circ_seq}"
    try:
        circuit = await client.circuit_mgr.get_or_build(iso_key, hops_count=HOPS, extend_routers=None, prefer_new=True)
    except Exception as exc:  # noqa: BLE001
        print(f"[{label}] circuit build failed: {exc}")
        return

    client.circuit_mgr.mark_used(circuit)

    # First batch
    await run_stream_batch(
        client,
        circuit,
        addr,
        payload_bytes,
        STREAM_CONCURRENCY,
        rng,
        label,
    )

    await asyncio.sleep(GAP_BETWEEN_STREAM_BATCHES_MS / 1000)

    # Second batch
    await run_stream_batch(
        client,
        circuit,
        addr,
        payload_bytes,
        STREAM_CONCURRENCY,
        rng,
        label,
    )

    with contextlib.suppress(Exception):
        await client.close_circuit(circuit)


async def circuit_scheduler(
    client: Tor_Client,
    addr: tuple[str, int],
    payload_bytes: int,
    start_time: float,
    warmup_duration_s: int,
    total_duration_s: int,
    period_ms: int,
    rng: random.Random,
    sem: asyncio.Semaphore,
):
    tasks: List[asyncio.Task] = []
    next_launch = start_time
    circ_seq = 0
    end_time = start_time + total_duration_s

    while True:
        now = time.time()
        if now >= end_time:
            break

        delay = next_launch - now
        if delay > 0:
            await asyncio.sleep(delay)

        circ_seq += 1
        label_prefix = "warmup" if (time.time() - start_time) < warmup_duration_s else "measure"
        label = f"{label_prefix}-circ{circ_seq}"
        rng_for_circ = random.Random(rng.randint(0, 2**31 - 1))
        tasks.append(
            asyncio.create_task(
                limited_circuit(
                    sem,
                    client,
                    circ_seq,
                    addr,
                    payload_bytes,
                    rng_for_circ,
                    label,
                )
            )
        )
        next_launch += period_ms / 1000

    if tasks:
        await asyncio.gather(*tasks)


async def limited_circuit(
    sem: asyncio.Semaphore,
    client: Tor_Client,
    circ_seq: int,
    addr: tuple[str, int],
    payload_bytes: int,
    rng: random.Random,
    label: str,
):
    async with sem:
        await run_circuit(client, circ_seq, addr, payload_bytes, rng, label)


async def main():
    loop = asyncio.get_running_loop()
    log_dir = env_str("LOG_DIR", "exp/deployment/e2/logs")
    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)

    directory_addr = env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
    os.environ["DIRECTORY_ADDR"] = directory_addr

    max_workers = env_int("MAX_TLS_THREADS", 128)
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker",
        )
    )

    seed = ensure_seed()
    writer = build_writer(log_dir)

    target_host = env_str("TARGET_HOST", "192.168.66.243")
    target_port = env_int("TARGET_PORT", 8000)
    addr = (target_host, target_port)

    exp_label = env_str("EXP_LABEL", "E2_Fixed_Pacing")
    run_meta_path = log_dir_path / "run_meta.json"
    run_meta = {
        "started_at": time.time(),
        "exp_label": exp_label,
        "random_seed": seed,
        "log_dir": str(log_dir_path.resolve()),
        "streams_per_circuit": STREAMS_PER_CIRCUIT,
        "payload_bytes_per_stream": PAYLOAD_BYTES_PER_STREAM,
        "period_ms": CIRCUIT_PERIOD_MS,
        "warmup_duration_s": WARMUP_DURATION_S,
        "measure_duration_s": MEASURE_DURATION_S,
        "max_concurrent_circuits": MAX_CONCURRENT_CIRCUITS,
    }

    print(f"[Config] directory={directory_addr} target={addr} max_tls_threads={max_workers}")
    print(
        f"[Config] period={CIRCUIT_PERIOD_MS} ms hops={HOPS} streams/circuit={STREAMS_PER_CIRCUIT} "
        f"stream_concurrency={STREAM_CONCURRENCY} payload={PAYLOAD_BYTES_PER_STREAM / 1024:.0f} KB"
    )
    print(
        f"[Config] warmup={WARMUP_DURATION_S}s measure={MEASURE_DURATION_S}s gap_batch={GAP_BETWEEN_STREAM_BATCHES_MS} ms"
        f" max_concurrent_circuits={MAX_CONCURRENT_CIRCUITS}"
    )

    name = env_str("CLIENT_NAME", "client0")
    node_addr = env_str("NODE_ADDR", "192.168.66.242")
    port = env_int("CLIENT_PORT", 9102)
    client = Tor_Client(name=name, host=node_addr, port=port, model="sim")

    def bus_factory(node_name: str) -> EventBus:
        return EventBus(writer.emit_nowait, node_id=node_name, role="client")

    client.attach_bus(bus_factory(name))
    client.emit = client.event_bus.emit

    proto_task = asyncio.create_task(client.start_protocol())
    try:
        await asyncio.wait_for(client.ready_to_send.wait(), timeout=env_int("START_TIMEOUT_S", 30))
        rng = random.Random(seed)
        start_time = time.time()
        sem = asyncio.Semaphore(env_int("MAX_CONCURRENT_CIRCUITS", MAX_CONCURRENT_CIRCUITS))
        await circuit_scheduler(
            client,
            addr,
            PAYLOAD_BYTES_PER_STREAM,
            start_time,
            WARMUP_DURATION_S,
            TOTAL_DURATION_S,
            CIRCUIT_PERIOD_MS,
            rng,
            sem,
        )
    finally:
        with contextlib.suppress(Exception):
            await client.stop_protocol()
        if not proto_task.done():
            proto_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await proto_task
        await writer.stop()
        run_meta.update(
            {
                "finished_at": time.time(),
                "log_files": {k: str(p) for k, p in writer.files.items()},
            }
        )
        run_meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        print(f"[Main] run metadata written to {run_meta_path}")
    return run_meta_path


if __name__ == "__main__":
    asyncio.run(main())