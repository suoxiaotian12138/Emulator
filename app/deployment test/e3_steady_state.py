"""Deployment test driver for E3 long-duration steady-state circuits and streams.

This script mirrors the tor-client flow of ``client_runner.py`` and encodes the
E3 requirements:

- run for 60 minutes with a fixed 2.0 s circuit launch cadence
- cap concurrent circuits at 3; pause launches when the cap is reached
- each circuit is 3 hops and sends 2 sequential streams (1 at a time)
- gap 200 ms between stream 1 and stream 2
- each stream sends a single 64 KB payload; no circuit or stream reuse
- no warmup window; all activity is measured

Randomness only affects payload contents; circuit construction uses the
``Tor_Client`` defaults and always requests a fresh circuit instance
(``prefer_new=True``). The scheduler is deterministic about launch cadence and
back-pressure, pausing when ``MAX_CONCURRENT_CIRCUITS`` circuits are active and
resuming once a slot is available.
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

from examples.Tor_simplified.Tor_Client import Tor_Client
from tools.Log.bus import EventBus
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# -------------------------------
# Workload constants (fixed by spec)
# -------------------------------
CIRCUIT_PERIOD_MS = 2000
TOTAL_DURATION_S = 60 * 60
STREAMS_PER_CIRCUIT = 2
STREAM_CONCURRENCY = 1
GAP_BETWEEN_STREAMS_MS = 200
PAYLOAD_BYTES_PER_STREAM = 64 * 1024
HOPS = 3
MAX_CONCURRENT_CIRCUITS = 3

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

    for stream_idx in range(STREAMS_PER_CIRCUIT):
        payload = rng.randbytes(payload_bytes)
        stream_label = f"{label}-stream{stream_idx + 1}"
        try:
            stream_uid, stream = await open_stream_on_circuit(client, circuit, addr)
        except Exception as exc:  # noqa: BLE001 - log and continue to next stream
            print(f"[{stream_label}] stream open failed: {exc}")
        else:
            try:
                await send_stream_payload(client, circuit, stream, payload, stream_uid)
            except Exception as exc:  # noqa: BLE001
                print(f"[{stream_label}] stream send error: {exc}")

        if stream_idx == 0:
            await asyncio.sleep(GAP_BETWEEN_STREAMS_MS / 1000)

    with contextlib.suppress(Exception):
        await client.close_circuit(circuit)


async def run_circuit_guarded(
    sem: asyncio.Semaphore,
    client: Tor_Client,
    circ_seq: int,
    addr: tuple[str, int],
    payload_bytes: int,
    rng: random.Random,
    label: str,
):
    try:
        await run_circuit(client, circ_seq, addr, payload_bytes, rng, label)
    finally:
        sem.release()


async def circuit_scheduler(
    client: Tor_Client,
    addr: tuple[str, int],
    payload_bytes: int,
    start_time: float,
    total_duration_s: int,
    period_ms: int,
    rng: random.Random,
    sem: asyncio.Semaphore,
):
    tasks: list[asyncio.Task] = []
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

        # Pause when concurrency cap is reached
        acquire_start = time.time()
        await sem.acquire()
        acquire_waited = time.time() - acquire_start > 0.001

        circ_seq += 1
        label = f"circ{circ_seq}"
        rng_for_circ = random.Random(rng.randint(0, 2**31 - 1))
        tasks.append(
            asyncio.create_task(
                run_circuit_guarded(
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
        if acquire_waited:
            next_launch = time.time() + period_ms / 1000
        else:
            next_launch += period_ms / 1000

    if tasks:
        await asyncio.gather(*tasks)


async def main():
    loop = asyncio.get_running_loop()
    log_dir = env_str("LOG_DIR", "exp/deployment/e3/logs")
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

    exp_label = env_str("EXP_LABEL", "E3_Steady_State")
    run_meta_path = log_dir_path / "run_meta.json"
    run_meta = {
        "started_at": time.time(),
        "exp_label": exp_label,
        "random_seed": seed,
        "log_dir": str(log_dir_path.resolve()),
        "streams_per_circuit": STREAMS_PER_CIRCUIT,
        "payload_bytes_per_stream": PAYLOAD_BYTES_PER_STREAM,
        "period_ms": CIRCUIT_PERIOD_MS,
        "total_duration_s": TOTAL_DURATION_S,
        "gap_between_streams_ms": GAP_BETWEEN_STREAMS_MS,
        "max_concurrent_circuits": MAX_CONCURRENT_CIRCUITS,
    }

    print(f"[Config] directory={directory_addr} target={addr} max_tls_threads={max_workers}")
    print(
        f"[Config] period={CIRCUIT_PERIOD_MS} ms hops={HOPS} streams/circuit={STREAMS_PER_CIRCUIT} "
        f"stream_concurrency={STREAM_CONCURRENCY} payload={PAYLOAD_BYTES_PER_STREAM / 1024:.0f} KB"
    )
    print(
        f"[Config] total_duration={TOTAL_DURATION_S}s gap_between_streams={GAP_BETWEEN_STREAMS_MS} ms "
        f"max_concurrent_circuits={MAX_CONCURRENT_CIRCUITS}"
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
        sem = asyncio.Semaphore(env_int("MAX_CONCURRENT_CIRCUITS", MAX_CONCURRENT_CIRCUITS))
        start_time = time.time()
        await circuit_scheduler(
            client,
            addr,
            PAYLOAD_BYTES_PER_STREAM,
            start_time,
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