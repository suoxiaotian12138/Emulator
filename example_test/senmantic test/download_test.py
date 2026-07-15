"""
Multi-user, multi-circuit, multi-stream realism test runner.

Behavior changes:
1) Add per-user max concurrent inflight streams (configurable).
2) Pre-stream wait is now a random interval within a range.
3) Remove "rounds". Use fixed run duration. Stop after duration expires.

For each user:
- Before starting a new stream, acquire a concurrency slot (semaphore).
- If full, wait until a slot is available.
- Once acquired, sleep a random interval.
- Then create a new stream, send payload, close stream.
- Finally release the slot.
- Keep doing this until run duration ends.
"""

import random
import asyncio
import concurrent.futures
import contextlib
import json
import os
import sys
import time
from pathlib import Path

from tools.Log.writer import AsyncJsonlWriter
from network_src.TorCore.Tor_Client import Tor_Client
from network_src.TorCore.Tor_Circuit import compute_isolation_key
from tools.Log.bus import EventBus

REALISTIC_DEFAULTS = {
    "USERS": "10",
    "CIRCUITS_PER_USER": "1",
    "STREAMS_PER_CIRCUIT": "1",  # kept for compatibility, but no longer used as a loop multiplier
    "LOG_DIR": "exp/e2/tor",
    "EXP_LABEL": "20mb",
    "PAYLOAD_MB": "1",

    # New: fixed duration (seconds). Example: 600 = 10 minutes
    "RUN_DURATION_S": "300",

    # New: wait range before starting each stream, in seconds
    # Example: "0.2,2.0" means sleep randomly in [0.2, 2.0]
    "WAIT_INTERVAL_RANGE_S": "2.0,5.0",

    # New: per-user max inflight streams (existing key kept, now actually enforced)
    "MAX_INFLIGHT_STREAMS_PER_USER": "1",
}


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


for key, value in REALISTIC_DEFAULTS.items():
    os.environ.setdefault(key, value)


if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)


def _env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


def _env_float(key: str, default: float) -> float:
    v = os.environ.get(key)
    return default if v is None else float(v)


def _parse_wait_range_s(value: str, default_min: float = 0.0, default_max: float = 0.0) -> tuple[float, float]:
    """
    Parse "a,b" into (min_s, max_s). Accept whitespace. If invalid, fallback to defaults.
    """
    if not value:
        return (default_min, default_max)
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if len(parts) != 2:
        return (default_min, default_max)
    try:
        a = float(parts[0])
        b = float(parts[1])
        lo = min(a, b)
        hi = max(a, b)
        if lo < 0:
            lo = 0.0
        if hi < 0:
            hi = 0.0
        return (lo, hi)
    except Exception:
        return (default_min, default_max)


async def _open_stream_on_circuit(client: Tor_Client, circuit, addr):
    await client.ready_to_send.wait()

    socket = client.socket_map.get(client.guard.addr, None)
    if socket is None:
        raise RuntimeError("no socket to guard")

    stream = circuit.create_stream()
    stream_id = stream.id
    stream_uid = f"{client.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
    dst = f"{addr[0]}:{addr[1]}"
    client.stream_tracker.start(stream_uid, src=client.name, dst=dst)

    if stream_id is not None:
        client._sid2uid[stream_id] = stream_uid

    try:
        connect_cell = stream.make_connect(addr)
        await socket.send_cell(connect_cell)
        await stream.wait_connect_ack()
        client.stream_tracker.mark_connected(stream_uid)
    except Exception:
        client.stream_tracker.set_status(stream_uid, "connect_fail")
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        raise

    return stream


async def _build_user_circuits_once(
    client: Tor_Client,
    addr,
    hop: int,
    circuits_per_user: int,
    start_timeout_s: int,
):
    await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

    if client.circuit_mgr.isolation_enabled:
        isolation_key = compute_isolation_key(addr[0], addr[1])
    else:
        isolation_key = "general"

    circuits = []
    for _ in range(circuits_per_user):
        circuit = await client.circuit_mgr.get_or_build(
            isolation_key,
            hops_count=hop,
            prefer_new=True,  # only at bootstrap
        )
        circuits.append(circuit)

    return circuits


async def _send_payload(
    client: Tor_Client,
    circuit,
    stream,
    payload_mb: int,
    chunk_kb: int,
    warmup_kb: int,
    inter_chunk_sleep_ms: int,
):
    if warmup_kb > 0:
        warmup = b"W" * (warmup_kb * 1024)
        await client.stream_write(circuit, stream, warmup)

    total_bytes = payload_mb * 1024 * 1024
    chunk_bytes = chunk_kb * 1024
    base = (b"TorBoxRealisticTest" * 1024)

    sent = 0
    while sent < total_bytes:
        n = min(chunk_bytes, total_bytes - sent)
        msg = (base * (n // len(base) + 1))[:n]
        await client.stream_write(circuit, stream, msg)
        sent += n

        if inter_chunk_sleep_ms > 0:
            await asyncio.sleep(inter_chunk_sleep_ms / 1000)


async def _one_stream_batch(
    *,
    client: Tor_Client,
    addr,
    circuits,
    payload_mb: int,
    chunk_kb: int,
    warmup_kb: int,
    start_timeout_s: int,
    inter_chunk_sleep_ms: int,
    wait_min_s: float,
    wait_max_s: float,
    sem: asyncio.Semaphore,
):
    """
    One "batch" equals one stream connect + payload send + close.
    The semaphore slot is acquired before calling this function.
    This function must release the semaphore in a finally block.
    """
    try:
        await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

        if wait_max_s > 0 or wait_min_s > 0:
            delay = random.uniform(wait_min_s, wait_max_s)
            if delay > 0:
                await asyncio.sleep(delay)

        # Choose a circuit (random gives more realism when multiple circuits exist)
        circuit = random.choice(circuits)
        client.circuit_mgr.mark_used(circuit)

        stream = await _open_stream_on_circuit(client, circuit, addr)
        try:
            await _send_payload(
                client,
                circuit,
                stream,
                payload_mb=payload_mb,
                chunk_kb=chunk_kb,
                warmup_kb=warmup_kb,
                inter_chunk_sleep_ms=inter_chunk_sleep_ms,
            )
        finally:
            with contextlib.suppress(Exception):
                await client.close_stream(circuit, stream)

    finally:
        sem.release()


async def _run_user_for_duration(
    *,
    client: Tor_Client,
    addr,
    circuits,
    payload_mb: int,
    chunk_kb: int,
    warmup_kb: int,
    start_timeout_s: int,
    inter_chunk_sleep_ms: int,
    run_duration_s: int,
    wait_min_s: float,
    wait_max_s: float,
    max_inflight_streams: int,
):
    await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

    sem = asyncio.Semaphore(max_inflight_streams)
    inflight_tasks: set[asyncio.Task] = set()

    end_ts = time.time() + run_duration_s

    def _track_done(t: asyncio.Task):
        inflight_tasks.discard(t)
        with contextlib.suppress(Exception):
            _ = t.result()

    while time.time() < end_ts:
        # Acquire a slot. If full, this awaits until a slot is released.
        await sem.acquire()

        # Stop scheduling new work if time is already up after waiting for slot.
        if time.time() >= end_ts:
            sem.release()
            break

        t = asyncio.create_task(
            _one_stream_batch(
                client=client,
                addr=addr,
                circuits=circuits,
                payload_mb=payload_mb,
                chunk_kb=chunk_kb,
                warmup_kb=warmup_kb,
                start_timeout_s=start_timeout_s,
                inter_chunk_sleep_ms=inter_chunk_sleep_ms,
                wait_min_s=wait_min_s,
                wait_max_s=wait_max_s,
                sem=sem,
            )
        )
        inflight_tasks.add(t)
        t.add_done_callback(_track_done)

        # Yield a bit to avoid starving the loop when wait range is 0.
        await asyncio.sleep(0)

    # Time is up. Wait all inflight tasks to finish.
    if inflight_tasks:
        await asyncio.gather(*list(inflight_tasks), return_exceptions=True)


async def main():
    loop = asyncio.get_running_loop()
    log_dir = _env_str("LOG_DIR", "exp/e2")
    exp_label = _env_str("EXP_LABEL", "e2")
    seed = ensure_seed()

    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)

    writer = build_writer(log_dir)
    meta_path = log_dir_path / "run_meta.json"
    run_meta = {
        "started_at": time.time(),
        "exp_label": exp_label,
        "random_seed": seed,
        "log_dir": str(log_dir_path.resolve()),
    }

    def bus_factory(node_name: str) -> EventBus:
        return EventBus(writer.emit_nowait, node_id=node_name, role="client")

    max_workers = _env_int("MAX_TLS_THREADS", 128)
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker",
        )
    )

    directory_addr = _env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
    os.environ["DIRECTORY_ADDR"] = directory_addr

    node_addr = _env_str("NODE_ADDR", "192.168.66.242")

    hop = _env_int("HOPS", 3)
    target_host = _env_str("TARGET_HOST", "192.168.66.243")
    target_port = _env_int("TARGET_PORT", 8000)
    addr = (target_host, target_port)

    payload_mb = _env_int("PAYLOAD_MB", 20)
    chunk_kb = _env_int("CHUNK_KB", 32)
    warmup_kb = _env_int("WARMUP_KB", 4)
    start_timeout_s = _env_int("START_TIMEOUT_S", 30)
    inter_chunk_sleep_ms = _env_int("INTER_CHUNK_SLEEP_MS", 0)

    users = _env_int("USERS", 1)
    circuits_per_user = _env_int("CIRCUITS_PER_USER", 1)

    run_duration_s = _env_int("RUN_DURATION_S", 600)
    wait_range_raw = _env_str("WAIT_INTERVAL_RANGE_S", "0.0,0.0")
    wait_min_s, wait_max_s = _parse_wait_range_s(wait_range_raw, 0.0, 0.0)
    max_inflight = _env_int("MAX_INFLIGHT_STREAMS_PER_USER", 8)

    print(f"[Config] DIRECTORY_ADDR={directory_addr}")
    print(f"[Config] NODE_ADDR={node_addr}")
    print(f"[Config] users={users} circuits_per_user={circuits_per_user}")
    print(f"[Config] target={addr} hop={hop}")
    print(f"[Config] payload_mb={payload_mb} chunk_kb={chunk_kb} warmup_kb={warmup_kb}")
    print(f"[Config] start_timeout_s={start_timeout_s} inter_chunk_sleep_ms={inter_chunk_sleep_ms}")
    print(f"[Config] max_tls_threads={max_workers}")
    print(f"[Config] run_duration_s={run_duration_s}")
    print(f"[Config] wait_interval_range_s={wait_min_s},{wait_max_s}")
    print(f"[Config] max_inflight_streams_per_user={max_inflight}")

    clients = []
    protocol_tasks = []
    client_circuits = {}

    try:
        # 1) Create all clients first
        for user_index in range(users):
            name = f"user{user_index}"
            port = 9102 + user_index

            client = Tor_Client(name=name, host=node_addr, port=port, model="sim")
            client.attach_bus(bus_factory(name))
            client.emit = client.event_bus.emit
            clients.append(client)
            protocol_tasks.append(asyncio.create_task(client.start_protocol()))

        # 2) Build circuits ONCE per client
        for client in clients:
            client_circuits[client] = await _build_user_circuits_once(
                client=client,
                addr=addr,
                hop=hop,
                circuits_per_user=circuits_per_user,
                start_timeout_s=start_timeout_s,
            )

        # 3) Each user runs independently for a fixed duration
        user_tasks = []
        for client in clients:
            user_tasks.append(
                asyncio.create_task(
                    _run_user_for_duration(
                        client=client,
                        addr=addr,
                        circuits=client_circuits[client],
                        payload_mb=payload_mb,
                        chunk_kb=chunk_kb,
                        warmup_kb=warmup_kb,
                        start_timeout_s=start_timeout_s,
                        inter_chunk_sleep_ms=inter_chunk_sleep_ms,
                        run_duration_s=run_duration_s,
                        wait_min_s=wait_min_s,
                        wait_max_s=wait_max_s,
                        max_inflight_streams=max_inflight,
                    )
                )
            )

        await asyncio.gather(*user_tasks, return_exceptions=True)

    finally:
        # (Optional) close circuits once, safely
        for client in clients:
            for c in client_circuits.get(client, []):
                with contextlib.suppress(Exception):
                    if hasattr(client, "close_circuit"):
                        await client.close_circuit(c)

        # stop protocols
        for client in clients:
            with contextlib.suppress(Exception):
                await client.stop_protocol()

        for task in protocol_tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        run_meta.update(
            {
                "finished_at": time.time(),
                "config": {
                    "directory_addr": directory_addr,
                    "node_addr": node_addr,
                    "users": users,
                    "circuits_per_user": circuits_per_user,
                    "hop": hop,
                    "payload_mb": payload_mb,
                    "chunk_kb": chunk_kb,
                    "warmup_kb": warmup_kb,
                    "start_timeout_s": start_timeout_s,
                    "inter_chunk_sleep_ms": inter_chunk_sleep_ms,
                    "run_duration_s": run_duration_s,
                    "wait_interval_range_s": [wait_min_s, wait_max_s],
                    "max_inflight_streams_per_user": max_inflight,
                },
                "log_files": {k: str(p) for k, p in writer.files.items()},
            }
        )

        meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        await writer.stop()
        print(f"[RealisticRunner] run metadata written to {meta_path}")

    return meta_path


if __name__ == "__main__":
    asyncio.run(main())
