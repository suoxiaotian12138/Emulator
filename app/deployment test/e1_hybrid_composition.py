"""Deployment test driver for E1 Hybrid Composition Coverage.

This script is based on ``app/senmantic test/client_runner.py`` but adapts
it to the E1 workload: concurrent "users" build circuits and send streams
through ``PatternedTorClient`` instances so each run can exercise explicit
TorBox/non-TorBox hop patterns. It avoids the earlier manifest-only
approach; every circuit and stream is actually opened via the client.

Workload constants (non-random):
- concurrent users: 20
- circuits per user: 10 (200 per run)
- streams per circuit: 4, with concurrency 2 (two batches)
- payload per stream: 256 KB (1 MB per circuit)
- hop count: 3
- jitter between user starts: 50 ms * user_index
- gap between circuits: 200 ms
- gap between stream batches: 100 ms

Random seed comes from ``RANDOM_SEED`` (default: current timestamp) and is
used only for payload bytes; circuit building relies on ``Tor_Client``
defaults so all circuits/streams are created by tor_client itself.
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

from patterned_tor_client import Pattern, PatternedTorClient
from examples.Tor_simplified.Tor_Client import Tor_Client
from tools.Log.bus import EventBus
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# -------------------------------
# Workload constants (fixed by spec)
# -------------------------------
CONCURRENT_USERS = 10
CIRCUITS_PER_USER =1
STREAMS_PER_CIRCUIT = 10
STREAM_CONCURRENCY = 2
PAYLOAD_BYTES_PER_STREAM = 64 * 1024
HOPS = 3
USER_START_JITTER_MS = 500
GAP_BETWEEN_CIRCUITS_MS = 200
GAP_BETWEEN_STREAM_BATCHES_MS = 100

# -------------------------------
# Pattern ordering (fixed, no sampling)
# -------------------------------
# The spec requires running all eight hop patterns in a fixed order without
# sampling/selection. Keep this explicit ordering aligned with the pattern list
# provided in the experiment description.
PATTERN_ORDER: list[Pattern] = [
    "RTR",
    "TTT",
    "RRR",
    "TRT",
    "RRT",
    "RTT",
    "TRR",
    "TTR",
]


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


def log_circuit(
    writer: AsyncJsonlWriter,
    *,
    run_id: str,
    pattern: Pattern,
    user_id: int,
    circuit_seq: int,
    circuit_id: int | None,

    t_circ_start: float,
    t_build_start: float | None = None,
    t_create2_send: float | None = None,
    t_circ_built: float | None = None,

    t_circ_end: float,
    circ_status: str,
    fail_stage: str | None = None,
    err: Exception | None = None,
):
    err_type = type(err).__name__ if err else None
    err_msg = str(err) if err else None
    writer.emit_nowait(
        "circuits",
        {
            "log_type": "circuit",
            "run_id": run_id,
            "pattern": pattern,
            "user_id": user_id,
            "circuit_seq": circuit_seq,
            "circuit_id": circuit_id,
            "t_circ_start": t_circ_start,
            "t_build_start": t_build_start,
            "t_create2_send": t_create2_send,
            "t_circ_built": t_circ_built,
            "t_circ_end": t_circ_end,
            "circ_status": circ_status,
            "fail_stage": fail_stage,
            "err_type": err_type,
            "err_msg": err_msg,
        },
    )


def log_stream(
    writer: AsyncJsonlWriter,
    *,
    run_id: str,
    pattern: Pattern,
    user_id: int,
    circuit_seq: int,
    circuit_id: int | None,
    stream_seq: int,
    batch_id: int,
    payload_bytes: int,
    t_stream_start: float,
    t_stream_connected: float | None,
    t_stream_write_done: float | None,
    t_stream_end: float,
    stream_status: str,
    err: Exception | None = None,
):
    err_type = type(err).__name__ if err else None
    err_msg = str(err) if err else None
    writer.emit_nowait(
        "streams",
        {
            "log_type": "stream",
            "run_id": run_id,
            "pattern": pattern,
            "user_id": user_id,
            "circuit_seq": circuit_seq,
            "circuit_id": circuit_id,
            "stream_seq": stream_seq,
            "batch_id": batch_id,
            "payload_bytes": payload_bytes,
            "t_stream_start": t_stream_start,
            "t_stream_connected": t_stream_connected,
            "t_stream_write_done": t_stream_write_done,
            "t_stream_end": t_stream_end,
            "stream_status": stream_status,
            "err_type": err_type,
            "err_msg": err_msg,
        },
    )


def env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)


def env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


async def open_stream_on_circuit(client: Tor_Client, circuit, addr: tuple[str, int]):
    socket = getattr(client, "get_active_guard_socket", None)
    if callable(socket):
        socket = socket(circuit)
    else:
        socket = client.socket_map.get(getattr(getattr(client, "guard", None), "addr", None), None)
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
    client: PatternedTorClient,
    user_index: int,
    circ_index: int,
    addr: tuple[str, int],
    payload_bytes: int,
    gap_between_batches_ms: int,
    stream_concurrency: int,
    rng: random.Random,
    *,
    pattern: Pattern,
    run_id: str,
    writer: AsyncJsonlWriter,
):
    iso_key = f"user{user_index}-circ{circ_index}"
    t_circ_start = time.perf_counter()
    circ_status = "build_fail"
    fail_stage: str | None = "build"
    build_exc: Exception | None = None
    circuit_id: int | None = None
    circuit = None

    # Will be filled on success
    t_circ_built: float | None = None
    t_build_start: float | None = None
    t_create2_send: float | None = None
    stream_error: Exception | None = None
    stream_fail_stage: str | None = None

    try:
        circuit = await client.build_circuit_by_pattern(
            pattern,
            hops_count=HOPS,
            extend_routers=None,
            isolation_key=iso_key,
            prefer_new=True,
        )
        circuit_id = getattr(circuit, "id", None)
        circ_status = "built_ok"
        fail_stage = None
    except Exception as exc:  # noqa: BLE001
        build_exc = exc
        log_circuit(
            writer,
            run_id=run_id,
            pattern=pattern,
            user_id=user_index,
            circuit_seq=circ_index,
            circuit_id=circuit_id,
            t_circ_start=t_circ_start,
            t_build_start=None,
            t_create2_send=None,
            t_circ_built=None,
            t_circ_end=time.perf_counter(),
            circ_status=circ_status,
            fail_stage=fail_stage,
            err=build_exc,
        )
        return

    # Mark used and timestamp build completion
    client.circuit_mgr.mark_used(circuit)
    t_circ_built = time.perf_counter()

    # Pull precise build-stage timestamps from the circuit object
    t_build_start = getattr(circuit, "build_start_ts", None)
    t_create2_send = getattr(circuit, "create2_send_ts", None)

    streams_left = STREAMS_PER_CIRCUIT
    stream_seq = 1
    batch_id = 1

    while streams_left > 0:
        batch = min(stream_concurrency, streams_left)
        tasks = []
        attempted = 0

        for _ in range(batch):
            payload = rng.randbytes(payload_bytes)
            t_stream_start = time.perf_counter()
            try:
                stream_uid, stream = await open_stream_on_circuit(client, circuit, addr)
                t_stream_connected = time.perf_counter()
            except Exception as exc:  # noqa: BLE001
                stream_error = stream_error or exc
                stream_fail_stage = stream_fail_stage or "stream_open"
                log_stream(
                    writer,
                    run_id=run_id,
                    pattern=pattern,
                    user_id=user_index,
                    circuit_seq=circ_index,
                    circuit_id=circuit_id,
                    stream_seq=stream_seq,
                    batch_id=batch_id,
                    payload_bytes=payload_bytes,
                    t_stream_start=t_stream_start,
                    t_stream_connected=None,
                    t_stream_write_done=None,
                    t_stream_end=time.perf_counter(),
                    stream_status="connect_fail",
                    err=exc,
                )
                attempted += 1
                stream_seq += 1
                continue

            async def run_stream_task(
                seq: int,
                batch: int,
                stream_obj,
                start_ts: float,
                connected_ts: float,
                payload_bytes_inner: int,
                stream_uid_inner: str,
            ):
                nonlocal stream_error, stream_fail_stage
                try:
                    await client.stream_write(circuit, stream_obj, payload)
                    t_write_done = time.perf_counter()
                    stream_status = "ok"
                    err: Exception | None = None
                except Exception as exc_inner:  # noqa: BLE001
                    stream_status = "write_fail"
                    err = exc_inner
                    stream_error = stream_error or exc_inner
                    stream_fail_stage = stream_fail_stage or "stream_xfer"
                    t_write_done = None
                finally:
                    t_end = time.perf_counter()
                    log_stream(
                        writer,
                        run_id=run_id,
                        pattern=pattern,
                        user_id=user_index,
                        circuit_seq=circ_index,
                        circuit_id=circuit_id,
                        stream_seq=seq,
                        batch_id=batch,
                        payload_bytes=payload_bytes_inner,
                        t_stream_start=start_ts,
                        t_stream_connected=connected_ts,
                        t_stream_write_done=t_write_done,
                        t_stream_end=t_end,
                        stream_status=stream_status,
                        err=err,
                    )
                    with contextlib.suppress(Exception):
                        await client.close_stream(circuit, stream_obj)

            task = asyncio.create_task(
                run_stream_task(
                    stream_seq,
                    batch_id,
                    stream,
                    t_stream_start,
                    t_stream_connected,
                    payload_bytes,
                    stream_uid,
                )
            )
            tasks.append(task)
            attempted += 1
            stream_seq += 1

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        streams_left -= attempted
        batch_id += 1
        if streams_left > 0:
            await asyncio.sleep(gap_between_batches_ms / 1000)

    t_circ_end = time.perf_counter()
    if stream_error:
        circ_status = "aborted"
        fail_stage = stream_fail_stage

    # IMPORTANT: write the extracted timestamps (not None)
    log_circuit(
        writer,
        run_id=run_id,
        pattern=pattern,
        user_id=user_index,
        circuit_seq=circ_index,
        circuit_id=circuit_id,
        t_circ_start=t_circ_start,
        t_build_start=t_build_start,
        t_create2_send=t_create2_send,
        t_circ_built=t_circ_built,
        t_circ_end=t_circ_end,
        circ_status=circ_status,
        fail_stage=fail_stage,
        err=stream_error,
    )

    with contextlib.suppress(Exception):
        await client.close_circuit(circuit)


async def run_one_user(
    client: PatternedTorClient,
    user_index: int,
    pattern: Pattern,
    run_id: str,
    addr: tuple[str, int],
    payload_bytes: int,
    gap_between_circuits_ms: int,
    gap_between_batches_ms: int,
    stream_concurrency: int,
    writer: AsyncJsonlWriter,
    pattern_seed_offset: int,
):


    rng = random.Random(int(os.environ.get("RANDOM_SEED", "0")) + pattern_seed_offset + user_index)

    jitter = user_index * USER_START_JITTER_MS / 1000
    await asyncio.sleep(jitter)

    for circ_index in range(CIRCUITS_PER_USER):
        try:
            await run_circuit(
                client,
                user_index,
                circ_index,
                addr,
                payload_bytes,
                gap_between_batches_ms,
                stream_concurrency,
                rng,
                pattern=pattern,
                run_id=run_id,
                writer=writer,
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[User {user_index}] circuit {circ_index} failed: {exc}")
        await asyncio.sleep(gap_between_circuits_ms / 1000)


async def run_pattern(
    pattern: Pattern,
    pattern_index: int,
    log_dir_base: Path,
    writer_factory,
    addr: tuple[str, int],
    max_workers: int,
    exp_label: str,
    seed: int,
    clients: list[PatternedTorClient],
):
    log_dir_path = log_dir_base / pattern
    log_dir_path.mkdir(parents=True, exist_ok=True)

    writer = writer_factory(str(log_dir_path))
    run_start_ts = time.time()
    run_id = f"{exp_label}-{pattern}-seed{seed}-t{int(run_start_ts)}"
    run_meta_path = log_dir_path / "run_meta.json"
    run_meta = {
        "started_at": run_start_ts,
        "exp_label": exp_label,
        "random_seed": seed,
        "run_id": run_id,
        "log_dir": str(log_dir_path.resolve()),
        "users": CONCURRENT_USERS,
        "circuits_per_user": CIRCUITS_PER_USER,
        "streams_per_circuit": STREAMS_PER_CIRCUIT,
        "payload_bytes_per_stream": PAYLOAD_BYTES_PER_STREAM,
        "pattern": pattern,
        "pattern_index": pattern_index,
        "max_tls_threads": max_workers,
        "target": f"{addr[0]}:{addr[1]}",
    }

    print(f"[Pattern {pattern}] starting run: logs at {log_dir_path}")

    tasks = [
        asyncio.create_task(
            run_one_user(
                client=clients[i],
                user_index=i,
                pattern=pattern,
                run_id=run_id,
                addr=addr,
                payload_bytes=PAYLOAD_BYTES_PER_STREAM,
                gap_between_circuits_ms=GAP_BETWEEN_CIRCUITS_MS,
                gap_between_batches_ms=GAP_BETWEEN_STREAM_BATCHES_MS,
                stream_concurrency=STREAM_CONCURRENCY,
                writer=writer,
                pattern_seed_offset=pattern_index * 1000,
            )
        )
        for i in range(CONCURRENT_USERS)
    ]

    try:
        await asyncio.gather(*tasks)
    finally:
        await writer.stop()
        run_meta.update(
            {
                "finished_at": time.time(),
                "log_files": {k: str(p) for k, p in writer.files.items()},
            }
        )
        run_meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        print(f"[Pattern {pattern}] run metadata written to {run_meta_path}")
    return run_meta_path


async def main():
    loop = asyncio.get_running_loop()
    log_dir = env_str("LOG_DIR", "exp/deployment/e1/logs")
    log_dir_base = Path(log_dir)
    log_dir_base.mkdir(parents=True, exist_ok=True)

    # Respect client_runner defaults for networking knobs
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
    target_host = env_str("TARGET_HOST", "192.168.66.243")
    target_port = env_int("TARGET_PORT", 8000)
    addr = (target_host, target_port)

    exp_label = env_str("EXP_LABEL", "E1_Hybrid_Composition")

    print(f"[Config] directory={directory_addr} target={addr} max_tls_threads={max_workers}")
    print(
        f"[Config] users={CONCURRENT_USERS} circuits/user={CIRCUITS_PER_USER} streams/circuit={STREAMS_PER_CIRCUIT} "
        f"stream_concurrency={STREAM_CONCURRENCY} payload={PAYLOAD_BYTES_PER_STREAM / 1024:.0f} KB"
    )
    print(
        f"[Config] jitter={USER_START_JITTER_MS} ms gap_circ={GAP_BETWEEN_CIRCUITS_MS} ms "
        f"gap_batch={GAP_BETWEEN_STREAM_BATCHES_MS} ms"
    )

    node_addr = env_str("NODE_ADDR", "192.168.66.242")
    clients: list[PatternedTorClient] = []
    proto_tasks: list[asyncio.Task] = []

    try:
        for i in range(CONCURRENT_USERS):
            name = f"client{i}"
            port = 9102 + i
            client = PatternedTorClient(name=name, host=node_addr, port=port, model="sim")

            def bus_factory(node_name: str) -> EventBus:
                return EventBus(lambda *_args, **_kwargs: None, node_id=node_name, role="client")

            client.attach_bus(bus_factory(name))
            client.emit = client.event_bus.emit
            clients.append(client)

            proto_task = asyncio.create_task(client.start_protocol())
            proto_tasks.append(proto_task)

        for client in clients:
            await asyncio.wait_for(client.ready_to_send.wait(), timeout=env_int("START_TIMEOUT_S", 30))

        patterns = PATTERN_ORDER
        meta_paths = []

        for idx, pattern in enumerate(patterns):
            meta_path = await run_pattern(
                pattern=pattern,
                pattern_index=idx,
                log_dir_base=log_dir_base,
                writer_factory=build_writer,
                addr=addr,
                max_workers=max_workers,
                exp_label=exp_label,
                seed=seed,
                clients=clients,
            )
            meta_paths.append(str(meta_path))

        print(f"[Main] completed patterns: {', '.join(patterns)}")
        return meta_paths
    finally:
        for client in clients:
            with contextlib.suppress(Exception):
                await client.stop_protocol()
        for task in proto_tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task


if __name__ == "__main__":
    asyncio.run(main())