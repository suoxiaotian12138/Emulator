"""Multi-user, multi-circuit, multi-stream realism test runner.

This script extends the semantic/client runner flow so each user can open
multiple circuits, multiple streams per circuit, and run for multiple rounds.
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

from examples.Tor_simplified.Tor_Client import Tor_Client
from examples.Tor_simplified.Tor_Circuit import compute_isolation_key
from tools.Log.bus import EventBus



REALISTIC_DEFAULTS = {
    "USERS": "20",
    "CIRCUITS_PER_USER": "1",
    "STREAMS_PER_CIRCUIT": "1",
    "TOTAL_ROUNDS": "100",
    "ROUND_INTERVAL_S": "2",
    "LOG_DIR": "exp/e2/torbox",
    "EXP_LABEL": "20mb",
    "PAYLOAD_MB": "1",
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

async def _run_user_round_on_existing_circuits(
    client: Tor_Client,
    addr,
    circuits,
    streams_per_circuit: int,
    payload_mb: int,
    chunk_kb: int,
    warmup_kb: int,
    start_timeout_s: int,
    inter_chunk_sleep_ms: int,
    round_idx: int,
    total_rounds: int,
):
    await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

    for circuit_idx, circuit in enumerate(circuits):
        for stream_idx in range(streams_per_circuit):
            client.circuit_mgr.mark_used(circuit)

            stream = await _open_stream_on_circuit(client, circuit, addr)
            await _send_payload(
                client,
                circuit,
                stream,
                payload_mb=payload_mb,
                chunk_kb=chunk_kb,
                warmup_kb=warmup_kb,
                inter_chunk_sleep_ms=inter_chunk_sleep_ms,
            )

            with contextlib.suppress(Exception):
                await client.close_stream(circuit, stream)

        print(
            f"[RealisticRunner] {client.name} round {round_idx + 1}/{total_rounds} "
            f"circuit {circuit_idx + 1}/{len(circuits)} completed"
        )



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
    streams_per_circuit = _env_int("STREAMS_PER_CIRCUIT", 1)
    total_rounds = _env_int("TOTAL_ROUNDS", 1)
    round_interval_s = _env_int("ROUND_INTERVAL_S", 0)

    print(f"[Config] DIRECTORY_ADDR={directory_addr}")
    print(f"[Config] NODE_ADDR={node_addr}")
    print(f"[Config] users={users} circuits_per_user={circuits_per_user}")
    print(f"[Config] streams_per_circuit={streams_per_circuit} total_rounds={total_rounds}")
    print(f"[Config] round_interval_s={round_interval_s}")
    print(f"[Config] target={addr} hop={hop}")
    print(f"[Config] payload_mb={payload_mb} chunk_kb={chunk_kb} warmup_kb={warmup_kb}")
    print(f"[Config] start_timeout_s={start_timeout_s} inter_chunk_sleep_ms={inter_chunk_sleep_ms}")
    print(f"[Config] max_tls_threads={max_workers}")

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
        client_circuits = {}
        for client in clients:
            client_circuits[client] = await _build_user_circuits_once(
                client=client,
                addr=addr,
                hop=hop,
                circuits_per_user=circuits_per_user,
                start_timeout_s=start_timeout_s,
            )

        # 3) Rounds: only open NEW streams on existing circuits
        for round_idx in range(total_rounds):
            round_tasks = [
                asyncio.create_task(
                    _run_user_round_on_existing_circuits(
                        client=client,
                        addr=addr,
                        circuits=client_circuits[client],
                        streams_per_circuit=streams_per_circuit,
                        payload_mb=payload_mb,
                        chunk_kb=chunk_kb,
                        warmup_kb=warmup_kb,
                        start_timeout_s=start_timeout_s,
                        inter_chunk_sleep_ms=inter_chunk_sleep_ms,
                        round_idx=round_idx,
                        total_rounds=total_rounds,
                    )
                )
                for client in clients
            ]
            await asyncio.gather(*round_tasks, return_exceptions=True)

            if round_idx < total_rounds - 1 and round_interval_s > 0:
                await asyncio.sleep(round_interval_s)

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
                    "streams_per_circuit": streams_per_circuit,
                    "total_rounds": total_rounds,
                    "round_interval_s": round_interval_s,
                    "hop": hop,
                    "payload_mb": payload_mb,
                    "chunk_kb": chunk_kb,
                    "warmup_kb": warmup_kb,
                    "start_timeout_s": start_timeout_s,
                    "inter_chunk_sleep_ms": inter_chunk_sleep_ms,
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