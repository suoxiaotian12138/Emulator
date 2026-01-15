"""
Deployment test driver for E2 fixed-pacing circuits and streams
with epoch-based client lifecycle control.

This file is AUDIT-EQUIVALENT to the original fixed-pacing driver:
- circuit / stream scheduling logic is unchanged
- logging semantics are unchanged
- epoch ONLY wraps client lifetime
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
from typing import List, Optional, Tuple

from labeled_tor_client import LabeledTorClient
from resource_probe import ResourceProbe, VmContainerSampler
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ============================================================
# Workload constants (ORIGINAL)
# ============================================================

CIRCUIT_PERIOD_MS = 500
WARMUP_EPOCHS = 2
MEASURE_EPOCHS = 20
TOTAL_EPOCHS = WARMUP_EPOCHS + MEASURE_EPOCHS

STREAMS_PER_CIRCUIT = 2
STREAM_CONCURRENCY = 4
GAP_BETWEEN_STREAM_BATCHES_MS = 100
PAYLOAD_BYTES_PER_STREAM = 64 * 1024
HOPS = 3
MAX_CONCURRENT_CIRCUITS = 10

# ============================================================
# Epoch control (EPOCH ADD)
# ============================================================

MAX_EPOCHS = None          # None = run until TOTAL_EPOCHS
EPOCH_CIRCUITS = 5
EPOCH_COOLDOWN_S = 1.5

CLIENT_NAME_PREFIX = "client"
CLIENT_PORT_BASE = 9102

# ============================================================
# Helpers (ORIGINAL)
# ============================================================

def ensure_seed() -> int:
    seed_env = os.environ.get("RANDOM_SEED")
    if seed_env is None:
        seed_env = str(int(time.time()))
        os.environ["RANDOM_SEED"] = seed_env
    seed = int(seed_env)
    random.seed(seed)
    return seed


def build_writer(log_dir: str) -> AsyncJsonlWriter:
    writer = AsyncJsonlWriter(
        out_dir=log_dir,
        rotate_mb=50,
        batch_size=200,
        flush_every_ms=100,
    )
    writer.start()
    return writer


def env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)


def env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


def env_csv(key: str, default: str) -> List[str]:
    raw = env_str(key, default)
    return [p.strip() for p in raw.split(",") if p.strip()]

# ============================================================
# Stream / circuit helpers (ORIGINAL, UNCHANGED)
# ============================================================

async def open_stream_on_circuit(client: LabeledTorClient, circuit, addr: Tuple[str, int]):
    socket = client.socket_map.get(client.guard.addr, None)
    if socket is None:
        raise RuntimeError("no socket to guard")

    stream = circuit.create_stream()
    stream_id = stream.id
    stream_uid = f"{client.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time()*1e6)}"
    dst = f"{addr[0]}:{addr[1]}"
    client.stream_tracker.start(stream_uid, src=client.name, dst=dst)

    if stream_id is not None:
        client._sid2uid[stream_id] = stream_uid

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


async def send_stream_payload(client, circuit, stream, payload: bytes, stream_uid: str):
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
    client,
    circuit,
    addr,
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
        except Exception as exc:
            print(f"[{label}] stream open failed (attempt {attempts}): {exc}")
            continue

        successes += 1
        tasks.append(asyncio.create_task(
            send_stream_payload(client, circuit, stream, payload, stream_uid)
        ))

    if successes < batch_size:
        print(f"[{label}] launched {successes}/{batch_size} streams after {attempts} attempts")

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                print(f"[{label}] stream send error: {res}")


async def run_circuit(
    client,
    circ_seq: int,
    addr,
    payload_bytes: int,
    rng: random.Random,
    label: str,
):
    iso_key = f"circ-{circ_seq}"
    try:
        circuit = await client.circuit_mgr.get_or_build(
            iso_key,
            hops_count=HOPS,
            extend_routers=None,
            prefer_new=True,
        )
    except Exception as exc:
        print(f"[{label}] circuit build failed: {exc}")
        return

    client.circuit_mgr.mark_used(circuit)

    await run_stream_batch(
        client, circuit, addr, payload_bytes, STREAM_CONCURRENCY, rng, label
    )

    await asyncio.sleep(GAP_BETWEEN_STREAM_BATCHES_MS / 1000)

    await run_stream_batch(
        client, circuit, addr, payload_bytes, STREAM_CONCURRENCY, rng, label
    )

    with contextlib.suppress(Exception):
        await client.close_circuit(circuit)


async def limited_circuit(
    sem: asyncio.Semaphore,
    client,
    circ_seq: int,
    addr,
    payload_bytes: int,
    rng: random.Random,
    label: str,
):
    async with sem:
        await run_circuit(client, circ_seq, addr, payload_bytes, rng, label)

# ============================================================
# Scheduler (ORIGINAL LOGIC + EPOCH WRAP)
# ============================================================

async def circuit_scheduler_epoch(
    client: LabeledTorClient,
    *,
    addr,
    payload_bytes: int,
    phase: str,
    period_ms: int,
    rng: random.Random,
    sem: asyncio.Semaphore,
    epoch_circuits: int,
):
    """
    IDENTICAL to original circuit_scheduler except:
    - bounded by epoch_circuits
    """
    tasks: List[asyncio.Task] = []
    next_launch = time.time()
    circ_seq = 0

    while circ_seq < epoch_circuits:
        now = time.time()

        delay = next_launch - now
        if delay > 0:
            await asyncio.sleep(delay)

        circ_seq += 1
        label = f"{phase}-circ{circ_seq}"

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

# ============================================================
# Epoch wrapper (EPOCH ADD)
# ============================================================

async def run_epoch(
    *,
    writer: AsyncJsonlWriter,
    ratio_label: str,
    epoch_idx: int,
    phase: str,
    node_addr: str,
    port: int,
    addr,
    seed: int,
):
    client = LabeledTorClient(
        name=f"{CLIENT_NAME_PREFIX}{epoch_idx}",
        host=node_addr,
        port=port,
        model="sim",
        ratio_label=ratio_label,
        writer=writer,
    )
    client.attach_labeled_bus(role="client")

    proto_task = asyncio.create_task(client.start_protocol())
    try:
        await asyncio.wait_for(client.ready_to_send.wait(), timeout=30)

        rng = random.Random(seed + epoch_idx * 1000003)
        sem = asyncio.Semaphore(MAX_CONCURRENT_CIRCUITS)

        await circuit_scheduler_epoch(
            client,
            addr=addr,
            payload_bytes=PAYLOAD_BYTES_PER_STREAM,
            phase=phase,
            period_ms=CIRCUIT_PERIOD_MS,
            rng=rng,
            sem=sem,
            epoch_circuits=EPOCH_CIRCUITS,
        )
    finally:
        with contextlib.suppress(Exception):
            await client.stop_protocol()
        if not proto_task.done():
            proto_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await proto_task

# ============================================================
# Main (ORIGINAL STRUCTURE + EPOCH LOOP)
# ============================================================
async def wait_resource_logging_ready(probe, timeout_s: float = 60.0, poll_s: float = 0.2) -> None:
    """
    Gate execution until resource logging is actually ready.
    Tries multiple probe APIs for compatibility:
      - probe.wait_ready(timeout_s=...)
      - probe.ready / probe.connected flags
      - probe.ready_event / probe.connected_event asyncio.Event
      - best-effort: try a lightweight "sample" call if exists
    """
    deadline = time.monotonic() + timeout_s

    # 1) If probe exposes an awaitable wait_ready
    wait_ready = getattr(probe, "wait_ready", None)
    if callable(wait_ready):
        try:
            await wait_ready(timeout_s=timeout_s)
            return
        except TypeError:
            # Some implementations may not accept keyword
            await wait_ready(timeout_s)
            return

    # 2) If probe has an asyncio.Event-like
    for ev_name in ("ready_event", "connected_event"):
        ev = getattr(probe, ev_name, None)
        if ev is not None and hasattr(ev, "wait"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Resource logging not ready within {timeout_s}s (event: {ev_name})")
            await asyncio.wait_for(ev.wait(), timeout=remaining)
            return

    # 3) Poll boolean flags
    for flag_name in ("ready", "connected", "is_ready", "is_connected"):
        if hasattr(probe, flag_name):
            while time.monotonic() < deadline:
                try:
                    if bool(getattr(probe, flag_name)):
                        return
                except Exception:
                    pass
                await asyncio.sleep(poll_s)
            raise TimeoutError(f"Resource logging not ready within {timeout_s}s (flag: {flag_name})")

    # 4) Best-effort: try a lightweight sampling method if it exists
    for fn_name in ("snapshot", "sample", "get_snapshot", "collect_once"):
        fn = getattr(probe, fn_name, None)
        if callable(fn):
            while time.monotonic() < deadline:
                try:
                    res = fn()
                    # If it is async
                    if asyncio.iscoroutine(res):
                        await res
                    return
                except Exception:
                    await asyncio.sleep(poll_s)
            raise TimeoutError(f"Resource logging not ready within {timeout_s}s (method: {fn_name})")

    # 5) If we cannot detect readiness, do a short delay as last resort (but still gate)
    while time.monotonic() < deadline:
        await asyncio.sleep(poll_s)
        # No signal to check; we just wait out a minimal stabilization
        if time.monotonic() + 1.0 >= deadline:
            break

    raise TimeoutError(
        "Resource logging readiness could not be detected (no known API found). "
        "Please expose probe.ready/connected or an asyncio Event, or implement probe.wait_ready()."
    )

async def main():
    loop = asyncio.get_running_loop()

    ratio_label = "75%"
    default_log_dir = Path("exp") / "deployment" / "e2" / ratio_label / "logs"
    log_dir = Path(env_str("LOG_DIR", str(default_log_dir)))
    log_dir.mkdir(parents=True, exist_ok=True)

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
    writer = build_writer(str(log_dir))

    target_host = env_str("TARGET_HOST", "192.168.66.243")
    target_port = env_int("TARGET_PORT", 8000)
    addr = (target_host, target_port)

    exp_label = env_str("EXP_LABEL", "E2_Fixed_Pacing_Epoch")

    run_meta_path = log_dir / "run_meta.json"
    run_meta = {
        "started_at": time.time(),
        "exp_label": exp_label,
        "random_seed": seed,
        "ratio_label": ratio_label,
        "log_dir": str(log_dir.resolve()),
        "streams_per_circuit": STREAMS_PER_CIRCUIT,
        "payload_bytes_per_stream": PAYLOAD_BYTES_PER_STREAM,
        "period_ms": CIRCUIT_PERIOD_MS,
        "warmup_epochs": WARMUP_EPOCHS,
        "measure_epochs": MEASURE_EPOCHS,
        "total_epochs": TOTAL_EPOCHS,
        "max_concurrent_circuits": MAX_CONCURRENT_CIRCUITS,
        "epoch_circuits": EPOCH_CIRCUITS,
        "epoch_cooldown_s": EPOCH_COOLDOWN_S,
        "client_port_base": CLIENT_PORT_BASE,
    }

    print(f"[Config] directory={directory_addr} target={addr} max_tls_threads={max_workers}")
    total_epochs = env_int("TOTAL_EPOCHS", TOTAL_EPOCHS)
    warmup_epochs = env_int("WARMUP_EPOCHS", WARMUP_EPOCHS)
    print(f"[Config] epoch_circuits={EPOCH_CIRCUITS} cooldown={EPOCH_COOLDOWN_S}s total_epochs={total_epochs} warmup_epochs={warmup_epochs}")

    node_addr = env_str("NODE_ADDR", "192.168.66.242")

    vm_sampler: Optional[VmContainerSampler] = None
    if env_str("ENABLE_VM_SAMPLING", "1") != "0":
        vm_sampler = VmContainerSampler(
            env_str("VM_HOST", "192.168.66.10"),
            env_str("VM_USER", "root"),
            env_str("VM_PASS", "sf5538177"),
            env_csv("VM_CONTAINER_PREFIXES", "tor-guard,tor-middle,tor-exit"),
        )

    probe = ResourceProbe(
        writer,
        ratio_label,
        interval_s=float(os.environ.get("RESOURCE_SAMPLE_INTERVAL_S", "1.0")),
        vm_sampler=vm_sampler,
    )


    probe.start()
    await wait_resource_logging_ready(probe, timeout_s=float(os.environ.get("RESOURCE_READY_TIMEOUT_S", "60")))
    try:
        total_epochs = env_int("TOTAL_EPOCHS", TOTAL_EPOCHS)
        warmup_epochs = env_int("WARMUP_EPOCHS", WARMUP_EPOCHS)
        if warmup_epochs > total_epochs:
            warmup_epochs = total_epochs

        for epoch_idx in range(1, total_epochs + 1):
            if MAX_EPOCHS is not None and epoch_idx > MAX_EPOCHS:
                break

            phase = "warmup" if epoch_idx <= warmup_epochs else "measure"
            port = CLIENT_PORT_BASE + epoch_idx - 1

            await run_epoch(
                writer=writer,
                ratio_label=ratio_label,
                epoch_idx=epoch_idx,
                phase=phase,
                node_addr=node_addr,
                port=port,
                addr=addr,
                seed=seed,
            )

            if EPOCH_COOLDOWN_S > 0 and epoch_idx < total_epochs:
                await asyncio.sleep(EPOCH_COOLDOWN_S)
    finally:
        await probe.stop()
        await writer.stop()
        run_meta.update(
            {
                "finished_at": time.time(),
                "log_files": {k: str(p) for k, p in writer.files.items()},
            }
        )
        run_meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        print(f"[Main] run metadata written to {run_meta_path}")


if __name__ == "__main__":
    asyncio.run(main())
