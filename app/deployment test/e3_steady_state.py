"""
Experiment E3: Long-Run Stability (混合部署的长期稳态健康度)

Based on E2 fixed pacing driver, but modified to:
- Run continuously for a long window (default 60 minutes)
- Introduce new circuits at a slow, fixed cadence
- Keep per-circuit load intentionally light (few streams, small payload)
- Strictly cap concurrent circuits to stay non-saturated
- Emit time-series "stability" heartbeat records for drift/leak diagnosis

Logs:
- stream / circuit logs are still emitted by LabeledTorClient (same semantics)
- resource logs are emitted by ResourceProbe (same format as E2)
- this driver adds "stability" records (one per STABILITY_EMIT_INTERVAL_S)

Env knobs (recommended):
- LOG_DIR
- DIRECTORY_ADDR
- NODE_ADDR
- TARGET_HOST / TARGET_PORT
- RANDOM_SEED
- EXP_LABEL
- RUN_DURATION_S (default 3600)
- WARMUP_S (default 300)
- CIRCUIT_PERIOD_MS (default 2000)
- MAX_CONCURRENT_CIRCUITS (default 3)
- STREAM_CONCURRENCY (default 1)
- PAYLOAD_BYTES_PER_STREAM (default 4096)
- STREAM_BATCHES_PER_CIRCUIT (default 1)
- GAP_BETWEEN_STREAM_BATCHES_MS (default 100)
- RESOURCE_SAMPLE_INTERVAL_S (default 1.0)
- STABILITY_EMIT_INTERVAL_S (default 60)
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
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from labeled_tor_client import LabeledTorClient
from resource_probe import ResourceProbe, VmContainerSampler
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ============================================================
# Defaults for E3 (can be overridden by env vars)
# ============================================================

DEFAULT_RUN_DURATION_S = 60 * 60          # 60 minutes
DEFAULT_WARMUP_S = 1 * 60                 # first 5 minutes treated as warmup in labels
DEFAULT_CIRCUIT_PERIOD_MS = 2000          # slower fixed pacing
DEFAULT_MAX_CONCURRENT_CIRCUITS = 5       # strict concurrency cap (non-saturated)
DEFAULT_STREAM_CONCURRENCY = 2            # light per-circuit load
DEFAULT_PAYLOAD_BYTES_PER_STREAM = 64 * 1024
DEFAULT_STREAM_BATCHES_PER_CIRCUIT = 1    # only 1 batch by default
DEFAULT_GAP_BETWEEN_STREAM_BATCHES_MS = 100
HOPS = 3

# Client networking
CLIENT_NAME = "client_e3"
CLIENT_PORT = 9102  # fixed port; long-run wants a single stable client process

# Stability record frequency
DEFAULT_STABILITY_EMIT_INTERVAL_S = 60

# ============================================================
# Helpers
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


def env_float(key: str, default: float) -> float:
    v = os.environ.get(key)
    return default if v is None else float(v)


def env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


def env_csv(key: str, default: str) -> List[str]:
    raw = env_str(key, default)
    return [p.strip() for p in raw.split(",") if p.strip()]

# ============================================================
# Driver-level logging helpers (E3 add: mirror E2 visibility)
# ============================================================

def emit_driver_log(client: LabeledTorClient, kind: str, rec: dict) -> None:
    """
    Emit an explicit driver-side record for circuit/stream lifecycle.
    This is a safety net in case lower-level components suppress logs.

    Output is JSONL via AsyncJsonlWriter, same directory/rotation as others.
    """
    try:
        base = {
            "ts": time.time(),
            "event": kind,
            "kind": kind,
            "ratio_label": getattr(client, "ratio_label", None),
            "client": getattr(client, "name", None),
        }
        base.update(rec)
        # client.writer is the AsyncJsonlWriter passed into LabeledTorClient
        w = getattr(client, "_writer", None) or getattr(client, "writer", None)
        if w is not None:
            log_kind = (
                "streams"
                if kind.startswith("stream_")
                else "circuits" if kind.startswith("circuit_") else "events"
            )
            w.emit_nowait(log_kind, base)
    except Exception:
        # Never let logging break the workload
        return

# ============================================================
# Stream / circuit helpers (adapted from E2; semantics kept)
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
    emit_driver_log(client, "stream_start", {"stream_uid": stream_uid, "circuit_id": getattr(circuit, "id", None), "dst": dst})

    if stream_id is not None:
        client._sid2uid[stream_id] = stream_uid

    try:
        connect_cell = stream.make_connect(addr)
        await socket.send_cell(connect_cell)
        await stream.wait_connect_ack()
        client.stream_tracker.mark_connected(stream_uid)
    except Exception:
        client.stream_tracker.set_status(stream_uid, "connect_fail")
        emit_driver_log(client, "stream_connect_fail", {"stream_uid": stream_uid, "circuit_id": getattr(circuit, "id", None), "dst": dst})
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        if rec:
            emit_driver_log(client, "stream_end", {"stream_uid": stream_uid, "circuit_id": getattr(circuit, "id", None), "status": rec.get("status"), "dur_ms": rec.get("dur_ms"), "bytes": rec.get("bytes")})
        raise

    return stream_uid, stream


async def send_stream_payload(client, circuit, stream, payload: bytes, stream_uid: str):
    try:
        await client.stream_write(circuit, stream, payload)
        client.stream_tracker.set_status(stream_uid, "ok")
        emit_driver_log(
            client,
            "stream_payload_sent",
            {"stream_uid": stream_uid, "circuit_id": getattr(circuit, "id", None), "bytes": len(payload)},
        )

        # Send RELAY_END immediately after the payload so the exit/server can
        # react without waiting for a downstream signal. This mirrors the E1/E2
        # behavior and avoids the peer timing out waiting for EOF.
        with contextlib.suppress(Exception):
            await client.close_stream(circuit, stream)

        # can be collected by Tor_Client.handle_cell_relay. The wait is best
        # effort only; if it times out we still keep the status as "ok" so we
        # don't mislabel successfully delivered payloads.
        try:
            await asyncio.wait_for(stream.end_event.wait(), timeout=10.0)
        except asyncio.TimeoutError:
            emit_driver_log(
                client,
                "stream_end_wait_timeout",
                {"stream_uid": stream_uid, "circuit_id": getattr(circuit, "id", None)},
            )
    except Exception:
        client.stream_tracker.set_status(stream_uid, "error")
        emit_driver_log(
            client,
            "stream_payload_error",
            {"stream_uid": stream_uid, "circuit_id": getattr(circuit, "id", None), "bytes": len(payload)},
        )
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        raise
    else:
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        emit_driver_log(
            client,
            "stream_complete",
            {
                "stream_uid": stream_uid,
                "circuit_id": getattr(circuit, "id", None),
                "bytes": len(payload),
                "status": rec.get("status") if rec else None,
                "dur_ms": rec.get("dur_ms") if rec else None,
            },
        )


async def run_stream_batch(
    client,
    circuit,
    addr,
    payload_bytes: int,
    batch_size: int,
    rng: random.Random,
    label: str,
    counters: "Counters",
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
            await counters.inc("stream_open_fail")
            continue

        successes += 1
        await counters.inc("stream_open_ok")
        tasks.append(
            asyncio.create_task(
                _send_with_counters(client, circuit, stream, payload, stream_uid, label, counters)
            )
        )

    if successes < batch_size:
        print(f"[{label}] launched {successes}/{batch_size} streams after {attempts} attempts")

    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for res in results:
            if isinstance(res, Exception):
                print(f"[{label}] stream send error: {res}")


async def _send_with_counters(client, circuit, stream, payload: bytes, stream_uid: str, label: str, counters: "Counters"):
    try:
        await send_stream_payload(client, circuit, stream, payload, stream_uid)
        await counters.inc("stream_send_ok")
    except Exception as exc:
        await counters.inc("stream_send_error")
        print(f"[{label}] send_stream_payload failed: {exc}")


async def run_circuit(
    client,
    circ_seq: int,
    addr,
    payload_bytes: int,
    rng: random.Random,
    label: str,
    batches_per_circuit: int,
    batch_size: int,
    gap_ms: int,
    counters: "Counters",
):
    iso_key = f"circ-{circ_seq}"
    await counters.inc("circuit_launch")
    build_started = time.monotonic()
    try:
        circuit = await client.circuit_mgr.get_or_build(
            iso_key,
            hops_count=HOPS,
            extend_routers=None,
            prefer_new=True,
        )
        build_ms = (time.monotonic() - build_started) * 1000
    except Exception as exc:
        await counters.inc("circuit_build_fail")
        print(f"[{label}] circuit build failed: {exc}")
        emit_driver_log(
            client,
            "circuit_build_fail",
            {
                "circ_seq": circ_seq,
                "iso_key": iso_key,
                "label": label,
                "error": str(exc),
                "build_ms": (time.monotonic() - build_started) * 1000,
            },
        )
        return

    await counters.inc("circuit_build_ok")
    client.circuit_mgr.mark_used(circuit)
    emit_driver_log(
        client,
        "circuit_start",
        {
            "circ_seq": circ_seq,
            "iso_key": iso_key,
            "circuit_id": getattr(circuit, "id", None),
            "label": label,
            "build_ms": build_ms,
        },
    )

    for b in range(batches_per_circuit):
        await run_stream_batch(client, circuit, addr, payload_bytes, batch_size, rng, f"{label}-b{b+1}", counters)
        if b != batches_per_circuit - 1:
            await asyncio.sleep(gap_ms / 1000)

    with contextlib.suppress(Exception):
        await client.close_circuit(circuit)
    await counters.inc("circuit_closed")
    emit_driver_log(client, "circuit_end", {"circ_seq": circ_seq, "iso_key": iso_key, "circuit_id": getattr(circuit, "id", None), "label": label})


async def limited_circuit(
    sem: asyncio.Semaphore,
    client,
    circ_seq: int,
    addr,
    payload_bytes: int,
    rng: random.Random,
    label: str,
    batches_per_circuit: int,
    batch_size: int,
    gap_ms: int,
    counters: "Counters",
):
    async with sem:
        await run_circuit(
            client,
            circ_seq,
            addr,
            payload_bytes,
            rng,
            label,
            batches_per_circuit,
            batch_size,
            gap_ms,
            counters,
        )

# ============================================================
# Counters + stability heartbeat
# ============================================================

@dataclass
class Counters:
    lock: asyncio.Lock
    data: Dict[str, int]

    @classmethod
    def new(cls) -> "Counters":
        return cls(lock=asyncio.Lock(), data={})

    async def inc(self, key: str, delta: int = 1) -> None:
        async with self.lock:
            self.data[key] = int(self.data.get(key, 0)) + int(delta)

    async def snapshot(self) -> Dict[str, int]:
        async with self.lock:
            return dict(self.data)

# ============================================================
# Scheduler (timeboxed, slow fixed pacing)
# ============================================================

async def circuit_scheduler_timeboxed(
    client: LabeledTorClient,
    *,
    addr,
    payload_bytes: int,
    period_ms: int,
    rng: random.Random,
    sem: asyncio.Semaphore,
    end_ts: float,
    warmup_until_ts: float,
    batches_per_circuit: int,
    batch_size: int,
    gap_ms: int,
    counters: Counters,
):
    tasks: List[asyncio.Task] = []
    next_launch = time.time()
    circ_seq = 0

    while True:
        now = time.time()
        if now >= end_ts:
            break

        delay = next_launch - now
        if delay > 0:
            await asyncio.sleep(delay)

        now = time.time()
        if now >= end_ts:
            break

        circ_seq += 1
        phase = "warmup" if now < warmup_until_ts else "measure"
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
                    batches_per_circuit,
                    batch_size,
                    gap_ms,
                    counters,
                )
            )
        )

        next_launch += period_ms / 1000

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)


async def stability_heartbeat(
    *,
    writer: AsyncJsonlWriter,
    ratio_label: str,
    started_at: float,
    end_ts: float,
    interval_s: float,
    counters: Counters,
):
    """
    Emits one record per interval, intended for long-run drift and leak checks
    (trend lines over time).
    """
    while True:
        now = time.time()
        if now >= end_ts:
            break

        elapsed_s = now - started_at
        snap = await counters.snapshot()
        rec = {
            "ratio_label": ratio_label,
            "ts": now,
            "elapsed_s": elapsed_s,
            "kind": "stability",
            **snap,
        }
        writer.emit_nowait("stability", rec)

        try:
            await asyncio.sleep(max(0.1, interval_s))
        except asyncio.CancelledError:
            break

# ============================================================
# Probe readiness helper (copied from E2 driver for compatibility)
# ============================================================

async def wait_resource_logging_ready(probe, timeout_s: float = 60.0, poll_s: float = 0.2) -> None:
    deadline = time.monotonic() + timeout_s

    wait_ready = getattr(probe, "wait_ready", None)
    if callable(wait_ready):
        try:
            await wait_ready(timeout_s=timeout_s)
            return
        except TypeError:
            await wait_ready(timeout_s)
            return

    for ev_name in ("ready_event", "connected_event"):
        ev = getattr(probe, ev_name, None)
        if ev is not None and hasattr(ev, "wait"):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Resource logging not ready within {timeout_s}s (event: {ev_name})")
            await asyncio.wait_for(ev.wait(), timeout=remaining)
            return

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

    for fn_name in ("snapshot", "sample", "get_snapshot", "collect_once"):
        fn = getattr(probe, fn_name, None)
        if callable(fn):
            while time.monotonic() < deadline:
                try:
                    res = fn()
                    if asyncio.iscoroutine(res):
                        await res
                    return
                except Exception:
                    await asyncio.sleep(poll_s)
            raise TimeoutError(f"Resource logging not ready within {timeout_s}s (method: {fn_name})")

    while time.monotonic() < deadline:
        await asyncio.sleep(poll_s)
        if time.monotonic() + 1.0 >= deadline:
            break

    raise TimeoutError(
        "Resource logging readiness could not be detected (no known API found). "
        "Please expose probe.ready/connected or an asyncio Event, or implement probe.wait_ready()."
    )

# ============================================================
# Main
# ============================================================

async def main():
    loop = asyncio.get_running_loop()

    ratio_label = env_str("RATIO_LABEL", "50%")
    default_log_dir = Path("exp") / "deployment" / "e3" / ratio_label / "logs"
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

    exp_label = env_str("EXP_LABEL", "E3_Long_Run_Stability")

    # E3 pacing & load knobs
    run_duration_s = env_int("RUN_DURATION_S", DEFAULT_RUN_DURATION_S)
    warmup_s = env_int("WARMUP_S", DEFAULT_WARMUP_S)
    circuit_period_ms = env_int("CIRCUIT_PERIOD_MS", DEFAULT_CIRCUIT_PERIOD_MS)
    max_concurrent_circuits = env_int("MAX_CONCURRENT_CIRCUITS", DEFAULT_MAX_CONCURRENT_CIRCUITS)
    stream_concurrency = env_int("STREAM_CONCURRENCY", DEFAULT_STREAM_CONCURRENCY)
    payload_bytes_per_stream = env_int("PAYLOAD_BYTES_PER_STREAM", DEFAULT_PAYLOAD_BYTES_PER_STREAM)
    stream_batches_per_circuit = env_int("STREAM_BATCHES_PER_CIRCUIT", DEFAULT_STREAM_BATCHES_PER_CIRCUIT)
    gap_between_batches_ms = env_int("GAP_BETWEEN_STREAM_BATCHES_MS", DEFAULT_GAP_BETWEEN_STREAM_BATCHES_MS)
    stability_emit_interval_s = env_float("STABILITY_EMIT_INTERVAL_S", float(DEFAULT_STABILITY_EMIT_INTERVAL_S))

    run_meta_path = log_dir / "run_meta.json"
    started_at = time.time()
    end_ts = started_at + float(run_duration_s)
    warmup_until_ts = started_at + float(warmup_s)

    run_meta = {
        "started_at": started_at,
        "exp_label": exp_label,
        "random_seed": seed,
        "ratio_label": ratio_label,
        "log_dir": str(log_dir.resolve()),
        "run_duration_s": run_duration_s,
        "warmup_s": warmup_s,
        "period_ms": circuit_period_ms,
        "max_concurrent_circuits": max_concurrent_circuits,
        "stream_concurrency": stream_concurrency,
        "payload_bytes_per_stream": payload_bytes_per_stream,
        "stream_batches_per_circuit": stream_batches_per_circuit,
        "gap_between_stream_batches_ms": gap_between_batches_ms,
        "stability_emit_interval_s": stability_emit_interval_s,
        "client_name": CLIENT_NAME,
        "client_port": CLIENT_PORT,
    }

    print(
        "[Config] "
        f"directory={directory_addr} target={addr} max_tls_threads={max_workers} "
        f"duration={run_duration_s}s warmup={warmup_s}s period={circuit_period_ms}ms "
        f"max_cc={max_concurrent_circuits} streams={stream_concurrency} payload={payload_bytes_per_stream}B "
        f"batches={stream_batches_per_circuit}"
    )

    node_addr = env_str("NODE_ADDR", "192.168.66.242")

    # Resource probe (same as E2)
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

    counters = Counters.new()
    sem = asyncio.Semaphore(max_concurrent_circuits)

    client = LabeledTorClient(
        name=CLIENT_NAME,
        host=node_addr,
        port=CLIENT_PORT,
        model="sim",
        ratio_label=ratio_label,
        writer=writer,
    )
    client.attach_labeled_bus(role="client")

    # Start client protocol first (same ordering as E2).
    proto_task = asyncio.create_task(client.start_protocol())
    hb_task: Optional[asyncio.Task] = None

    # Wait until the client is really ready. If the protocol task fails, surface the exception.
    ready_timeout_s = float(os.environ.get("READY_TIMEOUT_S", "30"))
    ready_wait = asyncio.create_task(client.ready_to_send.wait(), name="wait-ready-to-send")

    try:
        done, pending = await asyncio.wait(
            {ready_wait, proto_task},
            return_when=asyncio.FIRST_COMPLETED,
            timeout=ready_timeout_s,
        )
        if ready_wait in done:
            # ready_to_send is set
            pass
        elif proto_task in done:
            # protocol failed early
            exc = proto_task.exception()
            raise RuntimeError("Client protocol exited before ready_to_send was set") from exc
        else:
            raise TimeoutError(f"Client not ready within {ready_timeout_s:.0f}s (ready_to_send not set)")
    finally:
        if not ready_wait.done():
            ready_wait.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await ready_wait

    # Start resource probe after client is up (so it can't affect startup).
    probe.start()
    with contextlib.suppress(Exception):
        await wait_resource_logging_ready(
            probe,
            timeout_s=float(os.environ.get("RESOURCE_READY_TIMEOUT_S", "60")),
        )

    rng = random.Random(seed)

    try:
        hb_task = asyncio.create_task(
            stability_heartbeat(
                writer=writer,
                ratio_label=ratio_label,
                started_at=started_at,
                end_ts=end_ts,
                interval_s=stability_emit_interval_s,
                counters=counters,
            ),
            name="stability-heartbeat",
        )

        await circuit_scheduler_timeboxed(
            client,
            addr=addr,
            payload_bytes=payload_bytes_per_stream,
            period_ms=circuit_period_ms,
            rng=rng,
            sem=sem,
            end_ts=end_ts,
            warmup_until_ts=warmup_until_ts,
            batches_per_circuit=stream_batches_per_circuit,
            batch_size=stream_concurrency,
            gap_ms=gap_between_batches_ms,
            counters=counters,
        )

    finally:
        if hb_task:
            hb_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await hb_task

        with contextlib.suppress(Exception):
            await client.stop_protocol()
        if not proto_task.done():
            proto_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await proto_task

        await probe.stop()
        await writer.stop()

        run_meta.update(
            {
                "finished_at": time.time(),
                "log_files": {k: str(p) for k, p in writer.files.items()},
                "counters_final": await counters.snapshot(),
            }
        )
        run_meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        print(f"[Main] run metadata written to {run_meta_path}")


if __name__ == "__main__":
    asyncio.run(main())