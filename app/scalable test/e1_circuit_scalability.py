"""
Experiment E1: Circuit Scalability under Fixed Relay Topology.

This driver adapts the E2 fixed-pacing harness to probe how many concurrent
"users" (LabeledTorClient instances) a fixed relay deployment can sustain
before circuit establishment becomes unstable. Relay configuration and Tor
behavior remain unchanged; only client-side concurrency is varied within a
single continuous run.

Key behavior:
- Load is ramped across multiple levels (epochs), each with a warmup and
  measurement window.
- Each "user" builds circuits at a fixed cadence with one in-flight circuit at
  a time. Circuits are closed immediately after build; streams are disabled.
- All circuit attempts (including failures) are logged with start/end
  timestamps, latency, outcome, and failure reason when applicable.
- Measurement windows aggregate success rate and latency percentiles; sustained
  degradations trigger capacity-boundary detection.

Environment knobs (defaults in parentheses):
- LOG_DIR (exp/deployment/e1_scalability/logs)
- DIRECTORY_ADDR (192.168.66.241:9030)
- NODE_ADDR (192.168.66.242)
- TARGET_HOST / TARGET_PORT (192.168.66.243 / 8000)
- RANDOM_SEED (current timestamp)
- EXP_LABEL (E1_Circuit_Scalability)
- MAX_TLS_THREADS (128)
- CONCURRENCY_LEVELS ("1,2,4,8,16,32,48,64")
- WARMUP_S (30)
- MEASURE_S (120)
- LOAD_COOLDOWN_S (5)
- PER_CLIENT_PERIOD_S (2.0)
- CIRCUIT_BUILD_TIMEOUT_S (5.0)
- SUCCESS_RATE_THRESHOLD (0.99)
- CONSECUTIVE_WINDOW_FAILURES (3)
- SUBWINDOW_S (10.0)
- MAX_CONCURRENT_CIRCUITS (1)  # per-client in-flight cap
- GLOBAL_CONCURRENT_CIRCUITS (None = no global cap)
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
from typing import Dict, List, Optional

from labeled_tor_client import LabeledTorClient
from resource_probe import ResourceProbe, VmContainerSampler
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOPS = 3
CLIENT_NAME_PREFIX = "client"
CLIENT_PORT_BASE = 9102


# ============================================================
# Helper utilities
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
    writer = AsyncJsonlWriter(out_dir=log_dir, rotate_mb=50, batch_size=200, flush_every_ms=100)
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


def env_csv_int(key: str, default: str) -> List[int]:
    raw = env_str(key, default)
    return [int(p.strip()) for p in raw.split(",") if p.strip()]


# ============================================================
# Data classes
# ============================================================

@dataclass
class CircuitAttempt:
    client: str
    load_level: int
    phase: str
    seq: int
    start_ts: float
    end_ts: float
    status: str
    latency_ms: float
    reason: Optional[str] = None
    ratio_label: Optional[str] = None


@dataclass
class LoadLevelResult:
    load_level: int
    attempts: List[CircuitAttempt]
    subwindow_success: List[float]
    success_rate: float
    p50_ms: Optional[float]
    p95_ms: Optional[float]


# ============================================================
# Logging helpers
# ============================================================

def log_circuit_attempt(writer: AsyncJsonlWriter, attempt: CircuitAttempt) -> None:
    writer.emit_nowait(
        "circuits",
        {
            "event": "circuit_attempt",
            "ratio_label": attempt.ratio_label,
            "client": attempt.client,
            "load_level": attempt.load_level,
            "phase": attempt.phase,
            "seq": attempt.seq,
            "start_ts": attempt.start_ts,
            "end_ts": attempt.end_ts,
            "latency_ms": attempt.latency_ms,
            "status": attempt.status,
            "reason": attempt.reason,
        },
    )


# ============================================================
# Circuit workload per client
# ============================================================

async def build_single_circuit(
    client: LabeledTorClient,
    iso_key: str,
    timeout_s: float,
) -> None:
    circuit = await asyncio.wait_for(
        client.circuit_mgr.get_or_build(
            iso_key,
            hops_count=HOPS,
            extend_routers=None,
            prefer_new=True,
        ),
        timeout=timeout_s,
    )
    client.circuit_mgr.mark_used(circuit)
    with contextlib.suppress(Exception):
        await client.close_circuit(circuit)


async def paced_circuit_builder(
    *,
    client: LabeledTorClient,
    load_level: int,
    phase: str,
    duration_s: float,
    period_s: float,
    timeout_s: float,
    writer: AsyncJsonlWriter,
    per_client_sem: asyncio.Semaphore,
    global_sem: Optional[asyncio.Semaphore],
    results: List[CircuitAttempt],
) -> None:
    start_time = time.time()
    end_time = start_time + duration_s
    seq = 0
    next_launch = start_time

    while True:
        now = time.time()
        if now >= end_time:
            break

        delay = next_launch - now
        if delay > 0:
            await asyncio.sleep(delay)

        seq += 1
        attempt_start = time.time()
        reason = None
        status = "fail"

        try:
            async with per_client_sem:
                if global_sem is None:
                    await build_single_circuit(client, f"{phase}-{load_level}-{seq}", timeout_s)
                else:
                    async with global_sem:
                        await build_single_circuit(client, f"{phase}-{load_level}-{seq}", timeout_s)
            status = "ok"
        except Exception as exc:  # noqa: PERF203
            reason = f"{type(exc).__name__}:{exc}"
        finally:
            attempt_end = time.time()
            latency_ms = (attempt_end - attempt_start) * 1000
            attempt = CircuitAttempt(
                client=client.name,
                load_level=load_level,
                phase=phase,
                seq=seq,
                start_ts=attempt_start,
                end_ts=attempt_end,
                status=status,
                latency_ms=latency_ms,
                reason=reason,
                ratio_label=getattr(client, "ratio_label", None),
            )
            results.append(attempt)
            log_circuit_attempt(writer, attempt)

        next_launch += period_s


async def run_client_for_level(
    *,
    writer: AsyncJsonlWriter,
    ratio_label: str,
    load_level: int,
    client_idx: int,
    node_addr: str,
    port: int,
    addr,
    warmup_s: float,
    measure_s: float,
    period_s: float,
    timeout_s: float,
    per_client_limit: int,
    global_sem: Optional[asyncio.Semaphore],
    seed: int,
) -> List[CircuitAttempt]:
    client = LabeledTorClient(
        name=f"{CLIENT_NAME_PREFIX}{client_idx}",
        host=node_addr,
        port=port,
        model="sim",
        ratio_label=ratio_label,
        writer=writer,
    )
    client.attach_labeled_bus(role="client")

    results: List[CircuitAttempt] = []
    per_client_sem = asyncio.Semaphore(per_client_limit)

    proto_task = asyncio.create_task(client.start_protocol())
    try:
        await asyncio.wait_for(client.ready_to_send.wait(), timeout=30)
        await paced_circuit_builder(
            client=client,
            load_level=load_level,
            phase="warmup",
            duration_s=warmup_s,
            period_s=period_s,
            timeout_s=timeout_s,
            writer=writer,
            per_client_sem=per_client_sem,
            global_sem=global_sem,
            results=results,
        )

        await paced_circuit_builder(
            client=client,
            load_level=load_level,
            phase="measure",
            duration_s=measure_s,
            period_s=period_s,
            timeout_s=timeout_s,
            writer=writer,
            per_client_sem=per_client_sem,
            global_sem=global_sem,
            results=results,
        )
    finally:
        with contextlib.suppress(Exception):
            await client.stop_protocol()
        if not proto_task.done():
            proto_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await proto_task

    return results


# ============================================================
# Aggregation and capacity boundary detection
# ============================================================

def compute_percentile(samples: List[float], pct: float) -> Optional[float]:
    if not samples:
        return None
    samples_sorted = sorted(samples)
    k = (len(samples_sorted) - 1) * (pct / 100)
    f = int(k)
    c = min(f + 1, len(samples_sorted) - 1)
    if f == c:
        return samples_sorted[f]
    return samples_sorted[f] + (samples_sorted[c] - samples_sorted[f]) * (k - f)


def compute_subwindow_success(attempts: List[CircuitAttempt], window_s: float) -> List[float]:
    measurement_attempts = [a for a in attempts if a.phase == "measure"]
    if not measurement_attempts:
        return []
    t0 = min(a.start_ts for a in measurement_attempts)
    buckets: Dict[int, List[CircuitAttempt]] = {}
    for att in measurement_attempts:
        bucket = int((att.start_ts - t0) // window_s)
        buckets.setdefault(bucket, []).append(att)

    success_rates: List[float] = []
    for idx in sorted(buckets.keys()):
        bucket_attempts = buckets[idx]
        ok = sum(1 for a in bucket_attempts if a.status == "ok")
        success_rates.append(ok / len(bucket_attempts))
    return success_rates


def summarize_load_level(load_level: int, attempts: List[CircuitAttempt], subwindow_s: float) -> LoadLevelResult:
    measurement_attempts = [a for a in attempts if a.phase == "measure"]
    success_rate = 0.0 if not measurement_attempts else sum(1 for a in measurement_attempts if a.status == "ok") / len(measurement_attempts)
    latencies = [a.latency_ms for a in measurement_attempts if a.status == "ok"]
    p50 = compute_percentile(latencies, 50)
    p95 = compute_percentile(latencies, 95)
    subwindow_success = compute_subwindow_success(attempts, subwindow_s)
    return LoadLevelResult(
        load_level=load_level,
        attempts=measurement_attempts,
        subwindow_success=subwindow_success,
        success_rate=success_rate,
        p50_ms=p50,
        p95_ms=p95,
    )


def detect_capacity_boundary(results: List[LoadLevelResult], success_threshold: float, consecutive_failures: int) -> Optional[int]:
    if not results:
        return None
    baseline_p95 = results[0].p95_ms
    boundary: Optional[int] = None

    for idx, res in enumerate(results):
        if idx == 0:
            continue

        sustained_fail = False
        if res.subwindow_success:
            streak = 0
            for rate in res.subwindow_success:
                if rate < success_threshold:
                    streak += 1
                    if streak >= consecutive_failures:
                        sustained_fail = True
                        break
                else:
                    streak = 0

        tail_amp = False
        if baseline_p95 is not None and res.p95_ms is not None:
            tail_amp = res.p95_ms >= 2 * baseline_p95

        sharp_tail = False
        prev_p95 = results[idx - 1].p95_ms
        if prev_p95 is not None and res.p95_ms is not None:
            sharp_tail = res.p95_ms >= 1.5 * prev_p95

        if sustained_fail or tail_amp or sharp_tail:
            boundary = results[idx - 1].load_level
            break

    return boundary


# ============================================================
# Main
# ============================================================

async def main():
    loop = asyncio.get_running_loop()

    ratio_label = "fixed-topology"
    default_log_dir = Path("exp") / "deployment" / "e1_scalability" / "logs"
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

    exp_label = env_str("EXP_LABEL", "E1_Circuit_Scalability")

    run_meta_path = log_dir / "run_meta.json"
    run_meta = {
        "started_at": time.time(),
        "exp_label": exp_label,
        "random_seed": seed,
        "ratio_label": ratio_label,
        "log_dir": str(log_dir.resolve()),
        "hops": HOPS,
    }

    concurrency_levels = env_csv_int("CONCURRENCY_LEVELS", "1,2,4,8,16,32,48,64")
    warmup_s = env_float("WARMUP_S", 30.0)
    measure_s = env_float("MEASURE_S", 120.0)
    cooldown_s = env_float("LOAD_COOLDOWN_S", 5.0)
    period_s = env_float("PER_CLIENT_PERIOD_S", 2.0)
    timeout_s = env_float("CIRCUIT_BUILD_TIMEOUT_S", 5.0)
    per_client_limit = env_int("MAX_CONCURRENT_CIRCUITS", 1)

    global_limit = os.environ.get("GLOBAL_CONCURRENT_CIRCUITS")
    global_sem = None if global_limit in (None, "") else asyncio.Semaphore(int(global_limit))

    success_threshold = env_float("SUCCESS_RATE_THRESHOLD", 0.99)
    consecutive_failures = env_int("CONSECUTIVE_WINDOW_FAILURES", 3)
    subwindow_s = env_float("SUBWINDOW_S", 10.0)

    run_meta.update(
        {
            "concurrency_levels": concurrency_levels,
            "warmup_s": warmup_s,
            "measure_s": measure_s,
            "cooldown_s": cooldown_s,
            "period_s": period_s,
            "timeout_s": timeout_s,
            "per_client_limit": per_client_limit,
            "global_limit": None if global_limit in (None, "") else int(global_limit),
            "success_rate_threshold": success_threshold,
            "consecutive_window_failures": consecutive_failures,
            "subwindow_s": subwindow_s,
        }
    )

    print(
        f"[Config] directory={directory_addr} target={addr} max_tls_threads={max_workers} "
        f"levels={concurrency_levels} warmup={warmup_s}s measure={measure_s}s period={period_s}s"
    )

    node_addr = env_str("NODE_ADDR", "192.168.66.242")

    vm_sampler: Optional[VmContainerSampler] = None
    if env_str("ENABLE_VM_SAMPLING", "1") != "0":
        vm_sampler = VmContainerSampler(
            env_str("VM_HOST", "192.168.66.10"),
            env_str("VM_USER", "root"),
            env_str("VM_PASS", "sf5538177"),
            [p.strip() for p in env_str("VM_CONTAINER_PREFIXES", "tor-guard,tor-middle,tor-exit").split(",") if p.strip()],
        )

    probe = ResourceProbe(
        writer,
        ratio_label,
        interval_s=float(os.environ.get("RESOURCE_SAMPLE_INTERVAL_S", "1.0")),
        vm_sampler=vm_sampler,
    )

    results: List[LoadLevelResult] = []

    probe.start()
    await wait_resource_logging_ready(probe, timeout_s=float(os.environ.get("RESOURCE_READY_TIMEOUT_S", "60")))
    try:
        for level_idx, load_level in enumerate(concurrency_levels):
            print(f"[Load] starting level {load_level} users ({level_idx + 1}/{len(concurrency_levels)})")
            client_tasks = []
            for client_idx in range(load_level):
                port = CLIENT_PORT_BASE + client_idx
                client_tasks.append(
                    asyncio.create_task(
                        run_client_for_level(
                            writer=writer,
                            ratio_label=ratio_label,
                            load_level=load_level,
                            client_idx=client_idx,
                            node_addr=node_addr,
                            port=port,
                            addr=addr,
                            warmup_s=warmup_s,
                            measure_s=measure_s,
                            period_s=period_s,
                            timeout_s=timeout_s,
                            per_client_limit=per_client_limit,
                            global_sem=global_sem,
                            seed=seed,
                        )
                    )
                )

            level_attempts: List[CircuitAttempt] = []
            client_results = await asyncio.gather(*client_tasks, return_exceptions=True)
            for res in client_results:
                if isinstance(res, Exception):
                    print(f"[Load] client task failed at level {load_level}: {res}")
                    continue
                level_attempts.extend(res)

            summary = summarize_load_level(load_level, level_attempts, subwindow_s)
            results.append(summary)

            p50_str = f"{summary.p50_ms:.1f}" if summary.p50_ms is not None else "n/a"
            p95_str = f"{summary.p95_ms:.1f}" if summary.p95_ms is not None else "n/a"
            print(
                f"[Load] level={load_level} attempts={len(summary.attempts)} "
                f"success_rate={summary.success_rate:.4f} p50={p50_str}ms p95={p95_str}ms"
            )

            if cooldown_s > 0 and load_level != concurrency_levels[-1]:
                await asyncio.sleep(cooldown_s)
    finally:
        await probe.stop()
        await writer.stop()
        run_meta.update(
            {
                "finished_at": time.time(),
                "log_files": {k: str(p) for k, p in writer.files.items()},
                "results": [
                    {
                        "load_level": r.load_level,
                        "success_rate": r.success_rate,
                        "p50_ms": r.p50_ms,
                        "p95_ms": r.p95_ms,
                        "subwindow_success": r.subwindow_success,
                        "attempts": len(r.attempts),
                    }
                    for r in results
                ],
                "capacity_boundary": detect_capacity_boundary(results, success_threshold, consecutive_failures),
            }
        )
        run_meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        print(f"[Main] run metadata written to {run_meta_path}")


async def wait_resource_logging_ready(probe, timeout_s: float = 60.0, poll_s: float = 0.2) -> None:
    """
    Gate execution until resource logging is actually ready.
    Tries multiple probe APIs for compatibility.
    """
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


if __name__ == "__main__":
    asyncio.run(main())