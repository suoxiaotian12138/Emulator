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
import sys, traceback, time

from labeled_tor_client import LabeledTorClient
from resource_probe import ResourceProbe, VmContainerSampler
from tools.Log.writer import AsyncJsonlWriter

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

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
    latency_ms: float   # 你可以保留为 total_ms，或改名

    reason: Optional[str] = None
    ratio_label: Optional[str] = None

    # new: breakdown
    queue_per_client_ms: Optional[float] = None
    queue_global_ms: Optional[float] = None
    build_ms: Optional[float] = None
    close_ms: Optional[float] = None

@dataclass
class LoadLevelResult:
    load_level: int
    attempts: List[CircuitAttempt]
    subwindow_success: List[float]
    success_rate: float

    # total latency percentiles (queue + build + close + overhead), ok only
    p50_total_ms: Optional[float]
    p95_total_ms: Optional[float]

    # build latency percentiles (ok only)
    p50_build_ms: Optional[float]
    p95_build_ms: Optional[float]



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

            # new
            "queue_per_client_ms": attempt.queue_per_client_ms,
            "queue_global_ms": attempt.queue_global_ms,
            "build_ms": attempt.build_ms,
            "close_ms": attempt.close_ms,
        },
    )



# ============================================================
# Circuit workload per client
# ============================================================

async def build_single_circuit(
    client: LabeledTorClient,
    iso_key: str,
    timeout_s: float,
) -> tuple[float, float]:
    t0 = time.perf_counter()
    circuit, timing = await asyncio.wait_for(
        client.create_circuit(hops_count=HOPS, extend_routers=None),
        timeout=timeout_s,
    )

    t1 = time.perf_counter()

    client.circuit_mgr.mark_used(circuit)

    close_ms = 0.0
    try:
        t2 = time.perf_counter()
        await client.close_circuit(circuit)
        t3 = time.perf_counter()
        close_ms = (t3 - t2) * 1000
    except Exception:
        # close 失败不影响 build_ms
        pass

    build_ms = (t1 - t0) * 1000
    return build_ms, close_ms


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
    # New knobs (env, optional)
    max_pending = env_int("MAX_PENDING_PER_CLIENT", 1)  # 1 means strict backpressure
    catchup_mode = env_str("PACING_CATCHUP", "drop").strip().lower()  # drop or catchup
    jitter_frac = env_float("PACING_JITTER_FRAC", 0.0)  # e.g. 0.05

    # Use monotonic clock for scheduling stability
    t0_wall = time.time()
    t0 = time.monotonic()
    t_end = t0 + duration_s

    seq = 0
    # Stable phase offset per client to avoid herd effect across thousands of clients
    phase_offset = (hash(client.name) % 1000) / 1000.0 * period_s
    next_tick = t0 + phase_offset

    pending: set[asyncio.Task] = set()

    def _emit_attempt(
        *,
        seq_no: int,
        wall_start: float,
        wall_end: float,
        status: str,
        reason: Optional[str],
        total_ms: float,
        queue_per_client_ms: float,
        queue_global_ms: float,
        build_ms: Optional[float],
        close_ms: Optional[float],
    ) -> None:
        attempt = CircuitAttempt(
            client=client.name,
            load_level=load_level,
            phase=phase,
            seq=seq_no,
            start_ts=wall_start,
            end_ts=wall_end,
            status=status,
            latency_ms=total_ms,
            reason=reason,
            ratio_label=getattr(client, "ratio_label", None),
            queue_per_client_ms=queue_per_client_ms,
            queue_global_ms=queue_global_ms if global_sem is not None else 0.0,
            build_ms=build_ms,
            close_ms=close_ms,
        )
        results.append(attempt)
        log_circuit_attempt(writer, attempt)

    async def _one_attempt(seq_no: int) -> None:
        wall_start = time.time()
        perf_start = time.perf_counter()

        status = "fail"
        reason = None

        queue_per_client_ms = 0.0
        queue_global_ms = 0.0
        build_ms = None
        close_ms = None

        # Important: timeout should include only the build step (as you already do),
        # but we keep total latency as (queue + build + close + overhead).
        try:
            # 1) per-client queue
            t_q0 = time.perf_counter()
            await per_client_sem.acquire()
            t_q1 = time.perf_counter()
            queue_per_client_ms = (t_q1 - t_q0) * 1000

            try:
                # 2) global queue (optional)
                if global_sem is not None:
                    t_g0 = time.perf_counter()
                    await global_sem.acquire()
                    t_g1 = time.perf_counter()
                    queue_global_ms = (t_g1 - t_g0) * 1000
                    try:
                        build_ms, close_ms = await build_single_circuit(
                            client, f"{phase}-{load_level}-{seq_no}", timeout_s
                        )
                    finally:
                        global_sem.release()
                else:
                    build_ms, close_ms = await build_single_circuit(
                        client, f"{phase}-{load_level}-{seq_no}", timeout_s
                    )

                status = "ok"
            finally:
                per_client_sem.release()

        except asyncio.TimeoutError:
            reason = "TimeoutError:circuit_build_timeout"
        except Exception as exc:
            reason = f"{type(exc).__name__}:{exc}"

        wall_end = time.time()
        perf_end = time.perf_counter()
        total_ms = (perf_end - perf_start) * 1000

        _emit_attempt(
            seq_no=seq_no,
            wall_start=wall_start,
            wall_end=wall_end,
            status=status,
            reason=reason,
            total_ms=total_ms,
            queue_per_client_ms=queue_per_client_ms,
            queue_global_ms=queue_global_ms,
            build_ms=build_ms,
            close_ms=close_ms,
        )

    while True:
        now = time.monotonic()
        if now >= t_end:
            break

        # Sleep until next tick
        delay = next_tick - now
        if delay > 0:
            await asyncio.sleep(delay)

        # Optional small jitter to avoid herd effect
        if jitter_frac > 0:
            await asyncio.sleep(random.random() * period_s * jitter_frac)

        # If we are behind schedule, decide what to do
        now2 = time.monotonic()
        if now2 - next_tick > period_s:
            if catchup_mode == "drop":
                # Drop missed ticks: real systems do not "catch up" by bursting
                skipped = int((now2 - next_tick) // period_s)
                next_tick += skipped * period_s
            # else: "catchup" keeps old behavior (not recommended)

        # Backpressure: do not allow unbounded pending queue
        if len(pending) >= max_pending:
            seq += 1
            wall = time.time()
            _emit_attempt(
                seq_no=seq,
                wall_start=wall,
                wall_end=wall,
                status="drop",
                reason="pacer_overrun:pending_limit",
                total_ms=0.0,
                queue_per_client_ms=0.0,
                queue_global_ms=0.0,
                build_ms=None,
                close_ms=None,
            )
        else:
            seq += 1
            task = asyncio.create_task(_one_attempt(seq))
            pending.add(task)
            task.add_done_callback(lambda t: pending.discard(t))

        next_tick += period_s

    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

class ClientRunner:
    def __init__(
        self,
        *,
        writer: AsyncJsonlWriter,
        ratio_label: str,
        client_idx: int,
        node_addr: str,
        port: int,
        per_client_limit: int,
        global_sem: Optional[asyncio.Semaphore],
        tls_sem: Optional[asyncio.Semaphore],
    ) -> None:
        self.writer = writer
        self.ratio_label = ratio_label
        self.client_idx = client_idx
        self.node_addr = node_addr
        self.port = port
        self.global_sem = global_sem

        self.client = LabeledTorClient(
            name=f"{CLIENT_NAME_PREFIX}{client_idx}",
            host=node_addr,
            port=port,
            model="sim",
            ratio_label=ratio_label,
            writer=writer,
            tls_sem=tls_sem,
        )
        self.client.attach_labeled_bus(role="client", enable_circuit_summary=False)

        self.per_client_sem = asyncio.Semaphore(per_client_limit)
        self._proto_task: Optional[asyncio.Task] = None
        self._started = False

    async def start(self) -> None:
        if self._started:
            return
        self._proto_task = asyncio.create_task(self.client.start_protocol())
        await asyncio.wait_for(self.client.ready_to_send.wait(), timeout=30)
        self._started = True

    async def run_epoch(
        self,
        *,
        load_level: int,
        warmup_s: float,
        measure_s: float,
        period_s: float,
        timeout_s: float,
        results: List[CircuitAttempt],
    ) -> None:
        await paced_circuit_builder(
            client=self.client,
            load_level=load_level,
            phase="warmup",
            duration_s=warmup_s,
            period_s=period_s,
            timeout_s=timeout_s,
            writer=self.writer,
            per_client_sem=self.per_client_sem,
            global_sem=self.global_sem,
            results=results,
        )
        await paced_circuit_builder(
            client=self.client,
            load_level=load_level,
            phase="measure",
            duration_s=measure_s,
            period_s=period_s,
            timeout_s=timeout_s,
            writer=self.writer,
            per_client_sem=self.per_client_sem,
            global_sem=self.global_sem,
            results=results,
        )

    async def stop(self) -> None:
        with contextlib.suppress(Exception):
            await self.client.stop_protocol()
        if self._proto_task is not None and not self._proto_task.done():
            self._proto_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._proto_task


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
    tls_sem: Optional[asyncio.Semaphore],
    seed: int,
) -> List[CircuitAttempt]:
    client = LabeledTorClient(
        name=f"{CLIENT_NAME_PREFIX}{client_idx}",
        host=node_addr,
        port=port,
        model="sim",
        ratio_label=ratio_label,
        writer=writer,
        tls_sem=tls_sem,
    )
    client.attach_labeled_bus(role="client", enable_circuit_summary=False)

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

    # Success rate: ok / (ok + fail). Drops are excluded to avoid "pacer artifact".
    ok = [a for a in measurement_attempts if a.status == "ok"]
    fail = [a for a in measurement_attempts if a.status == "fail"]
    denom = (len(ok) + len(fail))
    success_rate = 0.0 if denom == 0 else (len(ok) / denom)

    total_lat = [a.latency_ms for a in ok]
    build_lat = [a.build_ms for a in ok if a.build_ms is not None]

    p50_total = compute_percentile(total_lat, 50)
    p95_total = compute_percentile(total_lat, 95)
    p50_build = compute_percentile(build_lat, 50)
    p95_build = compute_percentile(build_lat, 95)

    subwindow_success = compute_subwindow_success(attempts, subwindow_s)

    return LoadLevelResult(
        load_level=load_level,
        attempts=measurement_attempts,
        subwindow_success=subwindow_success,
        success_rate=success_rate,
        p50_total_ms=p50_total,
        p95_total_ms=p95_total,
        p50_build_ms=p50_build,
        p95_build_ms=p95_build,
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

def excepthook(exc_type, exc, tb):
    with open("unhandled_errors.log", "a", encoding="utf-8") as f:
        f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] UNHANDLED\n")
        f.write("".join(traceback.format_exception(exc_type, exc, tb)))
        f.flush()

# ============================================================
# Main
# ============================================================
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



async def main():
    sys.excepthook = excepthook

    tls_limit = env_int("GLOBAL_CONCURRENT_TLS", 64)
    # tls_sem = asyncio.Semaphore(tls_limit)
    tls_sem = None
    loop = asyncio.get_running_loop()

    ratio_label = "fixed-topology"
    default_log_dir = Path("exp") / "deployment" / "e1_scalability" / "logs"
    base_log_dir = Path(env_str("LOG_DIR", str(default_log_dir)))
    mode_tag = env_str("MODE_TAG", "tor")
    log_dir = base_log_dir / mode_tag

    log_dir.mkdir(parents=True, exist_ok=True)

    directory_addr = env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
    os.environ["DIRECTORY_ADDR"] = directory_addr

    max_workers = env_int("MAX_TLS_THREADS", 64)
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
    #16,24,32,48,64,80,96,112,128,160,196,256
    concurrency_levels = env_csv_int("CONCURRENCY_LEVELS", "16,24,32,48,64,80,96,112,128,160,196,256")
    warmup_s = env_float("WARMUP_S", 30.0)
    measure_s = env_float("MEASURE_S", 120.0)
    cooldown_s = env_float("LOAD_COOLDOWN_S", 5.0)
    period_s = env_float("PER_CLIENT_PERIOD_S", 10.0)
    timeout_s = env_float("CIRCUIT_BUILD_TIMEOUT_S", 5.0)
    per_client_limit = env_int("MAX_CONCURRENT_CIRCUITS", 1)

    user_ramp_mode = env_str("USER_RAMP_MODE", "rebuild").strip().lower()
    if user_ramp_mode not in ("rebuild", "incremental"):
        raise ValueError(f"Invalid USER_RAMP_MODE={user_ramp_mode}, expected rebuild or incremental")

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
    runners: List[ClientRunner] = []

    try:
        for level_idx, load_level in enumerate(concurrency_levels):
            print(f"[Load] starting level {load_level} users ({level_idx + 1}/{len(concurrency_levels)})")

            level_attempts: List[CircuitAttempt] = []

            if user_ramp_mode == "rebuild":
                # Keep old behavior: build N clients, run epoch, tear down all.
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
                                tls_sem=tls_sem,
                                seed=seed,
                            )
                        )
                    )

                client_results = await asyncio.gather(*client_tasks, return_exceptions=True)
                for res in client_results:
                    if isinstance(res, Exception):
                        print(f"[Load] client task failed at level {load_level}: {res}")
                        continue
                    level_attempts.extend(res)

            else:
                # incremental: keep existing clients, add delta only
                current = len(runners)
                target = load_level
                if target < current:
                    # If levels ever decrease, we keep extra clients but make them idle.
                    # (You can change policy to stop extras if you want.)
                    print(f"[Load] incremental mode: target {target} < current {current}, keeping extras idle")
                else:
                    # create and start only delta clients
                    for client_idx in range(current, target):
                        port = CLIENT_PORT_BASE + client_idx
                        r = ClientRunner(
                            writer=writer,
                            ratio_label=ratio_label,
                            client_idx=client_idx,
                            node_addr=node_addr,
                            port=port,
                            per_client_limit=per_client_limit,
                            global_sem=global_sem,
                            tls_sem=tls_sem,
                        )
                        await r.start()
                        runners.append(r)

                # run epoch on the first `target` clients
                active = runners[:target]
                epoch_tasks = []
                for r in active:
                    epoch_tasks.append(
                        asyncio.create_task(
                            r.run_epoch(
                                load_level=load_level,
                                warmup_s=warmup_s,
                                measure_s=measure_s,
                                period_s=period_s,
                                timeout_s=timeout_s,
                                results=level_attempts,
                            )
                        )
                    )

                epoch_results = await asyncio.gather(*epoch_tasks, return_exceptions=True)
                for res in epoch_results:
                    if isinstance(res, Exception):
                        print(f"[Load] runner epoch failed at level {load_level}: {res}")

            summary = summarize_load_level(load_level, level_attempts, subwindow_s)
            results.append(summary)

            p50t = f"{summary.p50_total_ms:.1f}" if summary.p50_total_ms is not None else "n/a"
            p95t = f"{summary.p95_total_ms:.1f}" if summary.p95_total_ms is not None else "n/a"
            p50b = f"{summary.p50_build_ms:.1f}" if summary.p50_build_ms is not None else "n/a"
            p95b = f"{summary.p95_build_ms:.1f}" if summary.p95_build_ms is not None else "n/a"
            print(
                f"[Load] level={load_level} attempts={len(summary.attempts)} "
                f"success_rate={summary.success_rate:.4f} "
                f"total_p50={p50t}ms total_p95={p95t}ms build_p50={p50b}ms build_p95={p95b}ms"
            )

            if cooldown_s > 0 and load_level != concurrency_levels[-1]:
                await asyncio.sleep(cooldown_s)
    finally:
        # Stop incremental clients if used
        if runners:
            stop_tasks = [asyncio.create_task(r.stop()) for r in runners]
            await asyncio.gather(*stop_tasks, return_exceptions=True)

        run_meta.update(
            {
                "finished_at": time.time(),
                "log_files": {k: str(p) for k, p in writer.files.items()},
                "results": [
                    {
                        "load_level": r.load_level,
                        "success_rate": r.success_rate,
                        "p50_total_ms": r.p50_total_ms,
                        "p95_total_ms": r.p95_total_ms,
                        "p50_build_ms": r.p50_build_ms,
                        "p95_build_ms": r.p95_build_ms,
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




if __name__ == "__main__":
    asyncio.run(main())