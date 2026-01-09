"""
Experiment E2: Circuit Density under Fixed Concurrency.

Goal
- Keep client concurrency fixed (N clients).
- Each client builds circuits at a fixed cadence (PER_CLIENT_PERIOD_S) with at most
  MAX_CONCURRENT_CIRCUITS in-flight per client.
- Optionally cap total in-flight circuits across all clients via GLOBAL_CONCURRENT_CIRCUITS.
- No load levels (no grading). One run = one fixed-concurrency configuration.

Logging
- Circuit attempt events: exp/deployment/e2_density/logs/<MODE_TAG>/circuits*.jsonl
- Resource probe events (if enabled): same directory (handled by ResourceProbe).
- run_meta.json: includes config + summary.

Environment knobs (defaults in parentheses)
- LOG_DIR (exp/deployment/e2_density/logs)
- MODE_TAG (torbox)
- EXP_LABEL (E2_Circuit_Density_FixedConcurrency)
- DIRECTORY_ADDR (192.168.66.241:9030)  # forwarded into os.environ for Tor client
- NODE_ADDR (192.168.66.242)

- CONCURRENCY (32)                       # number of clients
- WARMUP_S (10)
- MEASURE_S (60)
- PER_CLIENT_PERIOD_S (2.0)
- CIRCUIT_BUILD_TIMEOUT_S (5.0)

- MAX_CONCURRENT_CIRCUITS (1)            # per-client in-flight cap
- GLOBAL_CONCURRENT_CIRCUITS (None)      # total in-flight cap, empty means disabled

- MAX_TLS_THREADS (64)
- GLOBAL_CONCURRENT_TLS (64)             # kept for compatibility, not enforced here

- ENABLE_VM_SAMPLING (1)                 # resource_probe knobs (optional)
- RESOURCE_SAMPLE_INTERVAL_S (1.0)
- RESOURCE_READY_TIMEOUT_S (60)

Notes
- This file intentionally mirrors E1's client creation, pacing, and logging style,
  but removes the ramped load levels and capacity boundary detection.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import os
import random
import re
import sys
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

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


# ============================================================
# Data classes + logging
# ============================================================
@dataclass
class CircuitAttempt:
    client: str
    concurrency: int
    phase: str
    seq: int

    start_ts: float
    end_ts: float

    status: str
    latency_ms: float

    reason: Optional[str] = None
    ratio_label: Optional[str] = None

    queue_per_client_ms: Optional[float] = None
    queue_global_ms: Optional[float] = None
    build_ms: Optional[float] = None
    close_ms: Optional[float] = None


def log_circuit_attempt(writer: AsyncJsonlWriter, attempt: CircuitAttempt) -> None:
    writer.emit_nowait(
        "circuits",
        {
            "event": "circuit_attempt",
            "ratio_label": attempt.ratio_label,
            "client": attempt.client,
            "concurrency": attempt.concurrency,
            "phase": attempt.phase,
            "seq": attempt.seq,
            "start_ts": attempt.start_ts,
            "end_ts": attempt.end_ts,
            "latency_ms": attempt.latency_ms,
            "status": attempt.status,
            "reason": attempt.reason,
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
    circuit, _timing = await asyncio.wait_for(
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
        close_ms = (t3 - t2) * 1000.0
    except Exception:
        # close failure should not fail the attempt
        pass

    build_ms = (t1 - t0) * 1000.0
    return build_ms, close_ms


async def paced_circuit_builder(
    *,
    client: LabeledTorClient,
    concurrency: int,
    phase: str,
    duration_s: float,
    period_s: float,
    timeout_s: float,
    writer: AsyncJsonlWriter,
    per_client_sem: asyncio.Semaphore,
    global_sem: Optional[asyncio.Semaphore],
    results: List[CircuitAttempt],
) -> None:
    max_pending = env_int("MAX_PENDING_PER_CLIENT", 1)
    catchup_mode = env_str("PACING_CATCHUP", "drop").strip().lower()
    jitter_frac = env_float("PACING_JITTER_FRAC", 0.0)

    t0 = time.monotonic()
    t_end = t0 + duration_s

    seq = 0
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
            concurrency=concurrency,
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

        try:
            t_q0 = time.perf_counter()
            await per_client_sem.acquire()
            t_q1 = time.perf_counter()
            queue_per_client_ms = (t_q1 - t_q0) * 1000.0
            try:
                if global_sem is not None:
                    t_g0 = time.perf_counter()
                    await global_sem.acquire()
                    t_g1 = time.perf_counter()
                    queue_global_ms = (t_g1 - t_g0) * 1000.0
                    try:
                        build_ms, close_ms = await build_single_circuit(
                            client, f"{phase}-{concurrency}-{seq_no}", timeout_s
                        )
                    finally:
                        global_sem.release()
                else:
                    build_ms, close_ms = await build_single_circuit(
                        client, f"{phase}-{concurrency}-{seq_no}", timeout_s
                    )
                status = "ok"
            finally:
                per_client_sem.release()
        except asyncio.TimeoutError:
            reason = "TimeoutError:circuit_build_timeout"
        except Exception as exc:  # noqa: BLE001
            reason = f"{type(exc).__name__}:{exc}"

        wall_end = time.time()
        perf_end = time.perf_counter()
        total_ms = (perf_end - perf_start) * 1000.0

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

        delay = next_tick - now
        if delay > 0:
            await asyncio.sleep(delay)

        if jitter_frac > 0:
            await asyncio.sleep(random.random() * period_s * jitter_frac)

        now2 = time.monotonic()
        if now2 - next_tick > period_s and catchup_mode == "drop":
            skipped = int((now2 - next_tick) // period_s)
            next_tick += skipped * period_s

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
        await asyncio.wait_for(self.client.ready_to_send.wait(), timeout=30.0)
        self._started = True

    async def run(
        self,
        *,
        concurrency: int,
        warmup_s: float,
        measure_s: float,
        period_s: float,
        timeout_s: float,
        results: List[CircuitAttempt],
    ) -> None:
        await paced_circuit_builder(
            client=self.client,
            concurrency=concurrency,
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
            concurrency=concurrency,
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


# ============================================================
# Summary helpers
# ============================================================
def compute_percentile(samples: List[float], pct: float) -> Optional[float]:
    if not samples:
        return None
    samples_sorted = sorted(samples)
    k = (len(samples_sorted) - 1) * (pct / 100.0)
    f = int(k)
    c = min(f + 1, len(samples_sorted) - 1)
    if f == c:
        return samples_sorted[f]
    return samples_sorted[f] + (samples_sorted[c] - samples_sorted[f]) * (k - f)


def summarize_attempts(concurrency: int, attempts: List[CircuitAttempt]) -> Dict[str, Optional[float]]:
    measurement = [a for a in attempts if a.phase == "measure"]
    ok = [a for a in measurement if a.status == "ok"]
    fail = [a for a in measurement if a.status == "fail"]
    denom = len(ok) + len(fail)
    success_rate = 0.0 if denom == 0 else (len(ok) / denom)

    total_lat = [a.latency_ms for a in ok]
    build_lat = [a.build_ms for a in ok if a.build_ms is not None]

    return {
        "concurrency": concurrency,
        "attempts_measure": len(measurement),
        "ok": len(ok),
        "fail": len(fail),
        "drops": sum(1 for a in measurement if a.status == "drop"),
        "success_rate": success_rate,
        "p50_total_ms": compute_percentile(total_lat, 50),
        "p95_total_ms": compute_percentile(total_lat, 95),
        "p50_build_ms": compute_percentile(build_lat, 50),
        "p95_build_ms": compute_percentile(build_lat, 95),
    }


def excepthook(exc_type, exc, tb):
    with open("unhandled_errors.log", "a", encoding="utf-8") as f:
        f.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] UNHANDLED\n")
        f.write("".join(traceback.format_exception(exc_type, exc, tb)))
        f.flush()


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

    while time.monotonic() < deadline:
        await asyncio.sleep(poll_s)
        if time.monotonic() + 1.0 >= deadline:
            break

    raise TimeoutError(
        "Resource logging readiness could not be detected. "
        "Expose probe.ready/connected or an asyncio Event, or implement probe.wait_ready()."
    )


async def main() -> None:
    sys.excepthook = excepthook

    loop = asyncio.get_running_loop()

    ratio_label = "fixed-topology"

    default_log_dir = Path("exp") / "deployment" / "e2_density" / "logs"
    base_log_dir = Path(env_str("LOG_DIR", str(default_log_dir)))
    mode_tag = env_str("MODE_TAG", "torbox")
    relay_tier = env_str("RELAY_TIER", "120")
    # sanitize path segment
    relay_tier = re.sub(r"[^A-Za-z0-9_.-]+", "_", relay_tier).strip("_") or "default"
    log_dir = base_log_dir / mode_tag / relay_tier
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

    exp_label = env_str("EXP_LABEL", "E2_Circuit_Density_FixedConcurrency")

    concurrency = env_int("CONCURRENCY", 32)
    warmup_s = env_float("WARMUP_S", 30.0)
    measure_s = env_float("MEASURE_S", 120.0)
    period_s = env_float("PER_CLIENT_PERIOD_S", 2.0)
    timeout_s = env_float("CIRCUIT_BUILD_TIMEOUT_S", 5.0)
    per_client_limit = env_int("MAX_CONCURRENT_CIRCUITS", 1)

    global_limit_raw = os.environ.get("GLOBAL_CONCURRENT_CIRCUITS")
    global_sem = None if global_limit_raw in (None, "") else asyncio.Semaphore(int(global_limit_raw))

    run_meta_path = log_dir / "run_meta.json"
    run_meta: Dict[str, object] = {
        "started_at": time.time(),
        "finished_at": None,
        "exp_label": exp_label,
        "random_seed": seed,
        "ratio_label": ratio_label,
        "log_dir": str(log_dir.resolve()),
        "mode_tag": mode_tag,
        "relay_tier": relay_tier,
        "hops": HOPS,
        "directory_addr": directory_addr,
        "concurrency": concurrency,
        "warmup_s": warmup_s,
        "measure_s": measure_s,
        "period_s": period_s,
        "timeout_s": timeout_s,
        "per_client_limit": per_client_limit,
        "global_limit": None if global_sem is None else int(global_limit_raw),
    }

    print(
        f"[Config] directory={directory_addr} concurrency={concurrency} "
        f"max_tls_threads={max_workers} warmup={warmup_s}s measure={measure_s}s period={period_s}s"
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

    runners: List[ClientRunner] = []
    all_attempts: List[CircuitAttempt] = []

    probe.start()
    await wait_resource_logging_ready(probe, timeout_s=float(os.environ.get("RESOURCE_READY_TIMEOUT_S", "60")))

    try:
        # Build and start clients
        tls_sem = None  # keep behavior consistent with E1's current default
        for client_idx in range(concurrency):
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

        # Run workload (warmup then measure) across all clients
        tasks = [
            asyncio.create_task(
                r.run(
                    concurrency=concurrency,
                    warmup_s=warmup_s,
                    measure_s=measure_s,
                    period_s=period_s,
                    timeout_s=timeout_s,
                    results=all_attempts,
                )
            )
            for r in runners
        ]
        await asyncio.gather(*tasks, return_exceptions=False)
    finally:
        stop_tasks = [asyncio.create_task(r.stop()) for r in runners]
        await asyncio.gather(*stop_tasks, return_exceptions=True)


        summary = summarize_attempts(concurrency, all_attempts)
        run_meta["finished_at"] = time.time()
        run_meta["log_files"] = {k: str(p) for k, p in writer.files.items()}
        run_meta["summary"] = summary
        run_meta_path.write_text(json.dumps(run_meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        await writer.close()

        print(f"[Main] run metadata written to {run_meta_path}")
        p50t = summary["p50_total_ms"]
        p95t = summary["p95_total_ms"]
        p50b = summary["p50_build_ms"]
        p95b = summary["p95_build_ms"]
        print(
            f"[Summary] concurrency={concurrency} success_rate={summary['success_rate']:.4f} "
            f"total_p50={p50t:.1f}ms total_p95={p95t:.1f}ms build_p50={p50b:.1f}ms build_p95={p95b:.1f}ms"
            if all(v is not None for v in (p50t, p95t, p50b, p95b))
            else f"[Summary] concurrency={concurrency} success_rate={summary['success_rate']:.4f} (insufficient ok samples)"
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("[Main] KeyboardInterrupt: exiting gracefully")
