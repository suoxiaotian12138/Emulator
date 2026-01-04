"""
Resource sampling helpers for deployment experiments.

Goal (requested):
- Local (Windows) sampling method is consistent with monitor_source.py:
  - Track python process(es) whose cmdline contains TARGET_SCRIPT
  - Compute local_cpu_ms_from_start as sum(last_cpu_ms - start_cpu_ms)
  - Track local_rss_mb (current) and local_threads (current)
- VM sampling keeps existing container cgroup logic (tor-guard*, tor-middle*, tor-exit*)
- Output format stays compatible with E2 logs:
  - writer.emit_nowait("resources", record)
  - Keep vm_cpu_ms_from_start, vm_mem_mb, local_cpu_ms_from_start, local_rss_mb fields when available
  - Add total_cpu_ms (local + vm) when both sides exist
  - Keep total_mem_mb behavior (local + vm). If local missing, total_mem_mb equals vm_mem_mb.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import paramiko
import psutil

from tools.Log.writer import AsyncJsonlWriter

# Default script to track on the Windows host.
TARGET_SCRIPT = os.environ.get("TARGET_SCRIPT", r"D:\project\Oniverse_refactor\aaatest.py")

# Fixed container name prefixes to include in VM sampling.
DEFAULT_CONTAINER_PREFIXES: Tuple[str, ...] = ("tor-guard", "tor-middle", "tor-exit")


def _cpu_ms_of_proc(p: psutil.Process) -> int:
    ct = p.cpu_times()
    return int((ct.user + ct.system) * 1000)


def _norm_path(p: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return os.path.normcase(p)


def _find_python_candidates_by_script(script_path: str) -> List[Tuple[int, List[str]]]:
    target = _norm_path(script_path)
    out: List[Tuple[int, List[str]]] = []
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if "python" not in name:
                continue
            cmd = proc.info.get("cmdline") or []
            if not cmd:
                continue
            hit = any(isinstance(x, str) and target in _norm_path(x) for x in cmd)
            if hit:
                out.append((proc.info["pid"], cmd))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def _score_process(pid: int) -> Tuple[int, Dict[str, float]]:
    proc = psutil.Process(pid)
    with proc.oneshot():
        rss = proc.memory_info().rss
        threads = proc.num_threads()
        ctime = proc.create_time()
    age_s = max(0.0, time.time() - ctime)

    score = 0
    score += min(int(rss / (1024 * 1024)), 200)
    if threads > 1:
        score += 20
    if age_s < 2.0 and rss < 1 * 1024 * 1024:
        score -= 50

    return score, {"rss_mb": rss / (1024 * 1024), "threads": threads, "age_s": age_s, "score": score}


def _pick_best_pid(cands: List[Tuple[int, List[str]]]) -> int:
    if not cands:
        return -1
    if len(cands) == 1:
        return cands[0][0]

    scored = []
    for pid, cmd in cands:
        try:
            s, d = _score_process(pid)
            scored.append((s, pid, cmd, d))
        except Exception as e:  # noqa: BLE001
            scored.append((-10**9, pid, cmd, {"err": str(e), "score": -10**9}))

    scored.sort(reverse=True, key=lambda x: x[0])
    return scored[0][1]


@dataclass
class _ProcState:
    pid: int
    cmdline: List[str]
    start_cpu_ms: int
    start_ts: float
    peak_rss: int
    peak_threads: int
    last_cpu_ms: int
    last_ts: float


class LocalProcSampler:
    """
    Local sampler that mirrors monitor_source.py behavior.

    - Auto attaches when it first sees the target script process.
    - If the process exits, it detaches and will re-attach if it appears again.
    """

    def __init__(self, script_path: str, *, monitor_all_candidates: bool = False):
        self.script_path = script_path
        self.monitor_all_candidates = monitor_all_candidates
        self._procs: List[_ProcState] = []


    async def wait_ready(self, timeout_s: float = 60.0) -> None:
        await asyncio.wait_for(self.ready_event.wait(), timeout=timeout_s)

    def _attach_if_needed(self) -> bool:
        if self._procs:
            return True

        cands = _find_python_candidates_by_script(self.script_path)
        if not cands:
            return False

        if self.monitor_all_candidates:
            chosen_pids = [pid for pid, _ in cands]
        else:
            chosen_pids = [_pick_best_pid(cands)]

        now = time.time()
        procs: List[_ProcState] = []
        for pid, cmd in cands:
            if pid not in chosen_pids:
                continue
            try:
                p = psutil.Process(pid)
                start_cpu = _cpu_ms_of_proc(p)
                mi = p.memory_info()
                procs.append(
                    _ProcState(
                        pid=pid,
                        cmdline=cmd,
                        start_cpu_ms=start_cpu,
                        start_ts=now,
                        peak_rss=mi.rss,
                        peak_threads=p.num_threads(),
                        last_cpu_ms=start_cpu,
                        last_ts=now,
                    )
                )
            except Exception:
                continue

        self._procs = procs
        return bool(self._procs)

    def is_running(self) -> bool:
        if not self._attach_if_needed():
            return False

        alive: List[_ProcState] = []
        for ps in self._procs:
            try:
                p = psutil.Process(ps.pid)
                if p.is_running():
                    alive.append(ps)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._procs = alive
        if not self._procs:
            return False
        return True

    def snapshot(self) -> Dict[str, float]:
        if not self._attach_if_needed():
            return {}

        now = time.time()
        alive: List[_ProcState] = []

        win_rss_total = 0
        win_th_total = 0
        win_cpu_from_start_ms = 0

        for ps in self._procs:
            try:
                p = psutil.Process(ps.pid)
                if not p.is_running():
                    continue
                with p.oneshot():
                    cpu_ms = _cpu_ms_of_proc(p)
                    mi = p.memory_info()
                    th = p.num_threads()

                ps.peak_rss = max(ps.peak_rss, mi.rss)
                ps.peak_threads = max(ps.peak_threads, th)
                ps.last_cpu_ms = cpu_ms
                ps.last_ts = now

                win_rss_total += mi.rss
                win_th_total += th
                win_cpu_from_start_ms += max(0, cpu_ms - ps.start_cpu_ms)

                alive.append(ps)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._procs = alive
        if not self._procs:
            return {}

        return {
            "local_cpu_ms_from_start": float(win_cpu_from_start_ms),
            "local_rss_bytes": float(win_rss_total),
            "local_rss_mb": float(win_rss_total) / (1024 * 1024),
            "local_threads": float(win_th_total),
        }


REMOTE_PY = r"""
import json, os, subprocess

PREFIXES = json.loads(os.environ.get("PREFIXES_JSON", "[]"))

def sh(cmd):
    return subprocess.check_output(cmd, text=True).strip()

def list_names():
    out = sh(["docker", "ps", "--format", "{{.Names}}"])
    names = [x.strip() for x in out.splitlines() if x.strip()]
    return names

def match(name):
    for p in PREFIXES:
        if name.startswith(p):
            return True
    return False

def container_id(name):
    return sh(["docker", "inspect", "-f", "{{.Id}}", name])

def read_first_existing(paths):
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                return f.read()
        except Exception:
            continue
    return None

def cgroup_v2_paths(cid):
    return f"/sys/fs/cgroup/system.slice/docker-{cid}.scope"

def read_cpu_usage_usec_v2(base):
    txt = read_first_existing([base + "/cpu.stat"])
    if not txt:
        return None
    for line in txt.splitlines():
        if line.startswith("usage_usec "):
            return int(line.split()[1])
    return None

def read_mem_current_v2(base):
    txt = read_first_existing([base + "/memory.current"])
    if not txt:
        return None
    return int(txt.strip())

def cgroup_v1_base(cid):
    return [
        f"/sys/fs/cgroup/cpuacct/docker/{cid}",
        f"/sys/fs/cgroup/cpuacct/system.slice/docker-{cid}.scope",
    ], [
        f"/sys/fs/cgroup/memory/docker/{cid}",
        f"/sys/fs/cgroup/memory/system.slice/docker-{cid}.scope",
    ]

def read_cpu_usage_ns_v1(cpu_base_list):
    for base in cpu_base_list:
        txt = read_first_existing([base + "/cpuacct.usage"])
        if txt:
            return int(txt.strip())
    return None

def read_mem_bytes_v1(mem_base_list):
    for base in mem_base_list:
        txt = read_first_existing([base + "/memory.usage_in_bytes"])
        if txt:
            return int(txt.strip())
    return None

names = [n for n in list_names() if match(n)]

containers = []
for name in names:
    try:
        cid = container_id(name)
        base_v2 = cgroup_v2_paths(cid)

        cpu_usec = read_cpu_usage_usec_v2(base_v2)
        mem_b = read_mem_current_v2(base_v2)

        if cpu_usec is None or mem_b is None:
            cpu_bases, mem_bases = cgroup_v1_base(cid)
            cpu_ns = read_cpu_usage_ns_v1(cpu_bases)
            mem_b = mem_b if mem_b is not None else read_mem_bytes_v1(mem_bases)
            cpu_usec = None if cpu_ns is None else int(cpu_ns / 1000)

        containers.append({
            "name": name,
            "id": cid[:12],
            "cpu_usage_usec": cpu_usec,
            "mem_bytes": mem_b,
        })
    except Exception as e:
        containers.append({"name": name, "err": str(e)})

print(json.dumps({"containers": containers}, ensure_ascii=False))
"""


class VmContainerSampler:
    """
    Samples cgroup stats for matching Docker containers on a remote VM over SSH.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        prefixes: Optional[Iterable[str]] = None,
    ):
        self.host = host
        self.user = user
        self.password = password
        self.prefixes = tuple(prefixes) if prefixes is not None else DEFAULT_CONTAINER_PREFIXES
        self.client: Optional[paramiko.SSHClient] = None
        self._start_cpu_usec: Optional[int] = None

    def connect(self) -> None:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.host, username=self.user, password=self.password, timeout=8)
        self.client = c

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None

    def sample(self) -> Tuple[Optional[Dict[str, float]], Dict[str, str]]:
        """
        Returns (metrics, debug_info).
        metrics is None when no matching containers or no readable cgroup stats.
        """
        dbg: Dict[str, str] = {"prefixes": ",".join(self.prefixes)}
        if not self.client:
            dbg["state"] = "ssh-not-connected"
            return None, dbg

        prefixes_json = json.dumps(list(self.prefixes))
        cmd = (
            "PREFIXES_JSON="
            + "'"
            + prefixes_json.replace("'", r"'\''")
            + "'"
            + " python3 - <<'PY'\n"
            + REMOTE_PY
            + "\nPY"
        )

        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=10)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()

        if err and not out:
            dbg["state"] = "remote-error"
            dbg["err"] = err[:500]
            raise RuntimeError(err)

        payload = json.loads(out)
        containers = payload.get("containers", [])
        dbg["matched"] = str(len(containers))

        cpu_sum = 0
        mem_sum = 0
        ok_any = False
        missing_cpu = 0
        missing_mem = 0

        for c in containers:
            if c.get("cpu_usage_usec") is not None:
                cpu_sum += int(c["cpu_usage_usec"])
                ok_any = True
            else:
                missing_cpu += 1

            if c.get("mem_bytes") is not None:
                mem_sum += int(c["mem_bytes"])
                ok_any = True
            else:
                missing_mem += 1

        dbg["missing_cpu"] = str(missing_cpu)
        dbg["missing_mem"] = str(missing_mem)

        if not ok_any:
            dbg["state"] = "no-metrics"
            return None, dbg

        if self._start_cpu_usec is None:
            self._start_cpu_usec = cpu_sum

        vm_cpu_ms_from_start = None
        if self._start_cpu_usec is not None:
            vm_cpu_ms_from_start = int((cpu_sum - self._start_cpu_usec) / 1000)

        dbg["state"] = "ok"
        return (
            {
                "vm_cpu_ms_from_start": float(vm_cpu_ms_from_start) if vm_cpu_ms_from_start is not None else None,
                "vm_mem_bytes": float(mem_sum),
                "vm_mem_mb": float(mem_sum) / (1024 * 1024),
            },
            dbg,
        )


class ResourceProbe:
    def __init__(
        self,
        writer: AsyncJsonlWriter,
        ratio_label: str,
        *,
        interval_s: float = 1.0,
        vm_sampler: VmContainerSampler | None = None,
        container_only_if_no_target: bool = True,
    ):
        self.writer = writer
        self.interval_s = max(interval_s, 0.1)
        self.vm_sampler = vm_sampler
        self.ratio_label = ratio_label
        self.container_only_if_no_target = container_only_if_no_target
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._local = LocalProcSampler(TARGET_SCRIPT)
        self.ready_event = asyncio.Event()
        self._ready_set = False

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run(), name="resource-probe")

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        if self.vm_sampler:
            with contextlib.suppress(Exception):
                self.vm_sampler.close()

    async def _run(self) -> None:
        try:
            if self.vm_sampler:
                with contextlib.suppress(Exception):
                    self.vm_sampler.connect()

            while not self._stop.is_set():
                record: Dict[str, float | str] = {"ratio_label": self.ratio_label, "ts": time.time()}

                # Local (Windows) metrics: same attach and sampling logic as monitor_source.
                local_running = False
                local_snapshot: Dict[str, float] = {}
                try:
                    local_running = self._local.is_running()
                    if local_running or not self.container_only_if_no_target:
                        local_snapshot = self._local.snapshot()
                except Exception as e:  # noqa: BLE001
                    record["local_err"] = str(e)

                if self.container_only_if_no_target and not local_running:
                    record["local_note"] = "target-script-not-running; container-only"
                elif not local_running:
                    record["local_note"] = "target-script-not-running"

                if local_snapshot:
                    record.update(local_snapshot)

                # VM container metrics
                if self.vm_sampler:
                    try:
                        vm_rec, vm_dbg = self.vm_sampler.sample()
                        record["vm_prefixes"] = vm_dbg.get("prefixes", "")
                        record["vm_state"] = vm_dbg.get("state", "")
                        record["vm_matched"] = vm_dbg.get("matched", "")
                        record["vm_missing_cpu"] = vm_dbg.get("missing_cpu", "")
                        record["vm_missing_mem"] = vm_dbg.get("missing_mem", "")
                        if vm_rec:
                            # Filter None values to keep JSON clean.
                            for k, v in vm_rec.items():
                                if v is not None:
                                    record[k] = v
                        else:
                            record["vm_note"] = "no-matching-containers-or-no-readable-cgroup"
                    except Exception as e:  # noqa: BLE001
                        record["vm_err"] = str(e)

                # Derived combined memory fields (E2 compatible)
                win_mb = record.get("local_rss_mb")
                vm_mb = record.get("vm_mem_mb")
                if win_mb is not None or vm_mb is not None:
                    total_mb = 0.0
                    if isinstance(win_mb, (int, float)):
                        total_mb += float(win_mb)
                        record["win_rss_mb"] = float(win_mb)
                    if isinstance(vm_mb, (int, float)):
                        total_mb += float(vm_mb)
                        record["vm_mem_mb"] = float(vm_mb)
                    record["total_mem_mb"] = total_mb

                # Derived combined CPU time (requested)
                local_cpu = record.get("local_cpu_ms_from_start")
                vm_cpu = record.get("vm_cpu_ms_from_start")
                if isinstance(local_cpu, (int, float)) and isinstance(vm_cpu, (int, float)):
                    record["total_cpu_ms"] = float(local_cpu) + float(vm_cpu)
                elif isinstance(local_cpu, (int, float)):
                    record["total_cpu_ms"] = float(local_cpu)
                elif isinstance(vm_cpu, (int, float)):
                    record["total_cpu_ms"] = float(vm_cpu)

                self.writer.emit_nowait("resources", record)

                if not self._ready_set:
                    self._ready_set = True
                    self.ready_event.set()

                    print("resource is ready")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.interval_s)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            raise
