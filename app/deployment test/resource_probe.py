"""Resource sampling helpers for deployment experiments.

The sampler combines local (Windows host) process metrics with optional VM
container cgroup statistics collected over SSH. Metrics are reported as deltas
from the start of the run to avoid misleading instantaneous readings that were
seen in older sourcetest-based approaches.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

import paramiko
import psutil

from tools.Log.writer import AsyncJsonlWriter


def _cpu_ms_of_proc(p: psutil.Process) -> int:
    ct = p.cpu_times()
    return int((ct.user + ct.system) * 1000)


@dataclass
class LocalProcGroup:
    root_pid: int
    start_cpu: Dict[int, int] = field(default_factory=dict)

    def _collect_targets(self) -> List[psutil.Process]:
        try:
            root = psutil.Process(self.root_pid)
        except psutil.NoSuchProcess:
            return []
        procs = [root]
        with root.oneshot():
            procs.extend(root.children(recursive=True))
        return procs

    def snapshot(self) -> Dict[str, float]:
        procs = self._collect_targets()
        total_cpu_ms = 0
        total_rss = 0
        total_threads = 0

        for p in procs:
            try:
                with p.oneshot():
                    cpu_ms = _cpu_ms_of_proc(p)
                    mem = p.memory_info()
                    th = p.num_threads()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if p.pid not in self.start_cpu:
                self.start_cpu[p.pid] = cpu_ms

            total_cpu_ms += max(0, cpu_ms - self.start_cpu[p.pid])
            total_rss += mem.rss
            total_threads += th

        return {
            "local_cpu_ms_from_start": total_cpu_ms,
            "local_rss_bytes": total_rss,
            "local_rss_mb": total_rss / (1024 * 1024),
            "local_threads": total_threads,
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
    def __init__(self, host: str, user: str, password: str, prefixes: Iterable[str]):
        self.host = host
        self.user = user
        self.password = password
        self.prefixes = tuple(prefixes)
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

    def sample(self) -> Optional[Dict[str, float]]:
        if not self.client:
            return None

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
            raise RuntimeError(err)

        payload = json.loads(out)
        containers = payload.get("containers", [])
        cpu_sum = 0
        mem_sum = 0
        ok_any = False
        for c in containers:
            if c.get("cpu_usage_usec") is not None:
                cpu_sum += int(c["cpu_usage_usec"])
                ok_any = True
            if c.get("mem_bytes") is not None:
                mem_sum += int(c["mem_bytes"])
                ok_any = True

        if not ok_any:
            return None

        if self._start_cpu_usec is None:
            self._start_cpu_usec = cpu_sum

        vm_cpu_ms_from_start = None
        if self._start_cpu_usec is not None:
            vm_cpu_ms_from_start = int((cpu_sum - self._start_cpu_usec) / 1000)

        return {
            "vm_cpu_ms_from_start": vm_cpu_ms_from_start,
            "vm_mem_bytes": mem_sum,
            "vm_mem_mb": mem_sum / (1024 * 1024),
        }


class ResourceProbe:
    def __init__(
        self,
        writer: AsyncJsonlWriter,
        ratio_label: str,
        *,
        interval_s: float = 1.0,
        vm_sampler: VmContainerSampler | None = None,
    ):
        self.writer = writer
        self.interval_s = max(interval_s, 0.1)
        self.vm_sampler = vm_sampler
        self.ratio_label = ratio_label
        self._stop = asyncio.Event()
        self._task: Optional[asyncio.Task] = None
        self._local = LocalProcGroup(os.getpid())

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
                try:
                    record.update(self._local.snapshot())
                except Exception as e:  # noqa: BLE001
                    record["local_err"] = str(e)

                if self.vm_sampler:
                    with contextlib.suppress(Exception):
                        vm_rec = self.vm_sampler.sample()
                        if vm_rec:
                            record.update(vm_rec)

                # Derived convenience fields for combined memory tracking
                win_mb = record.get("local_rss_mb")
                vm_mb = record.get("vm_mem_mb")
                if win_mb is not None or vm_mb is not None:
                    total_mb = 0.0
                    if isinstance(win_mb, (int, float)):
                        total_mb += win_mb
                        record["win_rss_mb"] = win_mb
                    if isinstance(vm_mb, (int, float)):
                        total_mb += vm_mb
                        record["vm_mem_mb"] = vm_mb
                    record["total_mem_mb"] = total_mb

                self.writer.emit_nowait("resources", record)
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.interval_s)
                except asyncio.TimeoutError:
                    continue
        except asyncio.CancelledError:
            raise