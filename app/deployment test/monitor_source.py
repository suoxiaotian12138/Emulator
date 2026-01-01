import os
import re
import time
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import psutil
import paramiko


# -----------------------------
# Config
# -----------------------------
TARGET_SCRIPT = r"D:\project\Oniverse_refactor\aaatest.py"

VM_HOST = "192.168.66.10"
VM_USER = "root"
VM_PASS = "sf5538177"  # TODO: replace with real password or use key auth

# 容器命名匹配规则
# 你后面会统一成 tor-guardn / tor-middlen / tor-exitn，这里提前按前缀匹配即可
CONTAINER_PREFIXES = ("tor-guard", "tor-middle", "tor-exit")

INTERVAL_S = 0.5
PRINT_EVERY_S = 5.0

# 是否同时监控所有候选 python 进程
MONITOR_ALL_CANDIDATES = False


# -----------------------------
# Helpers
# -----------------------------
def norm_path(p: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(p))
    except Exception:
        return os.path.normcase(p)


def find_python_candidates_by_script(script_path: str) -> List[Tuple[int, List[str]]]:
    target = norm_path(script_path)
    out: List[Tuple[int, List[str]]] = []
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            name = (p.info.get("name") or "").lower()
            if "python" not in name:
                continue
            cmd = p.info.get("cmdline") or []
            if not cmd:
                continue
            hit = any(isinstance(x, str) and target in norm_path(x) for x in cmd)
            if hit:
                out.append((p.info["pid"], cmd))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return out


def score_process(pid: int) -> Tuple[int, Dict]:
    p = psutil.Process(pid)
    with p.oneshot():
        rss = p.memory_info().rss
        th = p.num_threads()
        ctime = p.create_time()
    age_s = max(0.0, time.time() - ctime)

    score = 0
    score += min(int(rss / (1024 * 1024)), 200)  # 1MB = 1分
    if th > 1:
        score += 20
    if age_s < 2.0 and rss < 1 * 1024 * 1024:
        score -= 50

    return score, {"rss_mb": rss / (1024 * 1024), "threads": th, "age_s": age_s, "score": score}


def pick_best_pid(cands: List[Tuple[int, List[str]]]) -> int:
    if not cands:
        return -1
    if len(cands) == 1:
        return cands[0][0]

    scored = []
    for pid, cmd in cands:
        try:
            s, d = score_process(pid)
            scored.append((s, pid, cmd, d))
        except Exception as e:
            scored.append((-10**9, pid, cmd, {"err": str(e), "score": -10**9}))

    scored.sort(reverse=True, key=lambda x: x[0])

    print("\n[monitor] candidate scores:")
    for s, pid, cmd, d in scored:
        print(f"  pid={pid} score={s} rss_mb={d.get('rss_mb')} th={d.get('threads')} age_s={d.get('age_s')} cmd={' '.join(cmd)}")

    best_pid = scored[0][1]
    print(f"[monitor] auto-selected pid={best_pid}")
    return best_pid


@dataclass
class ProcState:
    pid: int
    cmdline: List[str]
    start_cpu_ms: int
    start_ts: float
    peak_rss: int
    peak_threads: int
    last_cpu_ms: int
    last_ts: float


def cpu_ms_of_proc(p: psutil.Process) -> int:
    ct = p.cpu_times()
    return int((ct.user + ct.system) * 1000)


# -----------------------------
# VM docker sampler over SSH
# -----------------------------
REMOTE_PY = r"""
import json, os, re, subprocess, sys

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
    # common v2 path
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
    # v1 path patterns vary
    # try docker cgroup path
    # cpuacct.usage is ns, memory.usage_in_bytes is bytes
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


class VmSampler:
    def __init__(self, host: str, user: str, password: str):
        self.host = host
        self.user = user
        self.password = password
        self.client: Optional[paramiko.SSHClient] = None

    def connect(self) -> None:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(self.host, username=self.user, password=self.password, timeout=8)
        self.client = c

    def close(self) -> None:
        if self.client:
            self.client.close()
            self.client = None

    def sample(self, prefixes: Tuple[str, ...]) -> Dict:
        import json

        if not self.client:
            raise RuntimeError("ssh not connected")

        prefixes_json = json.dumps(list(prefixes))
        cmd = (
                "PREFIXES_JSON=" + "'" + prefixes_json.replace("'", r"'\''") + "'" + " "
                                                                                     "python3 - <<'PY'\n" + REMOTE_PY + "\nPY"
        )
        stdin, stdout, stderr = self.client.exec_command(cmd, timeout=10)
        out = stdout.read().decode("utf-8", errors="replace").strip()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if err and not out:
            raise RuntimeError(err)
        return {"raw": out, "err": err}


# -----------------------------
# Main monitor
# -----------------------------
def main():
    print(f"[monitor] target={TARGET_SCRIPT}")
    print("[monitor] waiting for process...")

    procs: List[ProcState] = []
    chosen_pid = None

    while True:
        cands = find_python_candidates_by_script(TARGET_SCRIPT)
        if cands:
            if MONITOR_ALL_CANDIDATES:
                chosen = [pid for pid, _ in cands]
            else:
                chosen_pid = pick_best_pid(cands)
                chosen = [chosen_pid]

            now = time.time()
            for pid, cmd in cands:
                if pid not in chosen:
                    continue
                try:
                    p = psutil.Process(pid)
                    start_cpu = cpu_ms_of_proc(p)
                    mi = p.memory_info()
                    procs.append(
                        ProcState(
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
            break
        time.sleep(0.2)

    if not procs:
        print("[monitor] no process attached")
        return

    print(f"[monitor] attached {len(procs)} process(es):")
    for ps in procs:
        try:
            p = psutil.Process(ps.pid)
            exe = p.exe()
        except Exception:
            exe = "?"
        print(f"  pid={ps.pid} exe={exe} cmd={' '.join(ps.cmdline)}")

    # VM sampler
    vm = VmSampler(VM_HOST, VM_USER, VM_PASS)
    try:
        vm.connect()
        print(f"[monitor] vm ssh connected: {VM_USER}@{VM_HOST}")
    except Exception as e:
        print(f"[monitor] vm ssh connect failed: {e}")
        print("[monitor] continue without vm sampling")
        vm = None

    # VM baseline
    vm_start: Dict[str, int] = {}
    vm_peak_mem_total = 0
    vm_last_cpu_total_usec = None
    vm_last_ts = None

    start_wall = time.time()
    last_print = start_wall

    try:
        while True:
            alive: List[ProcState] = []
            now = time.time()

            # sample local procs
            win_cpu_total_ms = 0
            win_rss_total = 0
            win_th_total = 0

            for ps in procs:
                try:
                    p = psutil.Process(ps.pid)
                    if not p.is_running():
                        continue
                    with p.oneshot():
                        cpu_ms = cpu_ms_of_proc(p)
                        mi = p.memory_info()
                        th = p.num_threads()

                    ps.peak_rss = max(ps.peak_rss, mi.rss)
                    ps.peak_threads = max(ps.peak_threads, th)

                    win_cpu_total_ms += cpu_ms
                    win_rss_total += mi.rss
                    win_th_total += th

                    ps.last_cpu_ms = cpu_ms
                    ps.last_ts = now

                    alive.append(ps)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            procs = alive
            if not procs:
                break

            # sample vm containers
            vm_cpu_total_usec = None
            vm_mem_total = None
            if vm is not None:
                try:
                    r = vm.sample(CONTAINER_PREFIXES)
                    import json
                    payload = json.loads(r["raw"])
                    containers = payload.get("containers", [])
                    cpu_sum = 0
                    mem_sum = 0
                    ok_any = False
                    for c in containers:
                        if "cpu_usage_usec" in c and c.get("cpu_usage_usec") is not None:
                            cpu_sum += int(c["cpu_usage_usec"])
                            ok_any = True
                        if "mem_bytes" in c and c.get("mem_bytes") is not None:
                            mem_sum += int(c["mem_bytes"])
                            ok_any = True
                    if ok_any:
                        vm_cpu_total_usec = cpu_sum
                        vm_mem_total = mem_sum
                        vm_peak_mem_total = max(vm_peak_mem_total, mem_sum)
                        if not vm_start:
                            # store baseline per run
                            vm_start["cpu_total_usec"] = cpu_sum
                            vm_start["ts"] = now
                except Exception as e:

                    print(f"[vm] sample error: {e}")

            # periodic live print
            if PRINT_EVERY_S > 0 and (now - last_print) >= PRINT_EVERY_S:
                # win CPU rate from procs aggregated
                # compute rate based on sum of deltas since last print is too coarse
                # we compute rate per interval with stored last values in each ProcState
                win_rate = 0.0
                # approximate using total cpu delta across all monitored procs since last_print
                # store prev snapshot
                # easiest: reuse last_print interval from total cpu via current minus start is not good for rate
                # instead compute per proc based on last sample interval (INTERVAL_S)
                # Here we compute from last loop interval, which is close to INTERVAL_S.
                # win_rate_ms_per_s approx: delta_cpu_ms / delta_t
                # Use current loop delta from previous loop values stored in locals
                # For simplicity, print cumulative + rss; rate is optional.

                win_cpu_from_start_ms = 0
                win_peak_rss_mb = 0.0
                for ps in procs:
                    win_cpu_from_start_ms += (ps.last_cpu_ms - ps.start_cpu_ms)
                    win_peak_rss_mb += ps.peak_rss / (1024 * 1024)

                vm_cpu_from_start_ms = None
                if vm_cpu_total_usec is not None and "cpu_total_usec" in vm_start:
                    vm_cpu_from_start_ms = int((vm_cpu_total_usec - vm_start["cpu_total_usec"]) / 1000)

                rss_mb = win_rss_total / (1024 * 1024)

                line = f"[live] t+{now-start_wall:.1f}s win_cpu_ms={win_cpu_from_start_ms} win_rss_mb={rss_mb:.2f} win_th={win_th_total}"
                if vm_cpu_from_start_ms is not None and vm_mem_total is not None:
                    line += f" vm_cpu_ms={vm_cpu_from_start_ms} vm_mem_mb={vm_mem_total/(1024*1024):.2f}"
                    line += f" total_cpu_ms={win_cpu_from_start_ms + vm_cpu_from_start_ms}"
                print(line)

                last_print = now

            time.sleep(INTERVAL_S)

    except KeyboardInterrupt:
        pass
    finally:
        end_wall = time.time()
        if vm is not None:
            try:
                vm.close()
            except Exception:
                pass

    # Summary
    wall_ms = int((end_wall - start_wall) * 1000)

    win_cpu_ms = 0
    win_peak_rss_mb = 0.0
    for ps in procs:
        win_cpu_ms += (ps.last_cpu_ms - ps.start_cpu_ms)
        win_peak_rss_mb += ps.peak_rss / (1024 * 1024)

    vm_cpu_ms = None
    if vm_start.get("cpu_total_usec") is not None:
        # best effort final resample is skipped, so we use last captured totals if any
        # If you need accurate end value, keep last successful vm_cpu_total_usec in a variable and use it here.
        pass

    print("\n[Result] summary")
    print(f"  wall_ms: {wall_ms}")
    print(f"  win_cpu_total_ms: {win_cpu_ms}")
    print(f"  win_peak_rss_mb_sum: {win_peak_rss_mb:.2f}")
    print(f"  vm_peak_mem_mb_sum: {vm_peak_mem_total/(1024*1024):.2f}")
    print("  note: vm cpu total is reported live; for final vm cpu total, keep last vm_cpu_total_usec and diff it at exit.")


if __name__ == "__main__":
    main()
