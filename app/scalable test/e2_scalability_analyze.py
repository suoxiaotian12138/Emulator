"""
E2 scalability analyzer (improved)

Fixes and additions compared to the minimal version:
1) Resource plot should include all scales: we now look for resource jsonl in BOTH:
   - <run_dir>/resources/*.jsonl
   - <run_dir>/resources*.jsonl  (no subdir)
   - <run_dir>/**/resources*.jsonl (nested)
   and we accept several common memory keys (preferring total_mem_mb).

2) Adds a tail-latency distribution plot for circuit build latency:
   - For each mode, we pick the run with the largest node scale (within the fixed-concurrency view),
     then plot the tail CCDF (survival function) of latency_ms for OK circuits in phase=="measure".

Outputs:
- CSV: out_dir/e2_fixed_c<target>.csv
- Plots: out_dir/plots/*.png

Usage:
  python e2_scalability_analyze_v2.py \
    --log-root exp/deployment/e2_density/logs \
    --out-dir analysis_out/e2 \
    --target-concurrency 64 \
    --modes tor,torbox
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import matplotlib.pyplot as plt


# ----------------------------
# Data model
# ----------------------------
@dataclass
class RunRow:
    run_dir: Path
    mode_tag: str
    node_scale_raw: str
    node_scale_num: Optional[int]
    concurrency: Optional[int]

    success_rate: Optional[float]
    ok: Optional[int]
    measure_s: Optional[float]
    throughput_ok_per_s: Optional[float]

    p95_total_ms: Optional[float]  # from run_meta summary

    mem_p95_mb: Optional[float]    # from resources logs


def _safe_get(d: Dict, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _parse_scale_num(s: str) -> Optional[int]:
    s = (s or "").strip()
    if not s:
        return None
    if s.isdigit():
        try:
            return int(s)
        except Exception:
            return None
    m = re.search(r"(\d+)", s)
    if m:
        try:
            return int(m.group(1))
        except Exception:
            return None
    return None


def _infer_mode_and_scale_from_path(meta_path: Path) -> Tuple[str, str]:
    parts = meta_path.parts
    if "logs" not in parts:
        return ("unknown", "unknown")
    i = parts.index("logs")
    mode_tag = parts[i + 1] if i + 1 < len(parts) else "unknown"
    node_scale_raw = parts[i + 2] if i + 2 < len(parts) else "unknown"
    return (mode_tag, node_scale_raw)


# ----------------------------
# Percentile helper
# ----------------------------
def _percentile(xs: List[float], p: float) -> Optional[float]:
    if not xs:
        return None
    xs = sorted(xs)
    k = (len(xs) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[f]
    return xs[f] + (k - f) * (xs[c] - xs[f])


# ----------------------------
# Resource logs
# ----------------------------
_MEM_KEYS_IN_ORDER = [
    "total_mem_mb",        # preferred
    "total_mem_mib",
    "mem_mb",
    "rss_mb",
    "proc_rss_mb",
    "process_rss_mb",
    "container_mem_mb",
    "host_mem_used_mb",
]

def _iter_jsonl_files(paths: List[Path]) -> Iterable[Path]:
    seen = set()
    for p in paths:
        try:
            rp = p.resolve()
        except Exception:
            rp = p
        if rp in seen:
            continue
        seen.add(rp)
        if rp.is_file():
            yield rp


def _candidate_resource_files(run_dir: Path) -> List[Path]:
    cands: List[Path] = []

    # 1) run_dir/resources/*.jsonl
    res_dir = run_dir / "resources"
    if res_dir.exists() and res_dir.is_dir():
        cands.extend(sorted([p for p in res_dir.rglob("*.jsonl") if p.is_file()]))

    # 2) run_dir/resources*.jsonl (no subdir)
    cands.extend(sorted([p for p in run_dir.glob("resources*.jsonl") if p.is_file()]))

    # 3) run_dir/**/resources*.jsonl (nested)
    cands.extend(sorted([p for p in run_dir.rglob("resources*.jsonl") if p.is_file()]))

    # also accept "resource*.jsonl" (some older naming)
    cands.extend(sorted([p for p in run_dir.rglob("resource*.jsonl") if p.is_file()]))

    return cands


def _iter_resource_records(run_dir: Path) -> Iterable[Dict]:
    files = list(_iter_jsonl_files(_candidate_resource_files(run_dir)))
    if not files:
        return []
    records: List[Dict] = []
    for fp in files:
        try:
            for line in fp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    records.append(obj)
        except Exception:
            continue
    return records


def mem_p95_from_resources(run_dir: Path) -> Optional[float]:
    xs: List[float] = []
    for r in _iter_resource_records(run_dir):
        v = None
        for k in _MEM_KEYS_IN_ORDER:
            if k in r and r.get(k) is not None:
                v = r.get(k)
                break
        if v is None:
            continue
        try:
            xs.append(float(v))
        except Exception:
            continue
    return _percentile(xs, 95.0) if xs else None


# ----------------------------
# Circuit logs (for tail distribution)
# ----------------------------
def _candidate_circuit_files(run_dir: Path) -> List[Path]:
    cands: List[Path] = []
    # common: circuits*.jsonl at run_dir root
    cands.extend(sorted([p for p in run_dir.glob("circuits*.jsonl") if p.is_file()]))
    # sometimes in subdir
    circ_dir = run_dir / "circuits"
    if circ_dir.exists() and circ_dir.is_dir():
        cands.extend(sorted([p for p in circ_dir.rglob("*.jsonl") if p.is_file()]))
    # nested naming
    cands.extend(sorted([p for p in run_dir.rglob("circuits*.jsonl") if p.is_file()]))
    return cands


def iter_circuit_latencies_ms(run_dir: Path) -> List[float]:
    """
    Extract latency_ms for OK circuit_attempt in phase=="measure".
    """
    xs: List[float] = []
    files = list(_iter_jsonl_files(_candidate_circuit_files(run_dir)))
    for fp in files:
        try:
            for line in fp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if not isinstance(obj, dict):
                    continue
                if obj.get("event") != "circuit_attempt":
                    continue
                if obj.get("phase") != "measure":
                    continue
                if obj.get("status") != "ok":
                    continue
                v = obj.get("latency_ms")
                if v is None:
                    continue
                try:
                    xs.append(float(v))
                except Exception:
                    continue
        except Exception:
            continue
    return xs


# ----------------------------
# Run discovery + view selection
# ----------------------------
def find_runs(log_root: Path, modes: Optional[List[str]]) -> List[RunRow]:
    candidates = list(log_root.rglob("run_meta.json"))
    rows: List[RunRow] = []
    for meta_path in sorted(candidates):
        try:
            run_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        mode_tag = str(_safe_get(run_meta, "mode_tag", default="")).strip()
        node_scale_raw = str(
            _safe_get(run_meta, "node_scale", default=None)
            or _safe_get(run_meta, "relay_tier", default=None)
            or ""
        ).strip()

        if not mode_tag or not node_scale_raw:
            p_mode, p_scale = _infer_mode_and_scale_from_path(meta_path)
            mode_tag = mode_tag or p_mode
            node_scale_raw = node_scale_raw or p_scale

        if modes and mode_tag not in modes:
            continue

        node_scale_num = _parse_scale_num(node_scale_raw)

        concurrency = _safe_get(run_meta, "concurrency", default=None)
        measure_s = _safe_get(run_meta, "measure_s", default=None)

        summary = _safe_get(run_meta, "summary", default={}) or {}
        ok = _safe_get(summary, "ok", default=None)
        success_rate = _safe_get(summary, "success_rate", default=None)
        p95_total_ms = _safe_get(summary, "p95_total_ms", default=None)

        throughput = None
        if ok is not None and measure_s:
            try:
                throughput = float(ok) / float(measure_s)
            except Exception:
                throughput = None

        run_dir = meta_path.parent
        mem_p95_mb = mem_p95_from_resources(run_dir)

        rows.append(
            RunRow(
                run_dir=run_dir,
                mode_tag=mode_tag or "unknown",
                node_scale_raw=node_scale_raw or "unknown",
                node_scale_num=node_scale_num,
                concurrency=int(concurrency) if concurrency is not None else None,
                success_rate=float(success_rate) if success_rate is not None else None,
                ok=int(ok) if ok is not None else None,
                measure_s=float(measure_s) if measure_s is not None else None,
                throughput_ok_per_s=throughput,
                p95_total_ms=float(p95_total_ms) if p95_total_ms is not None else None,
                mem_p95_mb=mem_p95_mb,
            )
        )

    return rows


def choose_target_concurrency(rows: List[RunRow], explicit: Optional[int]) -> Optional[int]:
    if explicit is not None:
        return explicit
    freq: Dict[int, int] = {}
    for r in rows:
        if r.concurrency is None:
            continue
        freq[int(r.concurrency)] = freq.get(int(r.concurrency), 0) + 1
    if not freq:
        return None
    return sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def fixed_concurrency_view(rows: List[RunRow], target: int) -> List[RunRow]:
    """
    For each (mode, scale), keep one row with concurrency==target.
    If multiple runs exist, keep the one with larger ok, tie-break with lower p95 latency.
    """
    best: Dict[Tuple[str, str], RunRow] = {}
    for r in rows:
        if r.concurrency != target:
            continue
        k = (r.mode_tag, r.node_scale_raw)
        if k not in best:
            best[k] = r
            continue
        prev = best[k]
        prev_ok = prev.ok or 0
        cur_ok = r.ok or 0
        if cur_ok > prev_ok:
            best[k] = r
            continue
        if cur_ok == prev_ok:
            prev_p95 = prev.p95_total_ms if prev.p95_total_ms is not None else 10**18
            cur_p95 = r.p95_total_ms if r.p95_total_ms is not None else 10**18
            if cur_p95 < prev_p95:
                best[k] = r
    return list(best.values())


# ----------------------------
# Output helpers
# ----------------------------
def write_csv(rows: List[RunRow], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "node_scale_raw",
        "node_scale_num",
        "mode_tag",
        "concurrency",
        "success_rate",
        "throughput_ok_per_s",
        "p95_total_ms",
        "mem_p95_mb",
        "run_dir",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "node_scale_raw": r.node_scale_raw,
                    "node_scale_num": r.node_scale_num,
                    "mode_tag": r.mode_tag,
                    "concurrency": r.concurrency,
                    "success_rate": r.success_rate,
                    "throughput_ok_per_s": r.throughput_ok_per_s,
                    "p95_total_ms": r.p95_total_ms,
                    "mem_p95_mb": r.mem_p95_mb,
                    "run_dir": str(r.run_dir),
                }
            )


def _plot_vs_scale(view: List[RunRow], modes: List[str], metric: str, ylabel: str, title: str, out_path: Path) -> None:
    plt.figure()
    for mode in modes:
        xs: List[int] = []
        ys: List[float] = []
        for r in view:
            if r.mode_tag != mode:
                continue
            if r.node_scale_num is None:
                continue
            y = getattr(r, metric)
            if y is None or (isinstance(y, float) and (math.isnan(y) or math.isinf(y))):
                continue
            xs.append(int(r.node_scale_num))
            ys.append(float(y))
        if xs and ys:
            xs, ys = zip(*sorted(zip(xs, ys), key=lambda t: t[0]))
            plt.plot(list(xs), list(ys), marker="o", label=mode)

    plt.xlabel("Node scale")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, dpi=170)
    plt.close()


def _plot_tail_ccdf(lat_ms: List[float], title: str, out_path: Path, tail_start_pct: float = 90.0) -> None:
    """
    Tail CCDF: y = P(X >= x) on the tail (>= p_tail_start).
    """
    if not lat_ms:
        return

    lat_ms = sorted(lat_ms)
    n = len(lat_ms)

    x0 = _percentile(lat_ms, tail_start_pct)
    if x0 is None:
        x0 = lat_ms[0]

    xs = [x for x in lat_ms if x >= x0]
    if not xs:
        xs = lat_ms

    # CCDF for the tail samples
    xs_sorted = sorted(xs)
    m = len(xs_sorted)
    ys = []
    for i in range(m):
        # survival function with plotting position
        ys.append((m - i) / m)

    plt.figure()
    plt.plot(xs_sorted, ys, marker=".")
    plt.yscale("log")
    plt.xlabel("Latency (ms)")
    plt.ylabel("CCDF P(X >= x) [log scale]")
    plt.title(title)

    # annotate key percentiles
    for p in (95.0, 99.0, 99.9):
        v = _percentile(lat_ms, p)
        if v is not None:
            plt.axvline(v, linestyle="--")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, dpi=170)
    plt.close()


def plot_tail_for_largest_scale(view: List[RunRow], modes: List[str], out_dir: Path, target_concurrency: int) -> None:
    """
    For each mode, pick the row with the largest node_scale_num in the fixed-concurrency view,
    then plot the tail latency CCDF from circuits*.jsonl.
    """
    plots_dir = out_dir / "plots"
    for mode in modes:
        candidates = [r for r in view if r.mode_tag == mode and r.node_scale_num is not None]
        if not candidates:
            continue
        row = sorted(candidates, key=lambda r: r.node_scale_num)[-1]
        lat = iter_circuit_latencies_ms(row.run_dir)
        if not lat:
            continue
        _plot_tail_ccdf(
            lat_ms=lat,
            title=f"E2 tail latency CCDF ({mode}, scale={row.node_scale_raw}, concurrency={target_concurrency})",
            out_path=plots_dir / f"tail_ccdf_{mode}_scale{row.node_scale_raw}_c{target_concurrency}.png",
        )


# ----------------------------
# Main
# ----------------------------
def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-root", type=str, default="exp/deployment/e2_density/logs")
    ap.add_argument("--out-dir", type=str, default="analysis_out/e2")
    ap.add_argument("--target-concurrency", type=int, default=None)
    ap.add_argument("--modes", type=str, default="tor,torbox", help="Comma-separated, order matters for legend")
    args = ap.parse_args()

    log_root = Path(args.log_root)
    out_dir = Path(args.out_dir)
    modes = [m.strip() for m in args.modes.split(",") if m.strip()]

    rows = find_runs(log_root=log_root, modes=modes if modes else None)
    if not rows:
        print("No runs found. Check --log-root.")
        return

    target = choose_target_concurrency(rows, args.target_concurrency)
    if target is None:
        print("No concurrency found in run_meta; cannot build fixed-concurrency view.")
        return

    view = fixed_concurrency_view(rows, target)
    view = sorted(view, key=lambda r: (r.node_scale_num if r.node_scale_num is not None else 10**18, r.mode_tag))

    fixed_csv = out_dir / f"e2_fixed_c{target}.csv"
    write_csv(view, fixed_csv)

    plots_dir = out_dir / "plots"
    _plot_vs_scale(
        view=view,
        modes=modes,
        metric="throughput_ok_per_s",
        ylabel="OK circuits per second",
        title=f"E2 throughput vs node scale (concurrency={target})",
        out_path=plots_dir / f"throughput_vs_scale_c{target}.png",
    )
    _plot_vs_scale(
        view=view,
        modes=modes,
        metric="mem_p95_mb",
        ylabel="p95 memory (MB)",
        title=f"E2 memory p95 vs node scale (concurrency={target})",
        out_path=plots_dir / f"mem_p95_vs_scale_c{target}.png",
    )

    # Tail latency distribution plot
    plot_tail_for_largest_scale(view=view, modes=modes, out_dir=out_dir, target_concurrency=target)

    print(f"Fixed-concurrency CSV: {fixed_csv}")
    print(f"Plots saved in: {plots_dir.resolve()}")


if __name__ == "__main__":
    main()
