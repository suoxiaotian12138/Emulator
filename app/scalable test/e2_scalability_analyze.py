"""
Analyze E2 logs (fixed concurrency) for scalability and compare tor vs torbox.

Adapted directory layout:

    e2_density/logs/
      tor/
        <scale>/
          circuits/
          resources/
          run_meta.json
      torbox/
        <scale>/
          circuits/
          resources/
          run_meta.json

So:
- mode_tag := the directory directly under "logs" (e.g., tor, torbox)
- node_scale := the directory under mode_tag (e.g., 12, scale_9)

Outputs
- Markdown table to stdout (per run)
- CSV: <out_dir>/e2_scalability_runs.csv
- CSV: <out_dir>/e2_capacity_by_scale.csv
- Plots (PNG) in <out_dir>/plots/ (one set per node_scale):
  - throughput vs concurrency (tor vs torbox)
  - success_rate vs concurrency
  - p95_total_ms vs concurrency

Usage
python analyze_e2_scalability_compare.py --log-root exp/deployment/e2_density/logs --out-dir analysis_out
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt


@dataclass
class RunRow:
    run_dir: Path
    run_meta_path: Path

    mode_tag: str
    node_scale_raw: str
    node_scale_num: Optional[int]

    concurrency: Optional[int]
    warmup_s: Optional[float]
    measure_s: Optional[float]

    attempts_measure: Optional[int]
    ok: Optional[int]
    fail: Optional[int]
    drops: Optional[int]
    success_rate: Optional[float]

    p50_total_ms: Optional[float]
    p95_total_ms: Optional[float]
    p50_build_ms: Optional[float]
    p95_build_ms: Optional[float]

    throughput_ok_per_s: Optional[float]


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
    m = re.search(r"(\\d+)", s)
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


def find_runs(log_root: Path, mode_filter: Optional[List[str]]) -> List[RunRow]:
    if log_root.is_file() and log_root.name == "run_meta.json":
        candidates = [log_root]
    else:
        candidates = list(log_root.rglob("run_meta.json"))

    rows: List[RunRow] = []
    for meta_path in sorted(candidates):
        try:
            run_meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue

        mode_tag = str(_safe_get(run_meta, "mode_tag", default="")).strip()
        node_scale_raw = str(_safe_get(run_meta, "node_scale", default="")).strip()

        if not mode_tag or not node_scale_raw:
            p_mode, p_scale = _infer_mode_and_scale_from_path(meta_path)
            mode_tag = mode_tag or p_mode
            node_scale_raw = node_scale_raw or p_scale

        if mode_filter and mode_tag not in mode_filter:
            continue

        node_scale_num = _parse_scale_num(node_scale_raw)

        summary = _safe_get(run_meta, "summary", default={}) or {}

        concurrency = _safe_get(run_meta, "concurrency", default=None)
        warmup_s = _safe_get(run_meta, "warmup_s", default=None)
        measure_s = _safe_get(run_meta, "measure_s", default=None)

        ok = _safe_get(summary, "ok", default=None)
        throughput = None
        if ok is not None and measure_s:
            try:
                throughput = float(ok) / float(measure_s)
            except Exception:
                throughput = None

        rows.append(
            RunRow(
                run_dir=meta_path.parent,
                run_meta_path=meta_path,
                mode_tag=mode_tag or "unknown",
                node_scale_raw=node_scale_raw or "unknown",
                node_scale_num=node_scale_num,
                concurrency=int(concurrency) if concurrency is not None else None,
                warmup_s=float(warmup_s) if warmup_s is not None else None,
                measure_s=float(measure_s) if measure_s is not None else None,
                attempts_measure=_safe_get(summary, "attempts_measure", default=None),
                ok=ok,
                fail=_safe_get(summary, "fail", default=None),
                drops=_safe_get(summary, "drops", default=None),
                success_rate=_safe_get(summary, "success_rate", default=None),
                p50_total_ms=_safe_get(summary, "p50_total_ms", default=None),
                p95_total_ms=_safe_get(summary, "p95_total_ms", default=None),
                p50_build_ms=_safe_get(summary, "p50_build_ms", default=None),
                p95_build_ms=_safe_get(summary, "p95_build_ms", default=None),
                throughput_ok_per_s=throughput,
            )
        )

    return rows


def sort_rows(rows: List[RunRow]) -> List[RunRow]:
    def key(r: RunRow):
        scale_key = r.node_scale_num if r.node_scale_num is not None else 10**18
        conc_key = r.concurrency if r.concurrency is not None else 10**18
        return (scale_key, r.node_scale_raw, r.mode_tag, conc_key)

    return sorted(rows, key=key)


def write_runs_csv(rows: List[RunRow], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "mode_tag",
        "node_scale_raw",
        "node_scale_num",
        "concurrency",
        "warmup_s",
        "measure_s",
        "attempts_measure",
        "ok",
        "fail",
        "drops",
        "success_rate",
        "throughput_ok_per_s",
        "p50_total_ms",
        "p95_total_ms",
        "p50_build_ms",
        "p95_build_ms",
        "run_dir",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "mode_tag": r.mode_tag,
                    "node_scale_raw": r.node_scale_raw,
                    "node_scale_num": r.node_scale_num,
                    "concurrency": r.concurrency,
                    "warmup_s": r.warmup_s,
                    "measure_s": r.measure_s,
                    "attempts_measure": r.attempts_measure,
                    "ok": r.ok,
                    "fail": r.fail,
                    "drops": r.drops,
                    "success_rate": r.success_rate,
                    "throughput_ok_per_s": r.throughput_ok_per_s,
                    "p50_total_ms": r.p50_total_ms,
                    "p95_total_ms": r.p95_total_ms,
                    "p50_build_ms": r.p50_build_ms,
                    "p95_build_ms": r.p95_build_ms,
                    "run_dir": str(r.run_dir),
                }
            )


def _scales_present(rows: List[RunRow]) -> List[str]:
    return sorted({r.node_scale_raw for r in rows}, key=lambda s: _parse_scale_num(s) or 10**18)


def _fmt(v, nd=4):
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def print_markdown_overview(rows: List[RunRow]) -> None:
    rows = sort_rows(rows)
    headers = [
        "node_scale",
        "mode",
        "concurrency",
        "success_rate",
        "throughput_ok_per_s",
        "p95_total_ms",
        "run_dir",
    ]
    print("| " + " | ".join(headers) + " |")
    print("| " + " | ".join(["---"] * len(headers)) + " |")
    for r in rows:
        print(
            "| "
            + " | ".join(
                [
                    r.node_scale_raw,
                    r.mode_tag,
                    _fmt(r.concurrency, 0),
                    _fmt(r.success_rate, 4),
                    _fmt(r.throughput_ok_per_s, 4),
                    _fmt(r.p95_total_ms, 1),
                    str(r.run_dir),
                ]
            )
            + " |"
        )


def derive_capacity(
    rows: List[RunRow],
    *,
    min_success_rate: float,
    max_p95_total_ms: Optional[float],
) -> Dict[Tuple[str, str], Optional[int]]:
    g: Dict[Tuple[str, str], List[RunRow]] = {}
    for r in rows:
        g.setdefault((r.node_scale_raw, r.mode_tag), []).append(r)
    for k in g:
        g[k].sort(key=lambda x: (x.concurrency is None, x.concurrency or 0))

    cap: Dict[Tuple[str, str], Optional[int]] = {}
    for (scale, mode), rs in g.items():
        best: Optional[int] = None
        for r in rs:
            if r.concurrency is None or r.success_rate is None:
                continue
            if r.success_rate < min_success_rate:
                continue
            if max_p95_total_ms is not None and r.p95_total_ms is not None and r.p95_total_ms > max_p95_total_ms:
                continue
            if best is None or r.concurrency > best:
                best = r.concurrency
        cap[(scale, mode)] = best
    return cap


def write_capacity_csv(
    rows: List[RunRow],
    caps: Dict[Tuple[str, str], Optional[int]],
    out_path: Path,
    modes_order: List[str],
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    scales = _scales_present(rows)

    fields = ["node_scale"] + [f"capacity_{m}" for m in modes_order] + ["speedup_torbox_over_tor"]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for scale in scales:
            row = {"node_scale": scale}
            tor = None
            torbox = None
            for m in modes_order:
                c = caps.get((scale, m))
                row[f"capacity_{m}"] = c
                if m == "tor":
                    tor = c
                if m == "torbox":
                    torbox = c
            speedup = None
            if tor is not None and torbox is not None and tor != 0:
                try:
                    speedup = float(torbox) / float(tor)
                except Exception:
                    speedup = None
            row["speedup_torbox_over_tor"] = speedup
            w.writerow(row)


def _plot_two_modes(
    *,
    rows: List[RunRow],
    scale: str,
    metric: str,
    ylabel: str,
    title: str,
    out_path: Path,
    modes_order: List[str],
) -> None:
    plt.figure()
    for mode in modes_order:
        xs: List[int] = []
        ys: List[float] = []
        for r in rows:
            if r.node_scale_raw != scale or r.mode_tag != mode:
                continue
            x = r.concurrency
            y = getattr(r, metric)
            if x is None or y is None:
                continue
            xs.append(int(x))
            ys.append(float(y))
        if xs and ys:
            plt.plot(xs, ys, marker="o", label=mode)

    plt.xlabel("Concurrency (clients)")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.tight_layout()
    plt.savefig(out_path, dpi=160)
    plt.close()


def make_plots(rows: List[RunRow], out_dir: Path, modes_order: List[str]) -> None:
    scales = _scales_present(rows)
    plots_dir = out_dir / "plots"
    for scale in scales:
        _plot_two_modes(
            rows=rows,
            scale=scale,
            metric="throughput_ok_per_s",
            ylabel="OK circuits per second",
            title=f"E2 throughput vs concurrency at node_scale={scale}",
            out_path=plots_dir / f"throughput_scale_{scale}.png",
            modes_order=modes_order,
        )
        _plot_two_modes(
            rows=rows,
            scale=scale,
            metric="success_rate",
            ylabel="Success rate",
            title=f"E2 success rate vs concurrency at node_scale={scale}",
            out_path=plots_dir / f"success_rate_scale_{scale}.png",
            modes_order=modes_order,
        )
        _plot_two_modes(
            rows=rows,
            scale=scale,
            metric="p95_total_ms",
            ylabel="p95 total latency (ms)",
            title=f"E2 p95 total latency vs concurrency at node_scale={scale}",
            out_path=plots_dir / f"p95_total_ms_scale_{scale}.png",
            modes_order=modes_order,
        )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-root", type=str, default="exp/deployment/e2_density/logs")
    ap.add_argument("--out-dir", type=str, default="analysis_out", help="Output directory")

    ap.add_argument(
        "--modes",
        type=str,
        default="tor,torbox",
        help="Comma-separated mode tags to include, order matters for plots/capacity CSV",
    )

    ap.add_argument("--min-success-rate", type=float, default=0.99, help="Capacity success_rate threshold")
    ap.add_argument("--max-p95-total-ms", type=float, default=None, help="Optional latency constraint for capacity")

    ap.add_argument("--no-plots", action="store_true", help="Disable saving plots")
    args = ap.parse_args()

    log_root = Path(args.log_root)
    out_dir = Path(args.out_dir)

    modes_order = [m.strip() for m in args.modes.split(",") if m.strip()]
    mode_filter = modes_order if modes_order else None

    rows = find_runs(log_root=log_root, mode_filter=mode_filter)

    if not rows:
        print("No runs found. Check --log-root path.")
        return

    print_markdown_overview(rows)

    runs_csv = out_dir / "e2_scalability_runs.csv"
    write_runs_csv(sort_rows(rows), runs_csv)
    print(f"\\nRuns CSV written: {runs_csv}")

    caps = derive_capacity(
        rows,
        min_success_rate=args.min_success_rate,
        max_p95_total_ms=args.max_p95_total_ms,
    )
    cap_csv = out_dir / "e2_capacity_by_scale.csv"
    write_capacity_csv(rows, caps, cap_csv, modes_order)
    print(f"Capacity CSV written: {cap_csv}")

    print("\\nDerived capacity (max concurrency meeting constraints):")
    for scale in _scales_present(rows):
        parts = [f"scale={scale}"]
        for mode in modes_order:
            parts.append(f"{mode}={caps.get((scale, mode))}")
        print("  " + " ".join(parts))

    if not args.no_plots:
        make_plots(rows, out_dir, modes_order)
        print(f"Plots written in: {(out_dir / 'plots').resolve()}")


if __name__ == "__main__":
    main()
