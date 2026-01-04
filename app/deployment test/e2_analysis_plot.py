"""
Analyze E2 fixed-pacing experiment outputs and generate comparison plots.

The script expects one or more ``run_meta.json`` files produced by the E2
experiment (``e2_fixed_pacing.py``). It automatically discovers runs under the
root directory (default: ``exp/deployment/e2``), groups them by replacement
ratio, and produces per-ratio summary statistics and figures. The plotting code
is resilient to partial data: if only a single ratio (e.g., only ``0%`` or only
``100%``) is available, it still emits the available plots.

Produced outputs (written under ``--out``):
- ``circuit_build_latency.png``: p50/p90/p99 circuit build times per ratio.
- ``cpu_per_circuit.png``: CPU milliseconds consumed per successfully built
  circuit (local process + optional VM samples).
- ``stream_latency.png``: average and p90 stream completion latency per ratio.
- ``resource_memory.png``: peak observed memory (local+VM) per ratio (if data
  present).

Run example::

    python "app/deployment test/e2_analysis_plot.py" \
        --root exp/deployment/e2 --out exp/deployment/e2/figures

  You can also point directly at specific ``run_meta.json`` files::

      python "app/deployment test/e2_analysis_plot.py" --run exp/deployment/e2/50%/logs/run_meta.json
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import matplotlib.pyplot as plt


@dataclass
class RunRecords:
    ratio_label: str
    circuits: List[dict]
    streams: List[dict]
    resources: List[dict]
    source: Path


def _fmt(value: Optional[float]) -> str:
    return f"{value:.2f}" if value is not None else "nan"


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    pct = max(0.0, min(100.0, pct))
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct / 100.0
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return ordered[int(pos)]
    low_val = ordered[lower]
    high_val = ordered[upper]
    return low_val + (high_val - low_val) * (pos - lower)


def _load_jsonl_files(dir_path: Path) -> List[dict]:
    records: List[dict] = []
    if not dir_path.exists():
        return records
    for file in sorted(dir_path.glob("*.jsonl")):
        with file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def _normalize_log_dir(meta_path: Path, meta: dict) -> Path:
    log_dir = meta.get("log_dir")
    if log_dir:
        return Path(log_dir)
    # Fallback: if run_meta.json lives under logs/, use parent
    if meta_path.parent.name == "logs":
        return meta_path.parent
    # Fallback: sibling logs directory
    sibling = meta_path.parent / "logs"
    if sibling.exists():
        return sibling
    return meta_path.parent


def load_run(meta_path: Path) -> Optional[RunRecords]:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    ratio_label = meta.get("ratio_label") or meta_path.parent.name
    log_dir = _normalize_log_dir(meta_path, meta)

    circuits = _load_jsonl_files(log_dir / "circuits")
    streams = _load_jsonl_files(log_dir / "streams")
    resources = _load_jsonl_files(log_dir / "resources")
    if not any((circuits, streams, resources)):
        return None

    return RunRecords(
        ratio_label=str(ratio_label),
        circuits=circuits,
        streams=streams,
        resources=resources,
        source=meta_path,
    )


def discover_runs(root: Path, explicit_meta: Iterable[Path]) -> List[RunRecords]:
    runs: List[RunRecords] = []
    searched: List[Path] = []
    for meta in explicit_meta:
        meta_path = meta if meta.name == "run_meta.json" else meta / "run_meta.json"
        searched.append(meta_path)
        rec = load_run(meta_path)
        if rec:
            runs.append(rec)

    if not explicit_meta:
        for meta_path in root.rglob("run_meta.json"):
            rec = load_run(meta_path)
            if rec:
                runs.append(rec)
                searched.append(meta_path)

    if not runs:
        print("[WARN] No runs found. Checked:")
        for m in searched:
            print(f"  - {m}")
    return runs


def summarize_ratio(run: RunRecords) -> dict:
    circuits = [c for c in run.circuits if c.get("success")]
    build_ms = [float(c.get("build_ms", 0.0)) for c in circuits if "build_ms" in c]

    streams_ok = [s for s in run.streams if s.get("status") == "ok"]
    stream_latency = [float(s["latency_ms_total"]) for s in streams_ok if "latency_ms_total" in s]

    local_cpu = [float(r.get("local_cpu_ms_from_start", 0.0)) for r in run.resources if "local_cpu_ms_from_start" in r]
    vm_cpu = [float(r.get("vm_cpu_ms_from_start", 0.0)) for r in run.resources if "vm_cpu_ms_from_start" in r]
    cpu_total_ms = (max(local_cpu) if local_cpu else 0.0) + (max(vm_cpu) if vm_cpu else 0.0)

    peak_mem_mb_candidates = []
    for r in run.resources:
        for key in ("total_mem_mb", "local_rss_mb", "vm_mem_mb"):
            val = r.get(key)
            if isinstance(val, (int, float)):
                peak_mem_mb_candidates.append(float(val))
    peak_mem_mb = max(peak_mem_mb_candidates) if peak_mem_mb_candidates else None

    circuits_count = len(circuits)
    cpu_per_circuit = cpu_total_ms / circuits_count if circuits_count and cpu_total_ms else None

    return {
        "ratio": run.ratio_label,
        "build_ms": build_ms,
        "build_quantiles": {
            "p50": _percentile(build_ms, 50),
            "p90": _percentile(build_ms, 90),
            "p99": _percentile(build_ms, 99),
        },
        "circuit_success": circuits_count,
        "streams_ok": len(streams_ok),
        "stream_latency": stream_latency,
        "stream_latency_avg": sum(stream_latency) / len(stream_latency) if stream_latency else None,
        "stream_latency_p90": _percentile(stream_latency, 90),
        "cpu_total_ms": cpu_total_ms if cpu_total_ms else None,
        "cpu_per_circuit": cpu_per_circuit,
        "peak_mem_mb": peak_mem_mb,
    }


def _prepare_bar_positions(n_groups: int, n_series: int, width: float = 0.2):
    base = list(range(n_groups))
    offsets = [((i - (n_series - 1) / 2) * width) for i in range(n_series)]
    return base, offsets


def plot_circuit_build(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = list(summary.keys())
    if not ratios:
        return

    labels = [summary[r]["ratio"] for r in ratios]
    metrics = [summary[r]["build_quantiles"] for r in ratios]
    series = ["p50", "p90", "p99"]

    x_base, offsets = _prepare_bar_positions(len(ratios), len(series))
    fig, ax = plt.subplots(figsize=(10, 6))

    for idx, key in enumerate(series):
        values = [(metrics[i].get(key) or 0) for i in range(len(ratios))]
        ax.bar([x + offsets[idx] for x in x_base], values, width=0.2, label=key.upper())

    ax.set_xticks(x_base)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Circuit build latency (ms)")
    ax.set_title("E2 circuit build latency quantiles")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path / "circuit_build_latency.png", dpi=150)
    plt.close(fig)


def plot_cpu(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = list(summary.keys())
    values = [summary[r].get("cpu_per_circuit") for r in ratios]
    if not any(v is not None for v in values):
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(ratios, [(v or 0) for v in values], color="#4C72B0")
    ax.set_ylabel("CPU ms per built circuit")
    ax.set_title("Per-circuit CPU cost (local + VM)")
    fig.tight_layout()
    fig.savefig(out_path / "cpu_per_circuit.png", dpi=150)
    plt.close(fig)


def plot_stream_latency(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = list(summary.keys())
    avg_values = [summary[r].get("stream_latency_avg") for r in ratios]
    p90_values = [summary[r].get("stream_latency_p90") for r in ratios]
    if not any(v is not None for v in avg_values):
        return

    x_base, offsets = _prepare_bar_positions(len(ratios), 2, width=0.3)
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([x + offsets[0] for x in x_base], [(v or 0) for v in avg_values], width=0.3, label="mean")
    ax.bar([x + offsets[1] for x in x_base], [(v or 0) for v in p90_values], width=0.3, label="p90")
    ax.set_xticks(x_base)
    ax.set_xticklabels(ratios)
    ax.set_ylabel("Stream completion latency (ms)")
    ax.set_title("Stream latency per replacement ratio")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path / "stream_latency.png", dpi=150)
    plt.close(fig)


def plot_memory(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = list(summary.keys())
    mem_values = [summary[r].get("peak_mem_mb") for r in ratios]
    if not any(v is not None for v in mem_values):
        return

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(ratios, [(v or 0) for v in mem_values], color="#55A868")
    ax.set_ylabel("Peak memory usage (MB)")
    ax.set_title("Peak total memory (local + VM)")
    fig.tight_layout()
    fig.savefig(out_path / "resource_memory.png", dpi=150)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze E2 fixed-pacing experiment logs")
    parser.add_argument("--root", type=Path, default=Path("exp/deployment/e2"), help="Root directory containing run_meta.json files")
    parser.add_argument("--run", dest="runs", action="append", type=Path, default=[], help="Optional explicit run_meta.json paths or their parent dirs")
    parser.add_argument("--out", type=Path, default=Path("exp/deployment/e2/figures"), help="Directory to write figures and summaries")
    args = parser.parse_args()

    runs = discover_runs(args.root, args.runs)
    if not runs:
        return

    runs_by_ratio: Dict[str, List[RunRecords]] = defaultdict(list)
    for run in runs:
        runs_by_ratio[run.ratio_label].append(run)

    summary: Dict[str, dict] = {}
    for ratio, ratio_runs in sorted(runs_by_ratio.items()):
        merged = RunRecords(
            ratio_label=ratio,
            circuits=[],
            streams=[],
            resources=[],
            source=ratio_runs[0].source,
        )
        for r in ratio_runs:
            merged.circuits.extend(r.circuits)
            merged.streams.extend(r.streams)
            merged.resources.extend(r.resources)
        summary[ratio] = summarize_ratio(merged)

    args.out.mkdir(parents=True, exist_ok=True)

    print("[Summary]")
    for ratio, metrics in summary.items():
        print(f"- {ratio}:")
        build = metrics["build_quantiles"]
        print(
            f"  circuits={metrics['circuit_success']} build_ms p50={_fmt(build['p50'])} "
            f"p90={_fmt(build['p90'])} p99={_fmt(build['p99'])}"
        )
        print(
            f"  streams_ok={metrics['streams_ok']} latency_avg={_fmt(metrics['stream_latency_avg'])} "
            f"latency_p90={_fmt(metrics['stream_latency_p90'])}"
        )
        if metrics.get("cpu_total_ms") is not None:
            print(
                f"  cpu_total_ms={_fmt(metrics['cpu_total_ms'])} cpu_per_circuit={_fmt(metrics['cpu_per_circuit'])}"
            )
        if metrics.get("peak_mem_mb") is not None:
            print(f"  peak_mem_mb={_fmt(metrics['peak_mem_mb'])}")

    plot_circuit_build(summary, args.out)
    plot_cpu(summary, args.out)
    plot_stream_latency(summary, args.out)
    plot_memory(summary, args.out)


if __name__ == "__main__":
    main()