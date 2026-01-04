"""
分析 E3 长期稳态实验输出并生成时间序列图。

用法示例（默认直接复用 E3 运行时的日志目录，无需额外参数）::

    python "app/deployment test/e3_analysis_plot.py"

也可以覆盖默认值::

    python "app/deployment test/e3_analysis_plot.py" \
        --log-dir exp/deployment/e3/run123/logs \
        --out exp/deployment/e3/run123/figures \
        --bucket-minutes 5

脚本会读取 ``streams/``, ``resources/`` 和 ``stability/`` JSONL 日志，按时间窗口聚合：
- 流延迟的均值 / p90
- 流成功率
- CPU 与内存资源轨迹
- 稳定性心跳中的计数器（累积值）

输出包括一份聚合的 ``stability_analysis.json``（方便复用）以及多张 PNG 图，帮助观察是否存在
随时间漂移、资源泄漏或异常拐点。
"""
from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import matplotlib.pyplot as plt
import matplotlib
import os

# 学术风格字体配置
matplotlib.rcParams.update({
    "font.size": 14,
    "axes.labelsize": 15,
    "axes.titlesize": 16,
    "xtick.labelsize": 13,
    "ytick.labelsize": 13,
    "legend.fontsize": 12,
    "font.family": "serif",
    "font.serif": ["Times New Roman", "DejaVu Serif"],
})


@dataclass
class Bucket:
    index: int
    window_start: float
    window_end: float
    streams_total: int
    streams_ok: int
    streams_error: int
    stream_latency_mean_ms: Optional[float]
    stream_latency_p90_ms: Optional[float]
    mem_peak_mb: Optional[float]
    cpu_from_start_max_ms: Optional[float]
    stability_counters: List[dict]


def _load_jsonl_dir(dir_path: Path) -> List[dict]:
    records: List[dict] = []
    if not dir_path.exists():
        return records
    for file in sorted(dir_path.glob("*.jsonl")):
        try:
            with file.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            continue
    return records


def _default_log_dir() -> Path:
    ratio_label = os.environ.get("RATIO_LABEL", "50%")
    return Path("exp") / "deployment" / "e3" / ratio_label / "logs"


def _extract_ts(rec: dict, fallback: float) -> float:
    for key in ("ts", "timestamp", "time"):
        if key in rec:
            try:
                return float(rec[key])
            except (TypeError, ValueError):
                continue
    return fallback


def _bucketize(records: Iterable[dict], start_ts: float, bucket_s: float) -> Dict[int, List[dict]]:
    buckets: Dict[int, List[dict]] = defaultdict(list)
    for rec in records:
        ts = _extract_ts(rec, start_ts)
        bucket = max(0, int((ts - start_ts) // bucket_s))
        buckets[bucket].append(rec)
    return buckets


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


def analyze_logs(log_dir: Path, bucket_minutes: int) -> Tuple[List[Bucket], dict]:
    log_dir = log_dir.resolve()
    bucket_s = max(60, bucket_minutes * 60)

    streams = _load_jsonl_dir(log_dir / "streams")
    resources = _load_jsonl_dir(log_dir / "resources")
    stability_records = _load_jsonl_dir(log_dir / "stability")

    start_candidates: List[float] = []
    for rec in streams[:1] + resources[:1] + stability_records[:1]:
        start_candidates.append(_extract_ts(rec, 0.0))
    start_ts = min(start_candidates) if start_candidates else 0.0

    stream_buckets = _bucketize(streams, start_ts, bucket_s)
    resource_buckets = _bucketize(resources, start_ts, bucket_s)
    stability_buckets = _bucketize(stability_records, start_ts, bucket_s)

    buckets: List[Bucket] = []
    max_bucket_index = max(stream_buckets.keys() | resource_buckets.keys() | stability_buckets.keys(), default=-1)

    for idx in range(max_bucket_index + 1):
        window_start = start_ts + idx * bucket_s
        window_end = window_start + bucket_s

        sb = stream_buckets.get(idx, [])
        rb = resource_buckets.get(idx, [])
        hb = stability_buckets.get(idx, [])

        latencies = []
        for s in sb:
            val = s.get("latency_ms_total", s.get("dur_ms"))
            if isinstance(val, (int, float)):
                latencies.append(float(val))

        stream_ok = [s for s in sb if s.get("status") == "ok"]
        stream_err = [s for s in sb if s.get("status") not in (None, "ok")]

        mem_candidates: List[float] = []
        cpu_candidates: List[float] = []
        for r in rb:
            for key in ("total_mem_mb", "local_rss_mb", "vm_mem_mb"):
                val = r.get(key)
                if isinstance(val, (int, float)):
                    mem_candidates.append(float(val))
            for key in ("local_cpu_ms_from_start", "vm_cpu_ms_from_start"):
                val = r.get(key)
                if isinstance(val, (int, float)):
                    cpu_candidates.append(float(val))

        buckets.append(
            Bucket(
                index=idx,
                window_start=window_start,
                window_end=window_end,
                streams_total=len(sb),
                streams_ok=len(stream_ok),
                streams_error=len(stream_err),
                stream_latency_mean_ms=(sum(latencies) / len(latencies)) if latencies else None,
                stream_latency_p90_ms=_percentile(latencies, 90.0) if latencies else None,
                mem_peak_mb=max(mem_candidates) if mem_candidates else None,
                cpu_from_start_max_ms=max(cpu_candidates) if cpu_candidates else None,
                stability_counters=hb,
            )
        )

    overall = {
        "duration_min": (max(b.window_end for b in buckets) - start_ts) / 60 if buckets else 0,
        "total_streams": sum(b.streams_total for b in buckets),
        "total_stream_errors": sum(b.streams_error for b in buckets),
        "mem_peak_mb": max((b.mem_peak_mb for b in buckets if b.mem_peak_mb is not None), default=None),
    }

    analysis = {
        "log_dir": str(log_dir),
        "bucket_minutes": bucket_minutes,
        "started_at": start_ts,
        "buckets": [b.__dict__ for b in buckets],
        "overall": overall,
    }

    return buckets, analysis


def _ensure_out_dir(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)


def _minutes_from_start(bucket: Bucket, start_ts: float) -> float:
    return (bucket.window_start - start_ts) / 60


def _plot_stream_latency(buckets: List[Bucket], start_ts: float, out: Path) -> None:
    x = [_minutes_from_start(b, start_ts) for b in buckets]
    mean = [b.stream_latency_mean_ms for b in buckets]
    p90 = [b.stream_latency_p90_ms for b in buckets]

    plt.figure(figsize=(11, 6))
    plt.plot(x, mean, label="mean latency (ms)", marker="o", linewidth=2)
    plt.plot(x, p90, label="p90 latency (ms)", marker="s", linewidth=2)
    plt.xlabel("Time (minutes)")
    plt.ylabel("Latency (ms)")
    plt.title("Stream latency drift over time")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out / "stream_latency.png", dpi=200)
    plt.close()


def _plot_stream_success(buckets: List[Bucket], start_ts: float, out: Path) -> None:
    x = [_minutes_from_start(b, start_ts) for b in buckets if b.streams_total > 0]
    ratios = [
        (b.streams_ok / b.streams_total) if b.streams_total else 0.0
        for b in buckets
        if b.streams_total > 0
    ]
    totals = [b.streams_total for b in buckets if b.streams_total > 0]

    plt.figure(figsize=(11, 6))
    plt.plot(x, ratios, marker="o", linewidth=2, color="#4daf4a", label="success ratio")
    plt.xlabel("Time (minutes)")
    plt.ylabel("Success ratio")
    plt.ylim(0, 1.05)
    plt.title("Stream success ratio per bucket")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend(loc="lower left")
    ax2 = plt.twinx()
    ax2.bar(x, totals, alpha=0.3, color="#377eb8", label="streams per bucket")
    ax2.set_ylabel("Streams per bucket")
    lines, labels = plt.gca().get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    plt.legend(lines + lines2, labels + labels2, loc="upper right")
    plt.tight_layout()
    plt.savefig(out / "stream_success.png", dpi=200)
    plt.close()


def _plot_resources(buckets: List[Bucket], start_ts: float, out: Path) -> None:
    x = [_minutes_from_start(b, start_ts) for b in buckets]
    mem = [b.mem_peak_mb for b in buckets]
    cpu = [b.cpu_from_start_max_ms for b in buckets]

    plt.figure(figsize=(11, 6))
    plt.plot(x, mem, marker="o", linewidth=2, color="#e41a1c", label="peak memory (MB)")
    plt.xlabel("Time (minutes)")
    plt.ylabel("Memory (MB)")
    plt.title("Resource usage over time")
    plt.grid(True, linestyle="--", alpha=0.6)

    ax2 = plt.twinx()
    ax2.plot(x, cpu, marker="s", linewidth=2, color="#984ea3", label="CPU from start (ms)")
    ax2.set_ylabel("CPU time (ms from start)")

    lines1, labels1 = plt.gca().get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    plt.legend(lines1 + lines2, labels1 + labels2, loc="upper left")
    plt.tight_layout()
    plt.savefig(out / "resources.png", dpi=200)
    plt.close()


def _collect_stability_series(buckets: List[Bucket], start_ts: float) -> Dict[str, List[Tuple[float, float]]]:
    series: Dict[str, List[Tuple[float, float]]] = defaultdict(list)
    for b in buckets:
        t_min = _minutes_from_start(b, start_ts)
        for rec in sorted(b.stability_counters, key=lambda r: _extract_ts(r, b.window_start)):
            for key, val in rec.items():
                if key in {"ts", "timestamp", "time", "elapsed_s", "kind", "ratio_label"}:
                    continue
                if isinstance(val, (int, float)):
                    series[key].append((t_min, float(val)))
    return series


def _plot_stability_counters(buckets: List[Bucket], start_ts: float, out: Path) -> None:
    series = _collect_stability_series(buckets, start_ts)
    if not series:
        return

    plt.figure(figsize=(12, 7))
    for key, points in series.items():
        points = sorted(points, key=lambda p: p[0])
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        plt.plot(xs, ys, marker="o", linewidth=2, label=key)

    plt.xlabel("Time (minutes)")
    plt.ylabel("Counter (cumulative)")
    plt.title("Stability heartbeat counters")
    plt.grid(True, linestyle="--", alpha=0.6)
    plt.legend(ncol=2)
    plt.tight_layout()
    plt.savefig(out / "stability_counters.png", dpi=200)
    plt.close()


def save_analysis(analysis: dict, out_path: Path) -> None:
    try:
        out_path.write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        print(f"[analyze] wrote {out_path}")
    except Exception as exc:
        print(f"[analyze] failed to write {out_path}: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze E3 long-run stability logs and plot drift metrics")
    parser.add_argument("--log-dir", type=Path, help="E3 log directory containing JSONL files")
    parser.add_argument("--out", type=Path, help="Output directory for figures (default: <log_dir>/figures)")
    parser.add_argument(
        "--bucket-minutes",
        type=int,
        default=5,
        help="Aggregation window size in minutes (default: 5)",
    )
    args = parser.parse_args()

    log_dir = args.log_dir or _default_log_dir()
    out_dir = args.out or (log_dir / "figures")
    _ensure_out_dir(out_dir)

    buckets, analysis = analyze_logs(log_dir, args.bucket_minutes)
    save_analysis(analysis, log_dir / "stability_analysis.json")

    if not buckets:
        print("[analyze] no buckets generated; check log directory")
        return

    start_ts = analysis.get("started_at", 0.0)
    _plot_stream_latency(buckets, start_ts, out_dir)
    _plot_stream_success(buckets, start_ts, out_dir)
    _plot_resources(buckets, start_ts, out_dir)
    _plot_stability_counters(buckets, start_ts, out_dir)
    print(f"[analyze] figures written to {out_dir}")


if __name__ == "__main__":
    main()