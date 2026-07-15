#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib

matplotlib.use("TkAgg")
import matplotlib.pyplot as plt

# ============================================================================
# GLOBAL PLOT PARAMETERS
# ============================================================================
# Font settings
FONT_FAMILY = 'Arial'
FONT_WEIGHT = 'bold'
FONT_SIZE_LABEL = 18  # Axis labels
FONT_SIZE_TICK = 16  # Tick labels
FONT_SIZE_LEGEND = 14  # Legend text
FONT_SIZE_ANNOTATION = 13  # Sample size annotations

# Figure settings
FIG_WIDTH = 8.0
FIG_HEIGHT = 5.0
FIG_DPI = 300

# Line and marker styles
LINE_WIDTH = 2.5
MARKER_SIZE = 8
CAPSIZE = 5
CAPTHICK = 2

# Grid settings
GRID_ALPHA = 0.3
GRID_LINESTYLE = ':'
GRID_LINEWIDTH = 0.8

# Colors (professional color scheme)
COLOR_TOR = '#2E86AB'  # Blue
COLOR_SIM = '#A23B72'  # Purple
COLOR_IDEAL = '#6C757D'  # Gray

# ============================================================================
# ANALYSIS PARAMETERS
# ============================================================================
BANDWIDTH_ORDER = [0.5, 1.0, 2.0, 5.0]  # MiB/s
CONF_LEVEL_Z = 1.96  # 95% CI

# Each stream payload is 20 MiB (fixed, recommended)
PAYLOAD_BYTES = 20 * 1024 * 1024

# Duration sanity filters
MIN_DURATION_S = 0.001
MAX_DURATION_S = 10 * 60  # 10 minutes


def get_cmd(obj: dict) -> Optional[str]:
    meta = obj.get("meta")
    if not isinstance(meta, dict):
        return None
    cmd = meta.get("cell_cmd")
    if isinstance(cmd, str) and cmd:
        return cmd.upper()
    return None


def get_stream_key(obj: dict) -> Optional[str]:
    node_id = obj.get("node_id")
    meta = obj.get("meta")
    if not isinstance(node_id, str) or not isinstance(meta, dict):
        return None

    circ_id = meta.get("circ_id")
    stream_id = meta.get("stream_id")
    if circ_id is None or stream_id is None:
        return None

    try:
        circ_id_i = int(circ_id)
        stream_id_i = int(stream_id)
    except Exception:
        return None

    return f"{node_id}:{circ_id_i}:{stream_id_i}"


def parse_bandwidth_folder(name: str) -> Optional[float]:
    s = name.strip().lower()
    if not s.endswith("mb"):
        return None
    try:
        return float(s[:-2])
    except ValueError:
        return None


def iter_event_files(bw_dir: Path) -> List[Path]:
    """
    Read multiple event files under:
      <B>/events/events-*.jsonl
      <B>/events/*.jsonl
    Sorted by filename to respect your "file order" requirement.
    """
    events_dir = bw_dir / "events"
    if not events_dir.exists():
        return []
    files = list(events_dir.glob("events-*.jsonl")) + list(events_dir.glob("*.jsonl"))
    files = [p for p in files if p.is_file()]
    return sorted(set(files), key=lambda p: p.name)


def get_ts_ns(obj: dict) -> Optional[int]:
    v = obj.get("ts_mono_ns")
    if v is None:
        return None
    try:
        return int(v)
    except Exception:
        return None


@dataclass
class StreamAgg:
    start_ns: Optional[int] = None
    last_data_ns: Optional[int] = None


def compute_stream_throughputs_from_events(event_files: List[Path]) -> List[float]:
    """
    Start: first RELAY_CONNECTED timestamp of a stream
    End: last RELAY_DATA timestamp after the start
    Throughput: fixed 20 MiB / (end - start)
    """
    streams: Dict[str, StreamAgg] = {}

    for fp in event_files:
        with fp.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                ts = get_ts_ns(obj)
                cmd = get_cmd(obj)
                sk = get_stream_key(obj)
                if ts is None or cmd is None or sk is None:
                    continue

                agg = streams.get(sk)
                if agg is None:
                    agg = StreamAgg()
                    streams[sk] = agg

                if cmd == "RELAY_CONNECTED":
                    if agg.start_ns is None or ts < agg.start_ns:
                        agg.start_ns = ts
                    continue

                if cmd == "RELAY_DATA":
                    if agg.start_ns is None:
                        continue
                    if ts <= agg.start_ns:
                        continue
                    if agg.last_data_ns is None or ts > agg.last_data_ns:
                        agg.last_data_ns = ts
                    continue

    samples: List[float] = []
    for sk, agg in streams.items():
        if agg.start_ns is None or agg.last_data_ns is None:
            continue
        if agg.last_data_ns <= agg.start_ns:
            continue

        dur_s = (agg.last_data_ns - agg.start_ns) / 1_000_000_000.0
        if not (MIN_DURATION_S <= dur_s <= MAX_DURATION_S):
            continue

        thr_mibs = PAYLOAD_BYTES / dur_s / 1024.0 / 1024.0
        if math.isfinite(thr_mibs) and thr_mibs >= 0:
            samples.append(thr_mibs)

    return samples


def mean_and_ci95(values: List[float]) -> Tuple[float, float, int]:
    n = len(values)
    if n == 0:
        return (float("nan"), float("nan"), 0)
    mu = sum(values) / n
    if n < 2:
        return (mu, 0.0, n)
    var = sum((x - mu) ** 2 for x in values) / (n - 1)
    sd = math.sqrt(var)
    se = sd / math.sqrt(n)
    ci = CONF_LEVEL_Z * se
    return (mu, ci, n)


def collect_series_from_events(base_dir: Path) -> Dict[float, List[float]]:
    out: Dict[float, List[float]] = {}
    if not base_dir.exists():
        return out

    for child in sorted(base_dir.iterdir()):
        if not child.is_dir():
            continue
        B = parse_bandwidth_folder(child.name)
        if B is None:
            continue

        ev_files = iter_event_files(child)
        samples = compute_stream_throughputs_from_events(ev_files)
        out[B] = samples

    return out


def series_stats(series: Dict[float, List[float]], order: List[float]) -> Tuple[List[float], List[float], List[int]]:
    means, errs, ns = [], [], []
    for B in order:
        mu, ci, n = mean_and_ci95(series.get(B, []))
        means.append(mu)
        errs.append(ci)
        ns.append(n)
    return means, errs, ns


def setup_plot_style():
    """Configure global matplotlib settings"""
    plt.rcParams['font.family'] = FONT_FAMILY
    plt.rcParams['font.weight'] = FONT_WEIGHT
    plt.rcParams['font.size'] = FONT_SIZE_TICK
    plt.rcParams['axes.labelsize'] = FONT_SIZE_LABEL
    plt.rcParams['axes.titlesize'] = FONT_SIZE_LABEL
    plt.rcParams['xtick.labelsize'] = FONT_SIZE_TICK
    plt.rcParams['ytick.labelsize'] = FONT_SIZE_TICK
    plt.rcParams['legend.fontsize'] = FONT_SIZE_LEGEND
    plt.rcParams['axes.linewidth'] = 1.2
    plt.rcParams['grid.alpha'] = GRID_ALPHA
    plt.rcParams['axes.titleweight'] = 'bold'
    plt.rcParams['axes.labelweight'] = 'bold'  # 坐标轴标签 (X/Y label) 加粗
    plt.rcParams['axes.titleweight'] = 'bold'  # 图表标题加粗
    plt.rcParams['figure.titleweight'] = 'bold'  # 总标题加粗


def main() -> None:
    here = Path(__file__).resolve().parent
    exp_root = here / "exp" / "e1"

    tor_dir = exp_root / "tor"
    sim_dir = exp_root / "torbox"

    tor_series = collect_series_from_events(tor_dir)
    sim_series = collect_series_from_events(sim_dir)

    B = BANDWIDTH_ORDER
    tor_mu, tor_ci, tor_n = series_stats(tor_series, B)
    sim_mu, sim_ci, sim_n = series_stats(sim_series, B)

    print("=== Sanity ===")
    for label, series in [("Naive Tor", tor_series), ("Torbox", sim_series)]:
        for b in B:
            vals = series.get(b, [])
            if vals:
                print(f"{label} B={b}: n={len(vals)} mean={sum(vals) / len(vals):.4f} MiB/s")
            else:
                print(f"{label} B={b}: n=0 (no completed streams found)")

    # Setup plot style
    setup_plot_style()

    fig, ax = plt.subplots(figsize=(FIG_WIDTH, FIG_HEIGHT))

    # Plot data with error bars
    ax.errorbar(
        B, tor_mu, yerr=tor_ci,
        fmt='o-', capsize=CAPSIZE, capthick=CAPTHICK,
        linewidth=LINE_WIDTH, markersize=MARKER_SIZE,
        color=COLOR_TOR, ecolor=COLOR_TOR,
        label="Naive Tor (mean ± 95% CI)"
    )
    ax.errorbar(
        B, sim_mu, yerr=sim_ci,
        fmt='s--', capsize=CAPSIZE, capthick=CAPTHICK,
        linewidth=LINE_WIDTH, markersize=MARKER_SIZE,
        color=COLOR_SIM, ecolor=COLOR_SIM,
        label="Torbox (mean ± 95% CI)"
    )

    # Ideal line
    ax.plot(
        B, B,
        linestyle='-.', linewidth=LINE_WIDTH - 0.5,
        color=COLOR_IDEAL, alpha=0.7,
        label="Ideal: y = x"
    )

    # Labels
    ax.set_xlabel("Bottleneck bandwidth B (MiB/s)", fontsize=FONT_SIZE_LABEL)
    ax.set_ylabel("Measured throughput (MiB/s)", fontsize=FONT_SIZE_LABEL)

    # Ticks
    ax.set_xticks(B)
    ax.set_xticklabels([str(x).rstrip("0").rstrip(".") for x in B])

    # Grid
    ax.grid(True, which="both", linestyle=GRID_LINESTYLE,
            linewidth=GRID_LINEWIDTH, alpha=GRID_ALPHA)

    # Legend
    ax.legend(frameon=True, fancybox=False, edgecolor='gray',
              framealpha=0.95, loc='upper left')

    # Sample size annotations removed per user request

    plt.tight_layout()

    # Save outputs
    out_dir = here / "analysis_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_png = out_dir / "throughput_vs_bandwidth.png"
    out_pdf = out_dir / "throughput_vs_bandwidth.pdf"

    plt.savefig(out_png, dpi=FIG_DPI, bbox_inches='tight')
    plt.savefig(out_pdf, bbox_inches='tight')
    plt.show()

    print(f"[OK] Saved: {out_png}")
    print(f"[OK] Saved: {out_pdf}")


if __name__ == "__main__":
    main()