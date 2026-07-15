import argparse
import json
from pathlib import Path
import matplotlib
import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl

matplotlib.use("TkAgg")

# ===================== Configuration =====================
TOP_WINDOW_MS = 1000  # Default top panel time window

FONT = {
    "title": 20,
    "label": 17,
    "tick": 18,
    "legend": 18,
    "anno": 18,
    "stats": 15,
}

mpl.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.unicode_minus": False,
    "font.size": FONT["tick"],
    "font.weight": "semibold",
    "axes.titlesize": FONT["title"],
    "axes.titleweight": "bold",
    "axes.labelsize": FONT["label"],
    "axes.labelweight": "bold",
    "xtick.labelsize": FONT["tick"],
    "ytick.labelsize": FONT["tick"],
    "axes.linewidth": 1.2,
    "xtick.major.width": 1.1,
    "ytick.major.width": 1.1,
    "xtick.major.size": 6,
    "ytick.major.size": 6,
    "text.antialiased": True,
    "lines.antialiased": True,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

# ===================== Data Loading =====================
RAW_SENDME_PREFIX = "# RAW_SENDME_JSON "
AVG_SENDME_FILENAME = "avg_sendme_metrics.txt"
ROUND_SENDME_FILENAME = "sendme_metrics.txt"


def _resolve_metrics_file(base: Path, filename: str, round_idx: int | None, prefer_avg: bool = True) -> Path:
    """Resolve metrics file path with fallback logic."""
    if base.is_file():
        return base

    if prefer_avg:
        avg_candidate = base / AVG_SENDME_FILENAME
        if avg_candidate.exists():
            return avg_candidate

    if round_idx is not None:
        candidate = base / f"round_{round_idx:03d}" / filename
        if candidate.exists():
            return candidate

    if (base / filename).exists():
        return base / filename

    rounds = sorted(base.glob("round_*/"))
    if rounds:
        candidate = rounds[-1] / filename
        if candidate.exists():
            return candidate

    raise FileNotFoundError(f"Unable to locate {filename} under {base}")


def _load_sendme_metrics(metrics_root: Path, round_idx: int | None) -> tuple[dict, Path]:
    path = _resolve_metrics_file(metrics_root, ROUND_SENDME_FILENAME, round_idx)
    payload_line = next(
        (line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith(RAW_SENDME_PREFIX)),
        None,
    )
    if not payload_line:
        raise ValueError(f"Missing RAW_SENDME_JSON in {path}")
    return json.loads(payload_line[len(RAW_SENDME_PREFIX):]), path



# ===================== Data Processing =====================
def _window_curve(window_trace, t_max):
    """
    Extract window curve from event-driven trace for step plotting.

    Args:
        window_trace: Dict with "time_ms" and "window" lists
        t_max: Maximum time to display

    Returns:
        (time_array, window_array) - raw data points for step plot
    """
    times = np.array(window_trace.get("time_ms", []), dtype=float)
    values = np.array(window_trace.get("window", []), dtype=float)

    if len(times) == 0 or len(values) == 0:
        print("WARNING: Empty window trace, returning flat line at 1000")
        return np.array([0, t_max]), np.array([1000.0, 1000.0])

    if t_max <= 0:
        t_max = max(times[-1], 1.0)

    # Crop to time window
    mask = times <= t_max
    times = times[mask]
    values = values[mask]

    if len(times) == 0:
        print("WARNING: No points within t_max, returning flat line")
        init_val = values[0] if len(values) > 0 else 1000.0
        return np.array([0, t_max]), np.array([init_val, init_val])

    return times, values


def _cdf_from_timestamps(timestamps_ms):
    """
    Generate CDF from timestamps in milliseconds.
    Assumes timestamps_ms are already RELATIVE times (>=0).
    """
    if not timestamps_ms or len(timestamps_ms) == 0:
        return np.array([]), np.array([])

    times = np.sort(np.array(timestamps_ms, dtype=float))

    # If times look like absolute epoch ms (very large), rebase to start at 0
    if times[0] > 1e6 or times[-1] > 1e7:
        times = times - times[0]

    # If times are negative, also rebase to start at 0
    if times[0] < 0:
        times = times - times[0]

    n = len(times)
    cdf = np.arange(1, n + 1) / n

    times = np.concatenate([[0.0], times])
    cdf = np.concatenate([[0.0], cdf])
    return times, cdf


def _cdf_from_intervals(intervals_ms):
    """
    Generate CDF from intervals (showing interval distribution).

    This is the INTERVAL DISTRIBUTION, not temporal accumulation.
    X-axis is interval length, Y-axis is proportion of intervals <= X.

    Args:
        intervals_ms: List of interval values in ms

    Returns:
        (interval_array, cdf_array)
    """
    if not intervals_ms or len(intervals_ms) == 0:
        return np.array([]), np.array([])

    arr = np.sort(np.array(intervals_ms, dtype=float))
    cdf = np.arange(1, len(arr) + 1) / len(arr)
    return arr, cdf


def _validate_trace(trace, label):
    """Validate window trace data."""
    if not trace:
        print(f"ERROR [{label}]: window_trace_ms is missing or empty")
        return False

    times = trace.get("time_ms", [])
    windows = trace.get("window", [])

    if len(times) == 0 or len(windows) == 0:
        print(f"ERROR [{label}]: window_trace_ms has empty time_ms or window arrays")
        return False

    if len(times) != len(windows):
        print(f"WARNING [{label}]: time_ms and window arrays have different lengths")

    if len(times) < 2:
        print(f"WARNING [{label}]: window_trace_ms has only {len(times)} points")

    # Check for both decrements and increments
    if len(windows) > 1:
        has_decrease = any(windows[i] < windows[i - 1] for i in range(1, len(windows)))
        has_increase = any(windows[i] > windows[i - 1] for i in range(1, len(windows)))

        if not has_decrease:
            print(f"WARNING [{label}]: No window decrements detected (missing RELAY_DATA?)")
        if not has_increase:
            print(f"WARNING [{label}]: No window increments detected (missing circuit SENDME?)")

    return True


# ===================== Plotting =====================
def plot_figures(
        metrics_root: Path,
        round_idx: int | None,
        out_dir: Path,
        top_window_ms: float | None = None,
) -> None:
    """
    Generate comparison plots from semantic analysis outputs.

    Args:
        metrics_root: Path to semantic_log_analysis outputs
        round_idx: Specific round to plot (None for avg)
        out_dir: Output directory for plots
        top_window_ms: Time window for top panel (None = full)

    Note: Always uses step plot (drawstyle='steps-post') to accurately
          represent the discrete nature of window changes.
    """
    payload, src_path = _load_sendme_metrics(metrics_root, round_idx)
    print(f"[send_me] loaded metrics from: {src_path}")

    if top_window_ms is None:
        top_window_ms = TOP_WINDOW_MS

    payload, src_path = _load_sendme_metrics(metrics_root, round_idx)

    # Extract data
    tor_data = payload.get("Tor", {})
    tb_data = payload.get("TorBox", {})

    # Get base timestamps (for converting to relative time)
    tor_base_ts = tor_data.get("base_ts", 0.0)
    tb_base_ts = tb_data.get("base_ts", 0.0)

    # Get timestamps (absolute time of SENDME events)
    tor_timestamps = tor_data.get("timestamps", [])
    tb_timestamps = tb_data.get("timestamps", [])

    # Convert to milliseconds relative to base
    tor_timestamps_ms = [(t - (tor_base_ts or 0.0)) * 1000.0 for t in tor_timestamps]
    tb_timestamps_ms = [(t - (tb_base_ts or 0.0)) * 1000.0 for t in tb_timestamps]

    # Extract window traces
    tor_trace = tor_data.get("window_trace_ms")
    tb_trace = tb_data.get("window_trace_ms")

    # Validate traces
    if not _validate_trace(tor_trace, "Tor"):
        raise ValueError("Tor window_trace_ms validation failed. Check semantic_log_analysis output.")
    if not _validate_trace(tb_trace, "TorBox"):
        raise ValueError("TorBox window_trace_ms validation failed. Check semantic_log_analysis output.")

    # Get intervals for statistics (not for CDF plotting)
    tor_intervals = tor_data.get("intervals", [])
    tb_intervals = tb_data.get("intervals", [])

    # Convert to ms
    tor_intervals_ms = [v * 1000.0 for v in tor_intervals] if tor_intervals else []
    tb_intervals_ms = [v * 1000.0 for v in tb_intervals] if tb_intervals else []

    # Statistics
    def _safe_float(val):
        return float("nan") if val is None else float(val)

    tor_mean = _safe_float(tor_data.get("mean"))
    tb_mean = _safe_float(tb_data.get("mean"))
    tor_median = _safe_float(tor_data.get("median"))
    tb_median = _safe_float(tb_data.get("median"))
    tor_count = tor_data.get("count", 0)
    tb_count = tb_data.get("count", 0)

    # Determine time range for plotting
    tor_times = tor_trace.get("time_ms", [])
    tb_times = tb_trace.get("time_ms", [])
    t_max = max(
        max(tor_times) if tor_times else 0,
        max(tb_times) if tb_times else 0,
    ) + 10.0

    # Find first change point for alignment
    def _first_change_time(trace):
        times = trace.get("time_ms", []) if trace else []
        return times[1] if len(times) >= 2 else 0.0

    start_candidates = [
        v for v in (_first_change_time(tor_trace), _first_change_time(tb_trace))
        if v is not None
    ]
    start_ms = max(0.0, min(start_candidates) - 20.0) if start_candidates else 0.0

    # Generate window curves (no interpolation - use raw event points)
    t_tor, tor_window = _window_curve(tor_trace, t_max)
    t_tb, torbox_window = _window_curve(tb_trace, t_max)

    # Crop to display window
    if top_window_ms is not None and top_window_ms > 0:
        end_ms = start_ms + top_window_ms

        mask_tor = (t_tor >= start_ms) & (t_tor <= end_ms)
        t_tor_plot = t_tor[mask_tor]
        tor_window_plot = tor_window[mask_tor]

        mask_tb = (t_tb >= start_ms) & (t_tb <= end_ms)
        t_tb_plot = t_tb[mask_tb]
        torbox_window_plot = torbox_window[mask_tb]

        t_max_plot = end_ms
    else:
        t_tor_plot = t_tor
        tor_window_plot = tor_window
        t_tb_plot = t_tb
        torbox_window_plot = torbox_window
        t_max_plot = t_max

    # If timestamps are missing, reconstruct them from intervals
    if (not tor_timestamps_ms) and tor_intervals_ms:
        tor_timestamps_ms = np.cumsum(np.array(tor_intervals_ms, dtype=float)).tolist()

    if (not tb_timestamps_ms) and tb_intervals_ms:
        tb_timestamps_ms = np.cumsum(np.array(tb_intervals_ms, dtype=float)).tolist()

    # Debug prints (optional but useful)
    print(f"[Tor] timestamps_ms={len(tor_timestamps_ms)} intervals_ms={len(tor_intervals_ms)}")
    print(f"[TorBox] timestamps_ms={len(tb_timestamps_ms)} intervals_ms={len(tb_intervals_ms)}")
    if tor_timestamps_ms:
        print(f"[Tor] t_ms range: {tor_timestamps_ms[0]:.3f} .. {tor_timestamps_ms[-1]:.3f}")
    if tb_timestamps_ms:
        print(f"[TorBox] t_ms range: {tb_timestamps_ms[0]:.3f} .. {tb_timestamps_ms[-1]:.3f}")


    # Generate CDFs from timestamps (temporal accumulation)
    x_tor, cdf_tor = _cdf_from_timestamps(tor_timestamps_ms)
    x_tb, cdf_tb = _cdf_from_timestamps(tb_timestamps_ms)

    # SENDME threshold
    threshold = 100

    # ===================== Create Figure =====================
    fig = plt.figure(figsize=(14, 9.2))
    gs = fig.add_gridspec(2, 1, height_ratios=[1.05, 1.20], hspace=0.35)

    ax1 = fig.add_subplot(gs[0])  # Top: Window trace
    ax2 = fig.add_subplot(gs[1])  # Bottom: Interval CDF

    # ---- Top Panel: Window Dynamics ----
    # Use drawstyle='steps-post' to show true step behavior
    l1, = ax1.plot(
        t_tor_plot, tor_window_plot,
        linewidth=2.8,
        drawstyle='steps-post',  # CRITICAL: shows actual step changes
        label="Tor Circuit Window",
        zorder=3
    )
    l2, = ax1.plot(
        t_tb_plot, torbox_window_plot,
        linestyle="--",
        linewidth=2.8,
        drawstyle='steps-post',  # CRITICAL: shows actual step changes
        label="TorBox Circuit Window",
        zorder=3
    )

    # SENDME threshold line
    ax1.axhline(
        threshold,
        linewidth=2.0,
        linestyle=(0, (5, 3)),
        color="gray",
        alpha=0.7,
        zorder=1
    )

    ax1.text(
        0.98, 0.10,
        f"SENDME threshold ({threshold})",
        transform=ax1.transAxes,
        ha="right",
        va="center",
        fontsize=FONT["anno"],
        weight="bold",
        bbox=dict(
            boxstyle="round,pad=0.2",
            facecolor="white",
            edgecolor="none",
            alpha=0.70
        ),
        zorder=10
    )

    ax1.set_title("Circuit Packaging Window Dynamics", pad=12)
    ax1.set_ylabel("Window Size (cells)")
    ax1.set_xlabel("Time (ms)")
    ax1.set_xlim(start_ms if top_window_ms else 0, t_max_plot)

    y_max = max(
        tor_window_plot.max() if len(tor_window_plot) else threshold,
        torbox_window_plot.max() if len(torbox_window_plot) else threshold,
        threshold
    ) + 50
    ax1.set_ylim(0, y_max)

    ax1.grid(alpha=0.25, linestyle="--", linewidth=0.8)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)

    if (len(x_tor) == 0) and (len(x_tb) == 0):
        ax2.text(
            0.5, 0.5,
            "No SENDME timestamps available in payload",
            transform=ax2.transAxes,
            ha="center", va="center",
            fontsize=FONT["label"],
            weight="bold",
        )

    # ---- Bottom Panel: SENDME Temporal Accumulation (CDF) ----
    c1, = ax2.plot(
        x_tor, cdf_tor,
        linewidth=3.0,
        label=f"Tor (n={tor_count}, mean_interval={tor_mean * 1000:.1f}ms)",
        zorder=3
    )
    c2, = ax2.plot(
        x_tb, cdf_tb,
        linestyle="--",
        linewidth=3.0,
        label=f"TorBox (n={tb_count}, mean_interval={tb_mean * 1000:.1f}ms)",
        zorder=3
    )

    ax2.set_title("Circuit SENDME Temporal Accumulation", pad=12)
    ax2.set_xlabel("Time (ms)")
    ax2.set_ylabel("Cumulative Proportion of SENDMEs")

    if len(x_tor) or len(x_tb):
        xmax = max(
            np.max(x_tor) if len(x_tor) else 0,
            np.max(x_tb) if len(x_tb) else 0
        )
        xmax = xmax if xmax > 0 else 1000.0
        xmin = min(np.min(x_tor) if len(x_tor) else 0, np.min(x_tb) if len(x_tb) else 0)
        xmax = max(np.max(x_tor) if len(x_tor) else 0, np.max(x_tb) if len(x_tb) else 0)
        if xmax <= xmin:
            xmax = xmin + 1.0
        ax2.set_xlim(xmin, xmax * 1.05)

    ax2.set_ylim(0, 1.02)
    ax2.grid(alpha=0.25, linestyle="--", linewidth=0.8)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    # Combined legend
    handles = [l1, l2, c1, c2]
    labels = [h.get_label() for h in handles]
    ax2.legend(
        handles, labels,
        loc="lower right",
        fontsize=FONT["legend"],
        framealpha=0.95,
        ncol=1,
    )

    fig.tight_layout()

    # Save figures
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / "flow_control_main.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "flow_control_main.png", dpi=400, bbox_inches="tight")

    # ===================== Statistics Box =====================
    stats_text = (
        "Circuit Window Analysis Statistics\n"
        "═══════════════════════════════════════\n"
        f"Tor:\n"
        f"  SENDME count: {tor_count}\n"
        f"  Mean interval: {tor_mean * 1000:.3f} ms\n"
        f"  Median interval: {tor_median * 1000:.3f} ms\n"
        f"  Total duration: {max(tor_timestamps_ms) if tor_timestamps_ms else 0:.1f} ms\n"
        f"\n"
        f"TorBox:\n"
        f"  SENDME count: {tb_count}\n"
        f"  Mean interval: {tb_mean * 1000:.3f} ms\n"
        f"  Median interval: {tb_median * 1000:.3f} ms\n"
        f"  Total duration: {max(tb_timestamps_ms) if tb_timestamps_ms else 0:.1f} ms\n"
        f"\n"
        f"Difference:\n"
        f"  Mean interval: {(tb_mean - tor_mean) * 1000:.3f} ms\n"
        f"  Median interval: {(tb_median - tor_median) * 1000:.3f} ms\n"
        "═══════════════════════════════════════\n"
        "Note: CDF shows temporal accumulation\n"
        "of circuit-level SENDMEs (stream_id=0)"
    )

    fig_s = plt.figure(figsize=(7.0, 4.0))
    ax_s = fig_s.add_subplot(111)
    ax_s.axis("off")

    ax_s.text(
        0.02, 0.95,
        stats_text,
        fontsize=FONT["stats"],
        family="monospace",
        va="top",
        ha="left",
        bbox=dict(
            boxstyle="round,pad=0.6",
            facecolor="#F8F9FA",
            edgecolor="#4B5563",
            linewidth=1.4,
            alpha=0.98
        )
    )

    fig_s.tight_layout()
    fig_s.savefig(out_dir / "flow_control_stats.pdf", bbox_inches="tight")
    fig_s.savefig(out_dir / "flow_control_stats.png", dpi=400, bbox_inches="tight")

    plt.show()
    print(f"Plots saved to {out_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot circuit window dynamics from semantic_log_analysis outputs"
    )
    parser.add_argument(
        "--metrics",
        type=Path,
        default=Path("exp/semantic_logs/semantic_outputs"),
        help="Path to semantic_log_analysis output directory"
    )
    parser.add_argument(
        "--round",
        dest="round_idx",
        type=int,
        default=None,
        help="Specific round to plot (None for multi-round average)"
    )
    parser.add_argument(
        "--out",
        dest="out_dir",
        type=Path,
        default=Path("."),
        help="Output directory for plots"
    )
    parser.add_argument(
        "--twin",
        type=float,
        default=None,
        help="Top panel time window in ms (e.g., 500 or 1000). None = full trace"
    )
    args = parser.parse_args()

    plot_figures(
        args.metrics,
        args.round_idx,
        args.out_dir,
        top_window_ms=args.twin,
    )


if __name__ == "__main__":
    main()