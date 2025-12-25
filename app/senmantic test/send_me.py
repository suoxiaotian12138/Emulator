import argparse
import json
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import matplotlib
matplotlib.use("TkAgg")

TOP_WINDOW_MS = 1000

# ===================== global style =====================
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

# ===================== data =====================
RAW_SENDME_PREFIX = "# RAW_SENDME_JSON "
AVG_SENDME_FILENAME = "avg_sendme_metrics.txt"
ROUND_SENDME_FILENAME = "sendme_metrics.txt"


def _resolve_metrics_file(base: Path, filename: str, round_idx: int | None, prefer_avg: bool = True) -> Path:
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


def _load_sendme_metrics(metrics_root: Path, round_idx: int | None) -> dict:
    path = _resolve_metrics_file(metrics_root, ROUND_SENDME_FILENAME, round_idx)
    payload_line = next(
        (line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith(RAW_SENDME_PREFIX)),
        None,
    )
    if not payload_line:
        raise ValueError(f"Missing RAW sendme payload in {path}")
    return json.loads(payload_line[len(RAW_SENDME_PREFIX) :])


def _to_ms(seq, base_ts):
    return [round((v - base_ts) * 1000.0, 6) for v in seq]


def _window_curve(intervals_ms, t_max, samples=300, base_value=100.0):
    if t_max <= 0:
        return np.linspace(0, 1, samples), np.full(samples, base_value)
    if not intervals_ms:
        return np.linspace(0, t_max, samples), np.full(samples, base_value)
    base = np.array(intervals_ms)
    interp = np.interp(
        np.linspace(0, len(base) - 1, samples),
        np.arange(len(base)),
        base,
    )
    return np.linspace(0, t_max, samples), interp + base_value


def _cdf_from_intervals(intervals_ms):
    if not intervals_ms:
        return np.array([]), np.array([])
    arr = np.sort(np.array(intervals_ms, dtype=float))
    cdf = np.linspace(0, 1, len(arr), endpoint=True)
    return arr, cdf

def plot_figures(metrics_root: Path, round_idx: int | None, out_dir: Path, top_window_ms: float | None = None) -> None:
    top_window_ms = TOP_WINDOW_MS
    payload = _load_sendme_metrics(metrics_root, round_idx)
    tor_data = payload.get("Tor", {})
    tb_data = payload.get("TorBox", {})

    def _nan_if_none(value):
        return float("nan") if value is None else float(value)

    base_ts_candidates = []
    if tor_data.get("timestamps"):
        base_ts_candidates.append(tor_data["timestamps"][0])
    if tb_data.get("timestamps"):
        base_ts_candidates.append(tb_data["timestamps"][0])
    base_ts = min(base_ts_candidates) if base_ts_candidates else 0.0

    tor_ts = _to_ms(tor_data.get("timestamps", []), base_ts) if tor_data else []
    tb_ts = _to_ms(tb_data.get("timestamps", []), base_ts) if tb_data else []

    tor_intervals_ms = [v * 1000.0 for v in tor_data.get("intervals", [])]
    tb_intervals_ms = [v * 1000.0 for v in tb_data.get("intervals", [])]

    t_max = max(tor_ts + tb_ts, default=0.0) + 10

    tor_mean = _nan_if_none(tor_data.get("mean", float("nan")))
    tb_mean = _nan_if_none(tb_data.get("mean", float("nan")))
    tor_median = _nan_if_none(tor_data.get("median", float("nan")))
    tb_median = _nan_if_none(tb_data.get("median", float("nan")))

    t, tor_window = _window_curve(tor_intervals_ms, t_max)
    _, torbox_window = _window_curve(tb_intervals_ms, t_max)

    # ===================== crop top panel by time window =====================
    if top_window_ms is not None and top_window_ms > 0:
        # slice window curves
        mask = t <= top_window_ms
        t_plot = t[mask]
        tor_window_plot = tor_window[mask]
        torbox_window_plot = torbox_window[mask]

        # slice SENDME markers
        tor_ts_plot = [x for x in tor_ts if x <= top_window_ms]
        tb_ts_plot = [x for x in tb_ts if x <= top_window_ms]

        t_max_plot = float(top_window_ms)
    else:
        t_plot = t
        tor_window_plot = tor_window
        torbox_window_plot = torbox_window
        tor_ts_plot = tor_ts
        tb_ts_plot = tb_ts
        t_max_plot = float(max(t_max, 1.0))


    x_tor, cdf_tor = _cdf_from_intervals(tor_intervals_ms)
    x_tb, cdf_tb = _cdf_from_intervals(tb_intervals_ms)

    thr = 100

    fig = plt.figure(figsize=(14, 9.2))
    gs = fig.add_gridspec(2, 1, height_ratios=[1.05, 1.20], hspace=0.35)

    ax1 = fig.add_subplot(gs[0])
    ax2 = fig.add_subplot(gs[1])

    # ---- top panel ----
    l1, = ax1.plot(t_plot, tor_window_plot, linewidth=2.8, label="Tor pkg_window", zorder=3)
    l2, = ax1.plot(t_plot, torbox_window_plot, linestyle="--", linewidth=2.8, label="TorBox pkg_window", zorder=3)

    ax1.axhline(thr, linewidth=2.0, linestyle=(0, (5, 3)), zorder=1)

    ax1.text(
        0.98, 0.10, "SENDME threshold",
        transform=ax1.transAxes,
        ha="right", va="center",
        fontsize=FONT["anno"], weight="bold",
        bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor="none", alpha=0.70),
        zorder=10
    )

    s1 = ax1.scatter(
        tor_ts_plot, [thr + 20] * len(tor_ts_plot),
        s=90, label="Tor SENDME",
        edgecolor="black", linewidth=1.0, zorder=4
    )
    s2 = ax1.scatter(
        tb_ts_plot, [thr - 20] * len(tb_ts_plot),
        s=90, label="TorBox SENDME",
        edgecolor="black", linewidth=1.0, zorder=4
    )

    ax1.set_title("Flow Control Window Dynamics", pad=12)
    ax1.set_ylabel("Window Size")
    ax1.set_xlim(0, t_max_plot)
    y_max = max((tor_window_plot.max() if len(tor_window_plot) else thr),
                (torbox_window_plot.max() if len(torbox_window_plot) else thr),
                thr) + 50
    ax1.set_ylim(0, y_max)
    ax1.grid(alpha=0.25, linestyle="--", linewidth=0.8)
    ax1.spines["top"].set_visible(False)
    ax1.spines["right"].set_visible(False)
    ax1.set_xlabel("")

    # ---- bottom panel ----
    c1, = ax2.plot(x_tor, cdf_tor, linewidth=3.0, label=f"Tor (mean = {tor_mean:.3f}s)", zorder=3)
    c2, = ax2.plot(x_tb, cdf_tb, linestyle="--", linewidth=3.0, label=f"TorBox (mean = {tb_mean:.3f}s)", zorder=3)
    fb = ax2.fill_between(
        np.concatenate([x_tor, x_tb]),
        np.concatenate([cdf_tor, cdf_tb]),
        alpha=0.12,
        label="95% CI overlap",
        zorder=2,
    ) if len(x_tor) and len(x_tb) else ax2.fill_between([0], [0], alpha=0.0)

    ax2.set_title("SENDME Interval Distribution (CDF)", pad=12)
    ax2.set_xlabel("Interval (ms)")
    ax2.set_ylabel("CDF")
    if len(x_tor) or len(x_tb):
        xmin = min(np.min(x_tor) if len(x_tor) else np.min(x_tb), np.min(x_tb) if len(x_tb) else np.min(x_tor))
        xmax = max(np.max(x_tor) if len(x_tor) else np.max(x_tb), np.max(x_tb) if len(x_tb) else np.max(x_tor))
        ax2.set_xlim(xmin, xmax * 1.05)
    ax2.set_ylim(0, 1.02)
    ax2.grid(alpha=0.25, linestyle="--", linewidth=0.8)
    ax2.spines["top"].set_visible(False)
    ax2.spines["right"].set_visible(False)

    handles = [l1, l2, s1, s2, c1, c2, fb]
    labels = [h.get_label() for h in handles]

    ax2.legend(
        handles, labels,
        loc="lower right",
        fontsize=FONT["legend"],
        framealpha=0.95,
        ncol=1,
    )

    fig.tight_layout()
    out_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_dir / "flow_control_main.pdf", bbox_inches="tight")
    fig.savefig(out_dir / "flow_control_main.png", dpi=400, bbox_inches="tight")

    stats_text = (
        "Statistical Analysis\n"
        "────────────────────────────\n"
        f"Mean difference: {(tb_mean - tor_mean) * 1000:.3f} ms\n"
        f"Tor mean: {tor_mean:.6f} s, median: {tor_median:.6f} s\n"
        f"TorBox mean: {tb_mean:.6f} s, median: {tb_median:.6f} s\n"
        "────────────────────────────\n"
        "Use semantic_log_analysis for detailed stats"
    )

    fig_s = plt.figure(figsize=(6.5, 2.4))
    ax_s = fig_s.add_subplot(111)
    ax_s.axis("off")

    ax_s.text(
        0.02, 0.92, stats_text,
        fontsize=FONT["stats"],
        family="monospace",
        va="top", ha="left",
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


def main():
    parser = argparse.ArgumentParser(description="Plot SENDME stats using semantic_log_analysis outputs")
    parser.add_argument("--metrics", type=Path, default=Path("exp/semantic_logs/semantic_outputs"), help="semantic_log_analysis 输出目录或 sendme_metrics.txt 路径（优先使用多轮平均）")
    parser.add_argument("--round", dest="round_idx", type=int, default=None, help="当目录包含 round_XXX 时选择轮次（若未找到多轮平均时使用）")
    parser.add_argument("--out", dest="out_dir", type=Path, default=Path("."), help="图表输出目录")
    parser.add_argument("--twin", type=float, default=None,
                        help="Top panel time window in ms, e.g., 500 or 1000. If None, use full.")
    args = parser.parse_args()

    plot_figures(args.metrics, args.round_idx, args.out_dir, top_window_ms=args.twin)


if __name__ == "__main__":
    main()