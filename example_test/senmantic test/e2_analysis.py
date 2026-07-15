import os
import re
import argparse
from typing import List, Tuple

import numpy as np
import matplotlib.pyplot as plt
import matplotlib

matplotlib.use("TkAgg")


# -----------------------------
# Global font configuration
# -----------------------------

def setup_global_font(base_size: int):
    """
    配置全局 matplotlib 字体，强制加粗所有元素。
    """
    plt.rcParams.update({
        'font.family': 'Arial',
        'font.size': base_size,
        'font.weight': 'bold',  # 全局字体加粗

        # 坐标轴标题与标签加粗
        'axes.titleweight': 'bold',
        'axes.labelweight': 'bold',
        'axes.titlesize': base_size * 1.3,
        'axes.labelsize': base_size * 1.2,

        # 刻度数字加粗
        'xtick.labelsize': base_size * 1.1,
        'ytick.labelsize': base_size * 1.1,

        # 图例加粗
        'legend.fontsize': base_size * 1.1,
        'legend.frameon': True,

        # 边框加粗
        'axes.linewidth': 1.5,

        'lines.antialiased': True,
        'text.antialiased': True,
    })


# -----------------------------
# Log parsing
# -----------------------------

LINE_RE = re.compile(
    r"\bio_sec=(?P<io_sec>[0-9]*\.?[0-9]+)\b.*?\bwait_sec=(?P<wait_sec>[0-9]*\.?[0-9]+)\b"
)


def read_completion_times(path: str) -> np.ndarray:
    times: List[float] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE_RE.search(line)
            if not m:
                continue
            io_sec = float(m.group("io_sec"))
            wait_sec = float(m.group("wait_sec"))
            times.append(io_sec + wait_sec)
    return np.array(times, dtype=float)


# -----------------------------
# Distribution utilities
# -----------------------------

def ecdf(sorted_x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    n = sorted_x.size
    y = np.arange(1, n + 1, dtype=float) / n
    return sorted_x, y


def cdf_points(x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    x_sorted = np.sort(x)
    return ecdf(x_sorted)


def ccdf_points(x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    x_sorted = np.sort(x)
    t, F = ecdf(x_sorted)
    return t, 1.0 - F


def ks_distance(a: np.ndarray, b: np.ndarray) -> float:
    a = np.sort(a)
    b = np.sort(b)
    all_x = np.unique(np.concatenate([a, b]))
    Fa = np.searchsorted(a, all_x, side="right") / a.size
    Fb = np.searchsorted(b, all_x, side="right") / b.size
    return float(np.max(np.abs(Fa - Fb)))


def wasserstein_1d(a: np.ndarray, b: np.ndarray) -> float:
    a = np.sort(a)
    b = np.sort(b)
    n = max(a.size, b.size)
    q = (np.arange(n, dtype=float) + 0.5) / n
    aq = np.quantile(a, q, method="linear")
    bq = np.quantile(b, q, method="linear")
    return float(np.mean(np.abs(aq - bq)))


def summary_metrics(real: np.ndarray, sim: np.ndarray) -> dict:
    real_med = float(np.median(real))
    sim_med = float(np.median(sim))

    real_iqr = float(np.percentile(real, 75) - np.percentile(real, 25))
    sim_iqr = float(np.percentile(sim, 75) - np.percentile(sim, 25))

    median_rel_err = abs(sim_med - real_med) / (real_med if real_med != 0 else 1.0)
    iqr_rel_err = abs(sim_iqr - real_iqr) / (real_iqr if real_iqr != 0 else 1.0)

    ks = ks_distance(real, sim)
    w1 = wasserstein_1d(real, sim)

    return {
        "median_rel_err": float(median_rel_err),
        "iqr_rel_err": float(iqr_rel_err),
        "ks": float(ks),
        "w1": float(w1),
        "real_n": int(real.size),
        "sim_n": int(sim.size),
    }


# -----------------------------
# Path resolving
# -----------------------------

def find_sink_log(root: str, system_name: str) -> str:
    root = os.path.abspath(root)

    direct = os.path.join(root, system_name, "stream_time", "sink.log")
    if os.path.isfile(direct):
        return direct

    preferred = []
    fallback = []

    for dirpath, _, filenames in os.walk(root):
        if "sink.log" not in filenames:
            continue
        full = os.path.join(dirpath, "sink.log")
        norm = os.path.normpath(full)

        parts = norm.split(os.sep)
        if system_name not in parts:
            continue

        if os.path.basename(os.path.dirname(norm)) == "stream_time":
            preferred.append(norm)
        else:
            fallback.append(norm)

    if preferred:
        preferred.sort(key=len)
        return preferred[0]
    if fallback:
        fallback.sort(key=len)
        return fallback[0]

    raise FileNotFoundError(f"Cannot find sink.log for '{system_name}' under {root}")


# -----------------------------
# Enhanced plotting function
# -----------------------------

def plot_enhanced_ccdf(t_real, ccdf_real, t_sim, ccdf_sim, metrics, out_path):
    fig, ax = plt.subplots(figsize=(8, 6), dpi=300)

    color_real = '#2E86AB'
    color_sim = '#A23B72'

    ax.plot(t_real, ccdf_real,
            label=f'Tor (n={metrics["real_n"]:,})',
            color=color_real,
            linewidth=2.5,
            alpha=0.9)

    ax.plot(t_sim, ccdf_sim,
            label=f'Torbox (n={metrics["sim_n"]:,})',
            color=color_sim,
            linewidth=2.5,
            alpha=0.9,
            linestyle='--')

    ax.set_yscale('log')

    all_times = np.concatenate([t_real, t_sim])
    x_min = np.percentile(all_times, 1)
    x_max = np.percentile(all_times, 99)
    x_range = x_max - x_min
    ax.set_xlim(x_min - 0.05 * x_range, x_max + 0.05 * x_range)

    ax.set_xlabel('Completion Time (s)', fontweight='medium')
    ax.set_ylabel('P(T > t)', fontweight='medium')
    ax.set_title('Completion Time Distribution under Contention (CCDF)',
                 pad=15, fontweight='bold')

    ax.grid(True, which='major', linestyle='-', linewidth=0.8, alpha=0.3, color='gray')
    ax.grid(True, which='minor', linestyle=':', linewidth=0.5, alpha=0.2, color='gray')
    ax.minorticks_on()

    legend = ax.legend(loc='upper right', framealpha=0.95,
                       edgecolor='gray', fancybox=True, shadow=False)
    legend.get_frame().set_linewidth(0.8)

    text = (
        f"Median Rel. Error: {metrics['median_rel_err'] * 100:.2f}%\n"
        f"IQR Rel. Error: {metrics['iqr_rel_err'] * 100:.2f}%\n"
        f"KS Distance: {metrics['ks']:.4f}\n"
        f"Wasserstein-1: {metrics['w1']:.4f} s"
    )

    bbox_props = dict(boxstyle='round,pad=0.6',
                      facecolor='white',
                      edgecolor='gray',
                      alpha=0.95,
                      linewidth=1.2)

    ax.text(0.02, 0.02, text,
            transform=ax.transAxes,
            verticalalignment='bottom',
            horizontalalignment='left',
            bbox=bbox_props,
            family='monospace')

    for spine in ax.spines.values():
        spine.set_linewidth(1.2)
        spine.set_color('gray')

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved high-quality CCDF: {out_path}")
    plt.show()


def plot_enhanced_cdf(t_real, cdf_real, t_sim, cdf_sim, metrics, out_path):
    fig, ax = plt.subplots(figsize=(8, 5), dpi=300)

    color_real = '#2E86AB'
    color_sim = '#A23B72'

    ax.plot(t_real, cdf_real,
            label='Tor',
            color=color_real,
            linewidth=2.5,
            alpha=0.9)

    ax.plot(t_sim, cdf_sim,
            label='Torbox',
            color=color_sim,
            linewidth=2.5,
            alpha=0.9,
            linestyle='--')

    all_times = np.concatenate([t_real, t_sim])
    x_min = np.percentile(all_times, 1)
    x_max = np.percentile(all_times, 99)
    x_range = x_max - x_min
    ax.set_xlim(x_min - 0.05 * x_range, x_max + 0.05 * x_range)

    ax.set_ylim(-0.02, 1.02)

    ax.set_xlabel('Completion Time (s)', fontweight='bold')
    ax.set_ylabel('F(T ≤ t)', fontweight='bold')

    ax.grid(True, which='major', linestyle='-', linewidth=0.8, alpha=0.3, color='gray')
    ax.grid(True, which='minor', linestyle=':', linewidth=0.5, alpha=0.2, color='gray')
    ax.minorticks_on()

    legend = ax.legend(loc='lower right', framealpha=0.95,
                       edgecolor='gray', fancybox=True, shadow=False)
    legend.get_frame().set_linewidth(0.8)

    ax.axhline(y=0.5, color='gray', linestyle=':', linewidth=1, alpha=0.5)
    ax.text(ax.get_xlim()[1] * 0.98, 0.5, 'Median',
            va='bottom', ha='right',
            color='gray', fontweight='bold')

    for spine in ax.spines.values():
        spine.set_linewidth(1.2)
        spine.set_color('gray')

    plt.tight_layout()
    plt.savefig(out_path, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved high-quality CDF: {out_path}")
    plt.show()


# -----------------------------
# Main
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=str,
        default=".",
        help="Experiment root, e.g. .../example_test/semantic test/exp/e2",
    )
    parser.add_argument("--drop_ratio", type=float, default=0.10,
                        help="Drop first ratio of samples.")
    parser.add_argument("--out_prefix", type=str, default="transport",
                        help="Output filename prefix.")
    parser.add_argument("--fontsize", type=int, default=15,
                        help="Base font size for plots.")
    args = parser.parse_args()

    # Apply global font configuration
    setup_global_font(args.fontsize)

    root = os.path.abspath(args.root)

    print("🔍 Searching for log files...")
    tor_path = find_sink_log(root, "tor")
    torbox_path = find_sink_log(root, "torbox")

    print("\n📂 Resolved paths:")
    print(f"  Tor:    {tor_path}")
    print(f"  Torbox: {torbox_path}")

    print("\n📊 Parsing log files...")
    real_raw = read_completion_times(tor_path)
    sim_raw = read_completion_times(torbox_path)

    if real_raw.size == 0 or sim_raw.size == 0:
        raise RuntimeError("Empty data parsed from sink.log.")

    def drop_head(x: np.ndarray, ratio: float) -> np.ndarray:
        n_drop = int(len(x) * ratio)
        return x[n_drop:] if n_drop < len(x) else x

    real = drop_head(real_raw, args.drop_ratio)
    sim = drop_head(sim_raw, args.drop_ratio)

    print(f"\n✂️  Dropped first {args.drop_ratio * 100:.1f}% samples (warm-up):")
    print(f"  Tor:    {len(real_raw):,} → {len(real):,}")
    print(f"  Torbox: {len(sim_raw):,} → {len(sim):,}")

    print("\n📈 Computing distribution metrics...")
    metrics = summary_metrics(real, sim)

    t_real_cdf, F_real = cdf_points(real)
    t_sim_cdf, F_sim = cdf_points(sim)
    t_real_ccdf, CCDF_real = ccdf_points(real)
    t_sim_ccdf, CCDF_sim = ccdf_points(sim)

    print("\n🎨 Generating enhanced visualizations...")
    ccdf_path = f"{args.out_prefix}_ccdf.png"
    cdf_path = f"{args.out_prefix}_cdf.png"

    plot_enhanced_ccdf(
        t_real_ccdf, CCDF_real,
        t_sim_ccdf, CCDF_sim,
        metrics, ccdf_path
    )

    plot_enhanced_cdf(
        t_real_cdf, F_real,
        t_sim_cdf, F_sim,
        metrics, cdf_path
    )

    print("\n📊 Distribution Metrics (after trimming):")
    print(f"  Median Rel. Error:  {metrics['median_rel_err'] * 100:>6.2f}%")
    print(f"  IQR Rel. Error:     {metrics['iqr_rel_err'] * 100:>6.2f}%")
    print(f"  KS Distance:        {metrics['ks']:>6.4f}")
    print(f"  Wasserstein-1:      {metrics['w1']:>6.4f} s")
    print(f"  Real samples (n):   {metrics['real_n']:>6,}")
    print(f"  Sim samples (n):    {metrics['sim_n']:>6,}")

    print("\n✅ Analysis complete!")


if __name__ == "__main__":
    main()
