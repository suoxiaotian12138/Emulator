import os
import re
import argparse
from typing import List, Tuple

import numpy as np
import matplotlib.pyplot as plt

import matplotlib

matplotlib.use("TkAgg")
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
# Main
# -----------------------------

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root",
        type=str,
        default=".",
        help="Experiment root, e.g. .../app/semantic test/exp/e2",
    )
    parser.add_argument("--drop_ratio", type=float, default=0.10, help="Drop first ratio of samples.")
    parser.add_argument("--out_prefix", type=str, default="exp2", help="Output filename prefix.")
    args = parser.parse_args()

    root = os.path.abspath(args.root)

    tor_path = find_sink_log(root, "tor")
    torbox_path = find_sink_log(root, "torbox")

    real_raw = read_completion_times(tor_path)
    sim_raw = read_completion_times(torbox_path)

    if real_raw.size == 0 or sim_raw.size == 0:
        raise RuntimeError("Empty data parsed from sink.log.")

    # --------------------------------------------------
    # Drop first N% samples (time order, not value order)
    # --------------------------------------------------
    def drop_head(x: np.ndarray, ratio: float) -> np.ndarray:
        n_drop = int(len(x) * ratio)
        return x[n_drop:] if n_drop < len(x) else x

    real = drop_head(real_raw, args.drop_ratio)
    sim = drop_head(sim_raw, args.drop_ratio)

    print(f"Dropped {args.drop_ratio * 100:.1f}% samples:")
    print(f"  Tor:    {len(real_raw)} -> {len(real)}")
    print(f"  Torbox: {len(sim_raw)}  -> {len(sim)}")

    # Metrics computed on trimmed data
    metrics = summary_metrics(real, sim)

    # Curves
    t_real_cdf, F_real = cdf_points(real)
    t_sim_cdf, F_sim = cdf_points(sim)

    t_real_ccdf, CCDF_real = ccdf_points(real)
    t_sim_ccdf, CCDF_sim = ccdf_points(sim)

    # -----------------------------
    # Figure 1: CCDF
    # -----------------------------
    plt.figure()
    plt.plot(t_real_ccdf, CCDF_real, label=f"Tor (n={metrics['real_n']})")
    plt.plot(t_sim_ccdf, CCDF_sim, label=f"Torbox (n={metrics['sim_n']})")
    plt.yscale("log")
    plt.xlabel("Completion Time (s)")
    plt.ylabel("P(T > t)")
    plt.title("Completion Time Distribution under Contention (CCDF)")
    plt.grid(True, which="both", linestyle=":")
    plt.legend()

    text = (
        f"Median rel. error: {metrics['median_rel_err'] * 100:.2f}%\n"
        f"IQR rel. error: {metrics['iqr_rel_err'] * 100:.2f}%\n"
        f"KS distance: {metrics['ks']:.4f}\n"
        f"Wasserstein (W1): {metrics['w1']:.4f} s"
    )
    plt.gca().text(
        0.98,
        0.98,
        text,
        transform=plt.gca().transAxes,
        ha="right",
        va="top",
        bbox=dict(boxstyle="round", alpha=0.85),
    )

    ccdf_path = f"{args.out_prefix}_ccdf.png"
    plt.tight_layout()
    plt.savefig(ccdf_path, dpi=200)
    plt.show()

    # -----------------------------
    # Figure 2: CDF
    # -----------------------------
    plt.figure()
    plt.plot(t_real_cdf, F_real, label="Tor")
    plt.plot(t_sim_cdf, F_sim, label="Torbox")
    plt.xlabel("Completion Time (s)")
    plt.ylabel("F(T ≤ t)")
    plt.title("Completion Time Distribution under Contention (CDF)")
    plt.grid(True, linestyle=":")
    plt.legend()

    cdf_path = f"{args.out_prefix}_cdf.png"
    plt.tight_layout()
    plt.savefig(cdf_path, dpi=200)
    plt.show()

    print("\nResolved paths:")
    print(f"  Tor:    {tor_path}")
    print(f"  Torbox: {torbox_path}")
    print("Metrics (after trimming):")
    for k, v in metrics.items():
        print(f"  {k}: {v}")
    print("\nSaved figures:")
    print(f"  {ccdf_path}")
    print(f"  {cdf_path}")


if __name__ == "__main__":
    main()
