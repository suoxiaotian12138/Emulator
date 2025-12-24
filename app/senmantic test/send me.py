"""Plot SENDME timing and CDF from JSONL logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np

# ===================== global style =====================
FONT = {
    "title": 20,
    "label": 17,
    "tick": 15,
    "legend": 14,
    "anno": 14,
}

def _ts_ms(rec: dict) -> float | None:
    if "ts_mono_ns" in rec:
        return rec["ts_mono_ns"] / 1e6
    if "ts_ns" in rec:
        return rec["ts_ns"] / 1e6
    if "ts_ms" in rec:
        return float(rec["ts_ms"])
    if "ts" in rec:
        return float(rec["ts"]) * 1000.0
    return None


def load_sendme_times(path: Path) -> List[float]:
    times: List[float] = []
    if not path.exists():
        raise FileNotFoundError(path)

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            cmd = (rec.get("cell_cmd") or rec.get("cmd") or rec.get("event") or "").upper()
            if cmd != "SENDME":
                continue

            ts = _ts_ms(rec)
            if ts is None:
                continue
            times.append(ts)

    times.sort()
    if not times:
        raise ValueError(f"no SENDME events found in {path}")

    t0 = times[0]
    return [t - t0 for t in times]


def cdf(data: List[float]):
    x = np.sort(np.asarray(data))
    y = np.arange(1, len(x) + 1) / len(x)
    return x, y


def build_parser():
    parser = argparse.ArgumentParser(description="Render SENDME scatter + CDF from JSONL logs.")
    parser.add_argument("--tor", required=True, type=Path, help="Tor JSONL log containing SENDME events")
    parser.add_argument("--torbox", required=True, type=Path, help="TorBox JSONL log containing SENDME events")
    parser.add_argument("--out", type=Path, default=Path.cwd(), help="Output directory for figures")
    parser.add_argument("--tor-label", default="Tor")
    parser.add_argument("--torbox-label", default="TorBox")
    return parser


def main(args=None):
    parser = build_parser()
    ns = parser.parse_args(args=args)
    ns.out.mkdir(parents=True, exist_ok=True)

    tor_sendme = load_sendme_times(ns.tor)
    torbox_sendme = load_sendme_times(ns.torbox)

    plt.rcParams.update({
        "font.size": FONT["label"],
        "axes.titlesize": FONT["title"],
        "axes.labelsize": FONT["label"],
    })

    fig = plt.figure(figsize=(13, 8))
    gs = fig.add_gridspec(2, 1, height_ratios=[1, 1.2], hspace=0.35)
    ax_scatter = fig.add_subplot(gs[0])
    ax_cdf = fig.add_subplot(gs[1])

    ax_scatter.scatter(tor_sendme, np.zeros_like(tor_sendme) + 1, label=f"{ns.tor_label} SENDME", s=75)
    ax_scatter.scatter(torbox_sendme, np.zeros_like(torbox_sendme) + 0, label=f"{ns.torbox_label} SENDME", s=75)
    ax_scatter.set_title("SENDME timeline", fontsize=FONT["title"])
    ax_scatter.set_ylabel("Trace", fontsize=FONT["label"], labelpad=6)
    ax_scatter.set_yticks([0, 1])
    ax_scatter.set_yticklabels([ns.torbox_label, ns.tor_label], fontsize=FONT["tick"])
    ax_scatter.grid(alpha=0.3, linestyle="--", linewidth=1.0)

    tor_x, tor_y = cdf(np.diff(tor_sendme)) if len(tor_sendme) > 1 else (np.array([]), np.array([]))
    tb_x, tb_y = cdf(np.diff(torbox_sendme)) if len(torbox_sendme) > 1 else (np.array([]), np.array([]))

    if tor_x.size:
        ax_cdf.plot(tor_x, tor_y, linewidth=2.6, label=f"{ns.tor_label} interval CDF")
    if tb_x.size:
        ax_cdf.plot(tb_x, tb_y, linewidth=2.6, linestyle="--", label=f"{ns.torbox_label} interval CDF")

    ax_cdf.set_title("SENDME interval distribution", fontsize=FONT["title"])
    ax_cdf.set_xlabel("Interval (ms)", fontsize=FONT["label"])
    ax_cdf.set_ylabel("CDF", fontsize=FONT["label"])
    ax_cdf.grid(alpha=0.3, linestyle="--", linewidth=1.0)
    ax_cdf.legend(loc="lower right", fontsize=FONT["legend"])

    for ax in (ax_scatter, ax_cdf):
        ax.tick_params(labelsize=FONT["tick"])

    out_pdf = ns.out / "sendme_comparison.pdf"
    out_png = ns.out / "sendme_comparison.png"
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_png, dpi=350, bbox_inches="tight")
    print(f"Saved {out_pdf} and {out_png}")


if __name__ == "__main__":
    main()
