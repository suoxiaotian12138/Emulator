"""Plot SENDME timing and CDF from JSONL logs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Optional
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


TOR_INPUT = Path("exp/semantic_logs/tor")
TORBOX_INPUT = Path("exp/semantic_logs/torbox")
OUT_DIR = Path("exp/semantic_logs/semantic_outputs")

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

def _events_from_meta(meta_path: Path) -> Path:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    log_files = meta.get("log_files") or {}
    events_path = log_files.get("events")
    if not events_path:
        raise ValueError(f"No 'events' entry in {meta_path}")
    events_path = Path(events_path)
    if not events_path.is_absolute():
        events_path = meta_path.parent / events_path
    if not events_path.exists():
        raise FileNotFoundError(f"Events log missing: {events_path}")
    return events_path


def resolve_events_path(base: Path, round_index: Optional[int] = None) -> Path:
    """Resolve an events JSONL path from various semantic_runner outputs.

    Supported inputs:
    - direct events JSONL file
    - ``run_meta.json``
    - directory containing ``run_meta.json`` or ``events/``
    - directory containing ``round_XXX`` subdirectories (selectable via ``round_index``)
    - ``multi_run_manifest.json`` (selects the last round by default or ``round_index``)
    """

    if not base.exists():
        raise FileNotFoundError(base)

    if base.is_file():
        if base.name == "multi_run_manifest.json":
            manifest = json.loads(base.read_text(encoding="utf-8"))
            meta_paths = [Path(p) for p in manifest.get("meta_paths", [])]
            if not meta_paths:
                raise ValueError(f"Manifest {base} contains no meta paths")
            idx = round_index if round_index is not None else -1
            return _events_from_meta(meta_paths[idx])

        if base.name == "run_meta.json":
            return _events_from_meta(base)

        if base.suffix == ".jsonl":
            return base

        raise ValueError(f"Unsupported file input: {base}")

    # Directory inputs
    meta_path = base / "run_meta.json"
    if meta_path.exists():
        return _events_from_meta(meta_path)

    round_dirs = sorted([p for p in base.iterdir() if p.is_dir() and p.name.startswith("round_")])
    if round_dirs:
        idx = round_index if round_index is not None else -1
        chosen = round_dirs[idx]
        return resolve_events_path(chosen)

    events_dir = base / "events"
    if events_dir.exists():
        candidates = sorted(events_dir.glob("*.jsonl"))
        if not candidates:
            raise FileNotFoundError(f"No JSONL logs found under {events_dir}")
        return candidates[-1]

    raise ValueError(f"Unsupported directory layout for {base}")


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



def main(
    *,
    tor: Path = TOR_INPUT,
    tor_round: int | None = None,
    torbox: Path = TORBOX_INPUT,
    torbox_round: int | None = None,
    out: Path = OUT_DIR,
    tor_label: str = "Tor",
    torbox_label: str = "TorBox",
):
    out.mkdir(parents=True, exist_ok=True)

    tor_path = resolve_events_path(tor, tor_round)
    torbox_path = resolve_events_path(torbox, torbox_round)

    tor_sendme = load_sendme_times(tor_path)
    torbox_sendme = load_sendme_times(torbox_path)

    plt.rcParams.update({
        "font.size": FONT["label"],
        "axes.titlesize": FONT["title"],
        "axes.labelsize": FONT["label"],
    })

    fig = plt.figure(figsize=(13, 8))
    gs = fig.add_gridspec(2, 1, height_ratios=[1, 1.2], hspace=0.35)
    ax_scatter = fig.add_subplot(gs[0])
    ax_cdf = fig.add_subplot(gs[1])

    ax_scatter.scatter(tor_sendme, np.zeros_like(tor_sendme) + 1, label=f"{tor_label} SENDME", s=75)
    ax_scatter.scatter(torbox_sendme, np.zeros_like(torbox_sendme) + 0, label=f"{torbox_label} SENDME", s=75)
    ax_scatter.set_title("SENDME timeline", fontsize=FONT["title"])
    ax_scatter.set_ylabel("Trace", fontsize=FONT["label"], labelpad=6)
    ax_scatter.set_yticks([0, 1])
    ax_scatter.set_yticklabels([torbox_label, tor_label], fontsize=FONT["tick"])
    ax_scatter.grid(alpha=0.3, linestyle="--", linewidth=1.0)

    tor_x, tor_y = cdf(np.diff(tor_sendme)) if len(tor_sendme) > 1 else (np.array([]), np.array([]))
    tb_x, tb_y = cdf(np.diff(torbox_sendme)) if len(torbox_sendme) > 1 else (np.array([]), np.array([]))

    if tor_x.size:
        ax_cdf.plot(tor_x, tor_y, linewidth=2.6, label=f"{tor_label} interval CDF")
    if tb_x.size:
        ax_cdf.plot(tb_x, tb_y, linewidth=2.6, linestyle="--", label=f"{torbox_label} interval CDF")


    ax_cdf.set_title("SENDME interval distribution", fontsize=FONT["title"])
    ax_cdf.set_xlabel("Interval (ms)", fontsize=FONT["label"])
    ax_cdf.set_ylabel("CDF", fontsize=FONT["label"])
    ax_cdf.grid(alpha=0.3, linestyle="--", linewidth=1.0)
    ax_cdf.legend(loc="lower right", fontsize=FONT["legend"])

    for ax in (ax_scatter, ax_cdf):
        ax.tick_params(labelsize=FONT["tick"])

    out_pdf = out / "sendme_comparison.pdf"
    out_png = out / "sendme_comparison.png"
    fig.savefig(out_pdf, bbox_inches="tight")
    fig.savefig(out_png, dpi=350, bbox_inches="tight")
    print(f"Resolved Tor log: {tor_path}")
    print(f"Resolved TorBox log: {torbox_path}")
    print(f"Saved {out_pdf} and {out_png}")


if __name__ == "__main__":
    main()
