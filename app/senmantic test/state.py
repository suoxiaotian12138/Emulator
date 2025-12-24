from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Iterable, List, Optional, Tuple
import matplotlib

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import matplotlib as mpl
from adjustText import adjust_text

matplotlib.use("Agg")


FONT = {
    "base": 14,
    "tick": 13,
    "title": 18,
    "event_name": 12,
    "event_info": 12,
}

VIS = {
    "event_marker": 8,
    "rect_lw": 1.0,
    "grid_alpha": 0.35,
}

COLORS = {
    "tor_blue": "#1E40AF",
    "torbox_orange": "#EA580C",
    "text_box_bg": "#FFFFFF",
}

TOR_INPUT = Path("exp/semantic_logs/tor")
TORBOX_INPUT = Path("exp/semantic_logs/torbox")
OUT_DIR = Path("exp/semantic_logs/semantic_outputs")

STATE_ORDER = ["CLOSED", "OPENING", "OPEN", "EXTENDING", "ERROR"]

CELL_STATE_MAP = {
    "START": "CLOSED",
    "CREATE2": "OPENING",
    "CREATED2": "OPEN",
    "EXTEND2": "EXTENDING",
    "EXTENDED2": "OPEN",
    "RELAY": "OPEN",
    "SENDME": "OPEN",
    "CRASH": "ERROR",
}

tor_events = [
    (0, "CLOSED", "START"),
    (50, "OPENING", "CREATE2"),
    (120, "OPEN", "CREATED2"),
    (220, "EXTENDING", "EXTEND2"),
    (300, "OPEN", "EXTENDED2"),
    (400, "OPEN", "RELAY"),
    (750, "OPEN", "SENDME"),
    (870, "ERROR", "CRASH"),
]

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
    """Resolve an events JSONL path from semantic_runner outputs."""

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

def load_cell_events(path: Path) -> List[Tuple[float, str, str]]:
    events: List[Tuple[float, str, str]] = []
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

            cmd = rec.get("cell_cmd") or rec.get("cmd") or rec.get("event")
            if not cmd:
                continue

            ts = _ts_ms(rec)
            if ts is None:
                continue

            state = CELL_STATE_MAP.get(str(cmd).upper(), "OPEN")
            events.append((ts, state, str(cmd)))

    events.sort(key=lambda x: x[0])
    if not events:
        raise ValueError(f"no cell_cmd events found in {path}")

    t0 = events[0][0]
    return [(t - t0, state, label) for t, state, label in events]


def get_diff_map(a_events: List[Tuple[float, str, str]], b_events: List[Tuple[float, str, str]]):
    d_map = {}
    for (t_a, _, _), (t_b, _, _) in zip(a_events, b_events):
        diff = t_b - t_a
        if diff != 0:
            d_map[t_b] = diff
    return d_map



def plot_state_timeline(ax, events, y_offset=0.0):
    state_y = {s: i for i, s in enumerate(STATE_ORDER)}
    for i in range(len(events) - 1):
        t_start, state_start, _ = events[i]
        t_end, _, _ = events[i + 1]
        y = state_y[state_start] + y_offset
        ax.add_patch(
            patches.Rectangle(
                (t_start, y - 0.3),
                t_end - t_start,
                0.6,
                facecolor="0.92",
                edgecolor="black",
                linewidth=VIS["rect_lw"],
                alpha=0.9,
                zorder=2,
            )
        )
    if events:
        t_last, state_last, _ = events[-1]
        y = state_y[state_last] + y_offset
        ax.add_patch(
            patches.Rectangle(
                (t_last, y - 0.3),
                max(10.0, events[-1][0] * 0.05),
                0.6,
                facecolor="0.92",
                edgecolor="black",
                linewidth=VIS["rect_lw"],
                alpha=0.9,
                zorder=2,
            )
        )
    return state_y




def add_event_markers(ax, events, state_y, y_offset, color, diff_map=None):
    texts = []

    for t, state, event_label in events:
        y = state_y[state] + y_offset

        ax.plot(
            t,
            y,
            "o",
            color=color,
            markersize=VIS["event_marker"],
            markeredgecolor="white",
            markeredgewidth=1.4,
            zorder=5,
        )
        # === 核心修改逻辑 ===
        if diff_map is not None:
            info_text = f"{diff_map.get(t, 0):+d}ms" if t in diff_map else f"{t:.0f}ms"
        else:
            info_text = f"{t:.0f}ms"
        # ===================

        display_text = f"{event_label}\n{info_text}"

        txt = ax.text(
            t, y,
            display_text,
            ha="center",
            va="bottom",
            color=color,
            fontsize=FONT["event_info"],
            fontweight="bold",
            bbox=dict(
                boxstyle="round,pad=0.5",
                facecolor=COLORS["text_box_bg"],
                edgecolor=color,
                linewidth=1.0,
                alpha=0.96,
                pad=0.6,
            ),
            zorder=10,
        )
        texts.append(txt)

    adjust_text(
        texts,
        ax=ax,
        arrowprops=dict(arrowstyle="-", color=color, alpha=0.65, lw=1.0),
        expand_points=(1.4, 2.8),
        force_text=(0.12, 0.8),
    )

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

    tor_events = load_cell_events(tor_path)
    torbox_events = load_cell_events(torbox_path)

    print(f"Resolved Tor log: {tor_path}")
    print(f"Resolved TorBox log: {torbox_path}")

    plt.rcParams.update({
        "font.size": FONT["base"],
        "axes.titlesize": FONT["title"],
        "axes.labelsize": FONT["title"],
    })

    fig = plt.figure(figsize=(12, 9), constrained_layout=True)
    gs = fig.add_gridspec(2, 1, height_ratios=[1, 1])

    max_time = max(tor_events[-1][0], torbox_events[-1][0]) * 1.05
    x_min = 0
    x_max = max_time

    ax_tor = fig.add_subplot(gs[0])
    ax_tor.set_xlim(x_min, x_max)
    ax_tor.set_ylim(-0.6, len(STATE_ORDER) + 0.8)
    ax_tor.set_yticks(range(len(STATE_ORDER)))
    ax_tor.set_yticklabels(STATE_ORDER, fontsize=FONT["tick"])
    ax_tor.tick_params(labelsize=FONT["tick"])
    ax_tor.set_title(f"{tor_label} Protocol", loc="left", color=COLORS["tor_blue"], pad=10, weight="bold")
    ax_tor.grid(axis="x", alpha=VIS["grid_alpha"], linestyle="--", linewidth=0.8)

    state_y_tor = plot_state_timeline(ax_tor, tor_events)
    add_event_markers(ax_tor, tor_events, state_y_tor, 0.0, color=COLORS["tor_blue"], diff_map=None)

    ax_tb = fig.add_subplot(gs[1])
    ax_tb.set_xlim(x_min, x_max)
    ax_tb.set_ylim(-0.6, len(STATE_ORDER) + 0.8)
    ax_tb.set_yticks(range(len(STATE_ORDER)))
    ax_tb.set_yticklabels(STATE_ORDER, fontsize=FONT["tick"])
    ax_tb.set_xlabel("Time (ms)", fontsize=FONT["title"], weight="bold")
    ax_tb.tick_params(labelsize=FONT["tick"])
    ax_tb.set_title(f"{torbox_label} Protocol", loc="left", color=COLORS["torbox_orange"], pad=10, weight="bold")
    ax_tb.grid(axis="x", alpha=VIS["grid_alpha"], linestyle="--", linewidth=0.8)

    diff_mapping = get_diff_map(tor_events, torbox_events)
    state_y_tb = plot_state_timeline(ax_tb, torbox_events)
    add_event_markers(ax_tb, torbox_events, state_y_tb, 0.0, color=COLORS["torbox_orange"], diff_map=diff_mapping)

    out_pdf = out / "protocol_timeline_comparison.pdf"
    out_png = out / "protocol_timeline_comparison.png"
    fig.savefig(out_pdf, format="pdf", bbox_inches="tight")
    fig.savefig(out_png, dpi=300, bbox_inches="tight")
    print(f"Saved {out_pdf} and {out_png}")


if __name__ == "__main__":
    main()