# -*- coding: utf-8 -*-
"""
Protocol timeline comparison with TWO broken X-axis gaps (v4.1).

Based on v4, with these changes:
1) TorBox event labels show its OWN absolute time (no diff).
2) Remove large left blank margin (tighter left, smaller y tick pad).
3) Better looking break marks (style knobs).
4) Break gaps and segment intervals are exposed as easy knobs.

Run:
  python state_timeline_two_breaks_v4_1.py --metrics <path> --out <dir>
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("TkAgg")

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import matplotlib as mpl
from adjustText import adjust_text
from matplotlib.ticker import FuncFormatter

# =====================================================
# Global style knobs
# =====================================================
FONT = {
    "base": 12,
    "tick": 11,
    "title": 14,
    "event_info": 9,
}

VIS = {
    "event_marker": 7,
    "rect_lw": 0.8,
    "grid_alpha": 0.3,
    "phase_alpha": 0.15,
}

COLORS = {
    "tor_blue": "#1E40AF",
    "torbox_orange": "#EA580C",
    "text_box_bg": "#FFFFFF",
    "break_color": "#111827",
}

# =====================================================
# Segment and break knobs (easy to tune)
# =====================================================
SEG = {
    # Segment A end: show early handshake + extend region
    "seg1_min_end_ms": 15.0,
    "seg1_extra_after_last_ms": 2.0,

    # Segment B: focus around RELAY_CONNECTED
    "seg2_pre_ms": 30.0,
    "seg2_post_ms": 85.0,
    "seg2_min_width_ms": 60.0,
    "seg2_hard_max_end_ms": 610.0,

    # Segment C: fixed start (you asked 9s)
    "seg3_start_ms": 9000.0,

    # Right padding after last event
    "x_max_pad_ms": 50.0,

    # Layout spacing between broken segments
    "wspace": 0.06,
    "width_ratios": (6, 4, 2),
}

BREAK = {
    # Break mark size in axes coordinates
    "d": 0.014,
    "lw": 1.1,
}

# Only keep first occurrence for these events
FIRST_ONLY_KEYS = {"RELAY_DATA", "SENDME"}

mpl.rcParams.update({
    "font.size": FONT["base"],
    "font.weight": "semibold",
    "axes.titleweight": "bold",
    "axes.labelweight": "semibold",
    "xtick.labelsize": FONT["tick"],
    "ytick.labelsize": FONT["tick"],
    "axes.linewidth": 1.0,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

# =====================================================
# Data loading helpers
# =====================================================
RAW_STAGE_PREFIX = "# RAW_STAGE_JSON "

STATE_MAP = {
    "CREATE2": "OPENING",
    "CREATED2": "OPEN",
    "EXTEND2": "EXTENDING",
    "EXTENDED2": "OPEN",
    "RELAY_CONNECTED": "OPEN",
    "RELAY_DATA": "OPEN",
    "SENDME": "OPEN",
    "DESTROY": "ERROR",
}

states = ["CLOSED", "OPENING", "OPEN", "EXTENDING", "ERROR"]
state_colors = {
    "CLOSED": "#9CA3AF",
    "OPENING": "#93C5FD",
    "OPEN": "#3B82F6",
    "EXTENDING": "#34D399",
    "ERROR": "#EF4444",
}


def _resolve_metrics_file(base: Path, filename: str) -> Path:
    if base.is_file():
        return base
    p = base / filename
    if p.exists():
        return p
    raise FileNotFoundError(f"Unable to locate {filename} under {base}")


def _load_stage_metrics(metrics_root: Path) -> dict:
    path = _resolve_metrics_file(metrics_root, "avg_state_metrics.txt")
    payload_line = next(
        (line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith(RAW_STAGE_PREFIX)),
        None,
    )
    if not payload_line:
        raise ValueError(f"Missing RAW stage payload in {path}")
    return json.loads(payload_line[len(RAW_STAGE_PREFIX):])


def _build_events(label_data: dict):
    """
    Use absolute timestamps from file:
      t_ms = ts_seconds * 1000
    START stays at 0ms to cover initial idle.

    Keep only the FIRST occurrence for RELAY_DATA and SENDME.
    """
    events = []
    for key, info in label_data.items():
        if key == "DESTROY_TS":
            continue
        times = info.get("times", []) if isinstance(info, dict) else []
        if not times:
            continue

        if key in FIRST_ONLY_KEYS:
            times = times[:1]

        for ts in times:
            events.append((float(ts) * 1000.0, STATE_MAP.get(key, "OPEN"), key))

    destroy_ts = label_data.get("DESTROY_TS")
    if destroy_ts is not None:
        events.append((float(destroy_ts) * 1000.0, STATE_MAP["DESTROY"], "DESTROY"))

    if not events:
        return [(0.0, "CLOSED", "START"), (50.0, "ERROR", "NO_DATA")]

    events_sorted = sorted(events, key=lambda x: x[0])
    return [(0.0, "CLOSED", "START")] + events_sorted


def _build_phases(tor_events, torbox_events):
    all_events = tor_events + torbox_events
    time_lookup = {name: t for t, _, name in all_events if name != "START"}

    handshake_end = time_lookup.get("CREATED2", 150.0)
    extend_end = max(time_lookup.get("EXTENDED2", handshake_end), handshake_end)
    data_end = max(time_lookup.get("SENDME", extend_end), extend_end)
    destroy_val = max(time_lookup.get("DESTROY", data_end), data_end)

    phases = [
        {"name": "Handshake", "start": 0.0, "end": handshake_end or 0.0, "color": "#DBEAFE"},
        {"name": "Extend", "start": handshake_end or 0.0, "end": extend_end or handshake_end, "color": "#D1FAE5"},
        {"name": "Data Transfer", "start": extend_end or handshake_end, "end": data_end or extend_end, "color": "#E9D5FF"},
        {"name": "Flow Control", "start": data_end or extend_end, "end": destroy_val or data_end, "color": "#FEF3C7"},
        {"name": "Error", "start": destroy_val or data_end, "end": (destroy_val or data_end) + 100.0, "color": "#FEE2E2"},
    ]
    return phases


# =====================================================
# Two-break window planning
# =====================================================
def _find_first_time(events, name):
    for t, _, n in events:
        if n == name:
            return t
    return None


def _find_last_time(events, names):
    last = None
    for t, _, n in events:
        if n in names:
            last = t if last is None else max(last, t)
    return last


def _pick_three_segments_ms(tor_events, torbox_events):
    """
    A: [0, seg1_end]
    B: [seg2_start, seg2_end] around RELAY_CONNECTED
    C: [seg3_start, x_max]
    All key numbers are in SEG dict.
    """
    ext_last = max(
        _find_last_time(tor_events, {"EXTENDED2", "EXTEND2", "CREATED2"}) or 0.0,
        _find_last_time(torbox_events, {"EXTENDED2", "EXTEND2", "CREATED2"}) or 0.0,
    )
    seg1_end = max(SEG["seg1_min_end_ms"], ext_last + SEG["seg1_extra_after_last_ms"])

    rc1 = _find_first_time(tor_events, "RELAY_CONNECTED")
    rc2 = _find_first_time(torbox_events, "RELAY_CONNECTED")
    if rc1 is not None and rc2 is not None:
        rc_anchor = min(rc1, rc2)
    else:
        rc_anchor = rc1 if rc1 is not None else (rc2 if rc2 is not None else 520.0)

    seg2_start = max(seg1_end + 1.0, rc_anchor - SEG["seg2_pre_ms"])
    seg2_end = max(seg2_start + SEG["seg2_min_width_ms"], rc_anchor + SEG["seg2_post_ms"])
    seg2_end = min(seg2_end, SEG["seg2_hard_max_end_ms"])

    x_max = max(
        max((t for t, _, _ in tor_events), default=0.0),
        max((t for t, _, _ in torbox_events), default=0.0),
    ) + SEG["x_max_pad_ms"]

    if x_max > 2.0:
        seg2_end = min(seg2_end, x_max - 1.0)
        if seg2_start > 2.0:
            seg1_end = min(seg1_end, seg2_start - 1.0)

    seg3_start = max(SEG["seg3_start_ms"], seg2_end + 1.0)
    if x_max > 2.0:
        seg3_start = min(seg3_start, x_max - 1.0)

    return (0.0, seg1_end), (seg2_start, seg2_end), (seg3_start, x_max)


def _draw_x_break(ax_l, ax_r):
    d = BREAK["d"]
    lw = BREAK["lw"]
    c = COLORS["break_color"]

    kwargs = dict(transform=ax_l.transAxes, color=c, clip_on=False, linewidth=lw)
    ax_l.plot((1 - d, 1 + d), (-d, +d), **kwargs)
    ax_l.plot((1 - d, 1 + d), (1 - d, 1 + d), **kwargs)

    kwargs = dict(transform=ax_r.transAxes, color=c, clip_on=False, linewidth=lw)
    ax_r.plot((-d, +d), (-d, +d), **kwargs)
    ax_r.plot((-d, +d), (1 - d, 1 + d), **kwargs)

    ax_r.tick_params(labelleft=False)
    ax_r.spines["left"].set_visible(False)


def _setup_axis_common(ax, title=None, title_color=None, show_ylabel=True):
    ax.set_ylim(-0.6, len(states) + 0.8)
    ax.set_yticks(range(len(states)))
    if show_ylabel:
        ax.set_yticklabels(states)
        ax.tick_params(axis="y", pad=4, labelleft=True)
    else:
        ax.set_yticklabels([])
    ax.grid(axis="x", alpha=VIS["grid_alpha"], linestyle="--", linewidth=0.6)
    if title is not None:
        ax.set_title(title, loc="left", color=title_color, pad=10, weight="bold")


def _force_y_labels(ax_left):
    ax_left.set_yticks(range(len(states)))
    ax_left.set_yticklabels(states)
    ax_left.tick_params(axis="y", labelleft=True, pad=4)
    for lab in ax_left.get_yticklabels():
        lab.set_visible(True)


# =====================================================
# Plot helpers
# =====================================================
def plot_state_timeline(ax, events, y_offset=0.0, timeline_end=None):
    state_y = {s: i for i, s in enumerate(states)}
    if len(events) < 2:
        return state_y

    for i in range(len(events) - 1):
        t_start, state_start, _ = events[i]
        t_end, _, _ = events[i + 1]
        y = state_y.get(state_start, 0) + y_offset
        ax.add_patch(
            patches.Rectangle(
                (t_start, y - 0.3),
                max(t_end - t_start, 0.0),
                0.6,
                facecolor=state_colors.get(state_start, "#CBD5E1"),
                edgecolor="black",
                linewidth=VIS["rect_lw"],
                alpha=0.85,
                zorder=2,
            )
        )

    t_last, state_last, _ = events[-1]
    y = state_y.get(state_last, 0) + y_offset
    tail_len = (timeline_end if timeline_end is not None else (t_last + 50.0)) - t_last
    ax.add_patch(
        patches.Rectangle(
            (t_last, y - 0.3),
            max(tail_len, 0.0),
            0.6,
            facecolor=state_colors.get(state_last, "#CBD5E1"),
            edgecolor="black",
            linewidth=VIS["rect_lw"],
            alpha=0.85,
            zorder=2,
        )
    )
    return state_y


def add_event_markers(ax, events, state_y, y_offset, color):
    """
    v4.1: Always show absolute time for labels.
    """
    xmin, xmax = ax.get_xlim()
    texts = []
    occ = {}

    for t, state, event_label in events:
        if t < xmin or t > xmax:
            continue

        y = state_y.get(state, 0) + y_offset
        ax.plot(
            t, y, "o",
            color=color,
            markersize=VIS["event_marker"],
            markeredgecolor="white",
            markeredgewidth=1.2,
            zorder=5
        )

        occ[event_label] = occ.get(event_label, 0) + 1
        suffix = ""
        if event_label in ("EXTEND2", "EXTENDED2"):
            suffix = f"#{occ[event_label]}"

        info_text = f"{t:.0f}ms"
        display_text = f"{event_label}{suffix}\n{info_text}"

        txt = ax.text(
            t, y, display_text,
            ha="center", va="bottom",
            color=color,
            fontsize=FONT["event_info"],
            fontweight="bold",
            bbox=dict(
                boxstyle="round,pad=0.35",
                facecolor=COLORS["text_box_bg"],
                edgecolor=color,
                linewidth=0.8,
                alpha=0.95,
            ),
            zorder=10
        )
        texts.append(txt)

    if texts:
        adjust_text(
            texts,
            ax=ax,
            arrowprops=dict(arrowstyle="-", color=color, alpha=0.6, lw=0.8),
            expand_points=(1.2, 2.5),
            force_text=(0.1, 0.7),
        )


def plot_timeline_two_breaks(tor_events, torbox_events, phases, output_dir: Path) -> None:
    seg1, seg2, seg3 = _pick_three_segments_ms(tor_events, torbox_events)

    ms_fmt = FuncFormatter(lambda v, pos: f"{v:.0f}ms")
    sec_fmt = FuncFormatter(lambda v, pos: f"{v/1000.0:.1f}s")

    fig = plt.figure(figsize=(13.5, 7.2))
    outer = fig.add_gridspec(2, 1, height_ratios=[1, 1])

    tor_gs = outer[0].subgridspec(1, 3, width_ratios=SEG["width_ratios"], wspace=SEG["wspace"])
    tb_gs = outer[1].subgridspec(1, 3, width_ratios=SEG["width_ratios"], wspace=SEG["wspace"])

    ax_tor_a = fig.add_subplot(tor_gs[0, 0])
    ax_tor_b = fig.add_subplot(tor_gs[0, 1], sharey=ax_tor_a)
    ax_tor_c = fig.add_subplot(tor_gs[0, 2], sharey=ax_tor_a)

    ax_tb_a = fig.add_subplot(tb_gs[0, 0])
    ax_tb_b = fig.add_subplot(tb_gs[0, 1], sharey=ax_tb_a)
    ax_tb_c = fig.add_subplot(tb_gs[0, 2], sharey=ax_tb_a)

    # X limits
    ax_tor_a.set_xlim(*seg1)
    ax_tor_b.set_xlim(*seg2)
    ax_tor_c.set_xlim(*seg3)

    ax_tb_a.set_xlim(*seg1)
    ax_tb_b.set_xlim(*seg2)
    ax_tb_c.set_xlim(*seg3)

    # Formatters: A/B in ms, C in seconds
    for ax in (ax_tor_a, ax_tor_b, ax_tb_a, ax_tb_b):
        ax.xaxis.set_major_formatter(ms_fmt)
    for ax in (ax_tor_c, ax_tb_c):
        ax.xaxis.set_major_formatter(sec_fmt)

    # Titles and Y labels
    _setup_axis_common(ax_tor_a, title="Tor Protocol", title_color=COLORS["tor_blue"], show_ylabel=True)
    _setup_axis_common(ax_tor_b, show_ylabel=False)
    _setup_axis_common(ax_tor_c, show_ylabel=False)

    _setup_axis_common(ax_tb_a, title="TorBox Protocol", title_color=COLORS["torbox_orange"], show_ylabel=True)
    _setup_axis_common(ax_tb_b, show_ylabel=False)
    _setup_axis_common(ax_tb_c, show_ylabel=False)

    ax_tb_b.set_xlabel("Time (A,B: ms; C: seconds)", fontsize=FONT["title"], weight="bold")

    # Phases
    for ax in (ax_tor_a, ax_tor_b, ax_tor_c, ax_tb_a, ax_tb_b, ax_tb_c):
        for ph in phases:
            ax.axvspan(ph["start"], ph["end"], facecolor=ph["color"], alpha=VIS["phase_alpha"], zorder=0)

    # State rectangles
    state_y_tor = plot_state_timeline(ax_tor_a, tor_events, timeline_end=seg1[1])
    plot_state_timeline(ax_tor_b, tor_events, timeline_end=seg2[1])
    plot_state_timeline(ax_tor_c, tor_events, timeline_end=seg3[1])

    state_y_tb = plot_state_timeline(ax_tb_a, torbox_events, timeline_end=seg1[1])
    plot_state_timeline(ax_tb_b, torbox_events, timeline_end=seg2[1])
    plot_state_timeline(ax_tb_c, torbox_events, timeline_end=seg3[1])

    # Markers: both Tor and TorBox show absolute time now
    add_event_markers(ax_tor_a, tor_events, state_y_tor, 0.0, COLORS["tor_blue"])
    add_event_markers(ax_tor_b, tor_events, state_y_tor, 0.0, COLORS["tor_blue"])
    add_event_markers(ax_tor_c, tor_events, state_y_tor, 0.0, COLORS["tor_blue"])

    add_event_markers(ax_tb_a, torbox_events, state_y_tb, 0.0, COLORS["torbox_orange"])
    add_event_markers(ax_tb_b, torbox_events, state_y_tb, 0.0, COLORS["torbox_orange"])
    add_event_markers(ax_tb_c, torbox_events, state_y_tb, 0.0, COLORS["torbox_orange"])

    # Break marks
    _draw_x_break(ax_tor_a, ax_tor_b)
    _draw_x_break(ax_tor_b, ax_tor_c)
    _draw_x_break(ax_tb_a, ax_tb_b)
    _draw_x_break(ax_tb_b, ax_tb_c)

    # HARD force y labels after all sharing/break tweaks
    _force_y_labels(ax_tor_a)
    _force_y_labels(ax_tb_a)

    # Remove large left blank area
    fig.subplots_adjust(left=0.11, right=0.99, top=0.95, bottom=0.08, hspace=0.22)

    output_dir.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_dir / "protocol_timeline_comparison.pdf", format="pdf")
    fig.savefig(output_dir / "protocol_timeline_comparison.png", dpi=300)
    plt.show()


def main():
    parser = argparse.ArgumentParser(description="Protocol timeline with TWO broken x-axis gaps (v4.1).")
    parser.add_argument("--metrics", type=Path, default=Path("exp/semantic_logs/semantic_outputs"),
                        help="semantic_log_analysis output dir or avg_state_metrics.txt path")
    parser.add_argument("--out", dest="out_dir", type=Path, default=Path("."),
                        help="output dir for figures")
    args = parser.parse_args()

    stage_payload = _load_stage_metrics(args.metrics)
    tor_events = _build_events(stage_payload.get("Tor", {}))
    torbox_events = _build_events(stage_payload.get("TorBox", {}))

    phases = _build_phases(tor_events, torbox_events)
    plot_timeline_two_breaks(tor_events, torbox_events, phases, args.out_dir)


if __name__ == "__main__":
    main()
