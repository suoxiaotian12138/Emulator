import argparse
import json
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import matplotlib as mpl
from adjustText import adjust_text
import matplotlib

matplotlib.use("TkAgg")

# =====================================================
# Global style knobs
# =====================================================
FONT = {
    "base": 12,
    "tick": 11,
    "title": 14,
    "event_name": 10,
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
}

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
def _resolve_metrics_file(base: Path, filename: str, round_idx: int | None) -> Path:
    if base.is_file():
        return base

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


def _load_stage_metrics(metrics_root: Path, round_idx: int | None) -> dict:
    path = _resolve_metrics_file(metrics_root, "avg_state_metrics.txt", round_idx)
    payload_line = next(
        (line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith(RAW_STAGE_PREFIX)),
        None,
    )
    if not payload_line:
        raise ValueError(f"Missing RAW stage payload in {path}")
    return json.loads(payload_line[len(RAW_STAGE_PREFIX) :])


def _build_events(label_data: dict):
    events = []
    all_times = []
    for key, info in label_data.items():
        if key == "DESTROY_TS":
            continue
        times = info.get("times", []) if isinstance(info, dict) else []
        if not times:
            continue
        for ts in times:
            events.append((ts, STATE_MAP.get(key, "OPEN"), key))
            all_times.append(ts)

    destroy_ts = label_data.get("DESTROY_TS")
    if destroy_ts is not None:
        events.append((destroy_ts, STATE_MAP["DESTROY"], "DESTROY"))
        all_times.append(destroy_ts)

    if not events:
        return [
            (0.0, "CLOSED", "START"),
            (50.0, "ERROR", "NO_DATA"),
        ]

    base_ts = min(all_times)
    normalized = [(ts - base_ts) * 1000.0 for ts, st, name in sorted(events, key=lambda x: x[0])]
    sorted_events = []
    for (ts, st, name), raw_ts in zip(sorted(events, key=lambda x: x[0]), normalized):
        sorted_events.append((raw_ts, st, name))

    sorted_events.insert(0, (0.0, "CLOSED", "START"))
    return sorted_events


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
# Plot helpers
# =====================================================
def plot_state_timeline(ax, events, y_offset=0.0):
    state_y = {s: i for i, s in enumerate(states)}
    for i in range(len(events) - 1):
        t_start, state_start, _ = events[i]
        t_end, _, _ = events[i + 1]
        y = state_y[state_start] + y_offset
        ax.add_patch(
            patches.Rectangle(
                (t_start, y - 0.3),
                t_end - t_start,
                0.6,
                facecolor=state_colors[state_start],
                edgecolor="black",
                linewidth=VIS["rect_lw"],
                alpha=0.85,
                zorder=2,
            )
        )
    if events:
        t_last, state_last, _ = events[-1]
        y = state_y[state_last] + y_offset
        ax.add_patch(
            patches.Rectangle(
                (t_last, y - 0.3),
                1000 - t_last,
                0.6,
                facecolor=state_colors[state_last],
                edgecolor="black",
                linewidth=VIS["rect_lw"],
                alpha=0.85,
                zorder=2,
            )
        )
    return state_y


def get_diff_map(a_events, b_events):
    d_map = {}
    for (t_a, _, _), (t_b, _, _) in zip(a_events, b_events):
        diff = t_b - t_a
        # 只要有差异（哪怕是0，为了逻辑统一也可以记录，但这里我们只记录非0差异）
        # 如果您希望0差异时显示"0ms"而不是绝对时间，可以去掉 if diff != 0
        if diff != 0:
            d_map[t_b] = diff
    return d_map


def add_event_markers(ax, events, state_y, y_offset, color, diff_map=None):
    texts = []

    for t, state, event_label in events:
        y = state_y[state] + y_offset

        ax.plot(t, y, "o", color=color, markersize=VIS["event_marker"],
                markeredgecolor="white", markeredgewidth=1.2, zorder=5)

        # === 核心修改逻辑 ===
        if diff_map is not None:
            # 这是 TorBox (对比组)
            if t in diff_map:
                # 场景 A: 有差异 -> 只显示差异值，版面更干净
                diff_val = diff_map[t]
                info_text = f"{diff_val:+d}ms"
            else:
                # 场景 B: 无差异 -> 显示绝对时间，表示它没变
                info_text = f"{t}ms"
        else:
            # 这是 Tor (基准组) -> 总是显示绝对时间
            info_text = f"{t}ms"
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
                boxstyle="round,pad=0.4",
                facecolor=COLORS["text_box_bg"],
                edgecolor=color,
                linewidth=0.8,
                alpha=0.95,
            ),
            zorder=10
        )
        texts.append(txt)

    adjust_text(texts,
                ax=ax,
                arrowprops=dict(
                    arrowstyle='-',
                    color=color,
                    alpha=0.6,
                    lw=0.8
                ),
                expand_points=(1.2, 2.5),
                force_text=(0.1, 0.7),
                )


def plot_timeline(tor_events, torbox_events, phases, output_dir: Path) -> None:
    fig1 = plt.figure(figsize=(10, 7), constrained_layout=True)
    gs = fig1.add_gridspec(2, 1, height_ratios=[1, 1])

    x_min = 0
    x_max = max(
        max((t for t, _, _ in tor_events), default=0),
        max((t for t, _, _ in torbox_events), default=0),
    ) + 50

    # ---- Tor Track ----
    ax_tor = fig1.add_subplot(gs[0])
    ax_tor.set_xlim(x_min, x_max)
    ax_tor.set_ylim(-0.6, len(states) + 0.8)
    ax_tor.set_yticks(range(len(states)))
    ax_tor.set_yticklabels(states)
    ax_tor.set_title("Tor Protocol", loc="left", color=COLORS["tor_blue"], pad=10, weight="bold")
    ax_tor.grid(axis="x", alpha=VIS["grid_alpha"], linestyle="--", linewidth=0.6)

    for ph in phases:
        ax_tor.axvspan(ph["start"], ph["end"], facecolor=ph["color"], alpha=VIS["phase_alpha"], zorder=0)

    state_y_tor = plot_state_timeline(ax_tor, tor_events)
    # Tor: diff_map=None, 显示绝对时间
    add_event_markers(ax_tor, tor_events, state_y_tor, 0.0, color=COLORS["tor_blue"], diff_map=None)

    # ---- TorBox Track ----
    ax_tb = fig1.add_subplot(gs[1])
    ax_tb.set_xlim(x_min, x_max)
    ax_tb.set_ylim(-0.6, len(states) + 0.8)
    ax_tb.set_yticks(range(len(states)))
    ax_tb.set_yticklabels(states)
    ax_tb.set_xlabel("Time (ms)", fontsize=FONT["title"], weight="bold")
    ax_tb.set_title("TorBox Protocol", loc="left", color=COLORS["torbox_orange"], pad=10, weight="bold")
    ax_tb.grid(axis="x", alpha=VIS["grid_alpha"], linestyle="--", linewidth=0.6)

    for ph in phases:
        ax_tb.axvspan(ph["start"], ph["end"], facecolor=ph["color"], alpha=VIS["phase_alpha"], zorder=0)

    diff_mapping = get_diff_map(tor_events, torbox_events)
    state_y_tb = plot_state_timeline(ax_tb, torbox_events)
    # TorBox: 传入 diff_mapping, 触发极简显示逻辑
    add_event_markers(ax_tb, torbox_events, state_y_tb, 0.0, color=COLORS["torbox_orange"], diff_map=diff_mapping)

    output_dir.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_dir / "protocol_timeline_comparison.pdf", format="pdf", bbox_inches="tight")
    plt.savefig(output_dir / "protocol_timeline_comparison.png", dpi=300, bbox_inches="tight")
    plt.show()


def main():
    import os
    print("CWD =", os.getcwd())
    parser = argparse.ArgumentParser(description="Plot protocol states using semantic_log_analysis outputs")
    parser.add_argument("--metrics", type=Path, default=Path("exp/semantic_logs/semantic_outputs"), help="semantic_log_analysis 输出目录或 state_metrics.txt 路径")
    parser.add_argument("--round", dest="round_idx", type=int, default=None, help="当目录包含 round_XXX 时选择具体轮次（默认最后一轮）")
    parser.add_argument("--out", dest="out_dir", type=Path, default=Path("."), help="图表输出目录")
    args = parser.parse_args()
    print("metrics =", args.metrics, "round =", args.round_idx, "out =", args.out_dir)

    stage_payload = _load_stage_metrics(args.metrics, args.round_idx)
    tor_events = _build_events(stage_payload.get("Tor", {}))
    torbox_events = _build_events(stage_payload.get("TorBox", {}))
    phases = _build_phases(tor_events, torbox_events)

    plot_timeline(tor_events, torbox_events, phases, args.out_dir)


if __name__ == "__main__":
    main()
