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
# Data
# =====================================================
phases = [
    {"name": "Handshake", "start": 0, "end": 150, "color": "#DBEAFE"},
    {"name": "Extend", "start": 150, "end": 400, "color": "#D1FAE5"},
    {"name": "Data Transfer", "start": 400, "end": 750, "color": "#E9D5FF"},
    {"name": "Flow Control", "start": 750, "end": 850, "color": "#FEF3C7"},
    {"name": "Error", "start": 850, "end": 1000, "color": "#FEE2E2"},
]

states = ["CLOSED", "OPENING", "OPEN", "EXTENDING", "ERROR"]
state_colors = {
    "CLOSED": "#9CA3AF",
    "OPENING": "#93C5FD",
    "OPEN": "#3B82F6",
    "EXTENDING": "#34D399",
    "ERROR": "#EF4444",
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

torbox_events = [
    (0, "CLOSED", "START"),
    (52, "OPENING", "CREATE2"),
    (122, "OPEN", "CREATED2"),
    (223, "EXTENDING", "EXTEND2"),
    (303, "OPEN", "EXTENDED2"),
    (403, "OPEN", "RELAY"),
    (753, "OPEN", "SENDME"),
    (873, "ERROR", "CRASH"),
]


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


# =====================================================
# Figure Setup
# =====================================================
fig1 = plt.figure(figsize=(10, 7), constrained_layout=True)
gs = fig1.add_gridspec(2, 1, height_ratios=[1, 1])

x_min = 0
x_max = 1050

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

# Save
plt.savefig("protocol_timeline_comparison.pdf", format="pdf", bbox_inches="tight")
plt.savefig("protocol_timeline_comparison.png", dpi=300, bbox_inches="tight")
plt.show()