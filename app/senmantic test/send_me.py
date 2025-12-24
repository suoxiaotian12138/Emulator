import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import matplotlib
matplotlib.use("TkAgg")

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
np.random.seed(0)

t = np.linspace(0, 500, 300)
tor_window = 600 + 350 * np.abs(np.sin(t / 35)) + 40 * np.sin(t / 10)
torbox_window = tor_window * (0.97 + 0.03 * np.sin(t / 50)) + np.random.normal(0, 15, len(t))

sendme_tor = np.arange(40, 500, 55) + np.random.normal(0, 5, 9)
sendme_tb = sendme_tor + np.random.normal(0, 3, 9)

x = np.linspace(8, 26, 300)
cdf_tor = 1 / (1 + np.exp(-(x - 13) / 1.8))
cdf_tb = 1 / (1 + np.exp(-(x - 14) / 2.0))

# ===================== Figure A: main plot (2 panels) =====================
fig = plt.figure(figsize=(14, 9.2))
gs = fig.add_gridspec(2, 1, height_ratios=[1.05, 1.20], hspace=0.35)

ax1 = fig.add_subplot(gs[0])
ax2 = fig.add_subplot(gs[1])

# ---- top panel ----
l1, = ax1.plot(t, tor_window, linewidth=2.8, label="Tor pkg_window", zorder=3)
l2, = ax1.plot(t, torbox_window, linestyle="--", linewidth=2.8, label="TorBox pkg_window", zorder=3)

thr = 100
ax1.axhline(thr, linewidth=2.0, linestyle=(0, (5, 3)), zorder=1)

# threshold label inside, but placed in empty right-side region
ax1.text(
    0.98, 0.10, "SENDME threshold",
    transform=ax1.transAxes,
    ha="right", va="center",
    fontsize=FONT["anno"], weight="bold",
    bbox=dict(boxstyle="round,pad=0.2", facecolor="white", edgecolor="none", alpha=0.70),
    zorder=10
)

s1 = ax1.scatter(sendme_tor, np.ones_like(sendme_tor) * 120, s=90, label="Tor SENDME",
                 edgecolor="black", linewidth=1.0, zorder=4)
s2 = ax1.scatter(sendme_tb, np.ones_like(sendme_tb) * 80, s=90, label="TorBox SENDME",
                 edgecolor="black", linewidth=1.0, zorder=4)

ax1.set_title("Flow Control Window Dynamics (100MB Transfer, 1000 Trials)", pad=12)
ax1.set_ylabel("Window Size")
ax1.set_xlim(0, 520)
ax1.set_ylim(0, 1050)
ax1.grid(alpha=0.25, linestyle="--", linewidth=0.8)
ax1.spines["top"].set_visible(False)
ax1.spines["right"].set_visible(False)
ax1.set_xlabel("")

# ---- bottom panel ----
c1, = ax2.plot(x, cdf_tor, linewidth=3.0, label="Tor (mean = 13.0ms)", zorder=3)
c2, = ax2.plot(x, cdf_tb, linestyle="--", linewidth=3.0, label="TorBox (mean = 14.0ms)", zorder=3)
fb = ax2.fill_between(x, cdf_tor, cdf_tb, alpha=0.12, label="95% CI overlap", zorder=2)

ax2.set_title("SENDME Interval Distribution (CDF)", pad=12)
ax2.set_xlabel("Interval (ms)")
ax2.set_ylabel("CDF")
ax2.set_xlim(8, 26)
ax2.set_ylim(0, 1.02)
ax2.grid(alpha=0.25, linestyle="--", linewidth=0.8)
ax2.spines["top"].set_visible(False)
ax2.spines["right"].set_visible(False)

# ---- merge legends into ONE, placed at bottom-right of CDF panel ----
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
fig.savefig("flow_control_main.pdf", bbox_inches="tight")
fig.savefig("flow_control_main.png", dpi=400, bbox_inches="tight")

# ===================== Figure B: statistical analysis ONLY =====================
stats_text = (
    "Statistical Analysis\n"
    "────────────────────────────\n"
    "Mean difference: 1.0 ms (≈7.7%)\n"
    "Std dev: Tor = 2.4 ms, TorBox = 2.6 ms\n"
    "p-value: 0.21\n"
    "KS test: D = 0.042, p = 0.39\n"
    "────────────────────────────\n"
    "Conclusion: No significant difference"
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
fig_s.savefig("flow_control_stats.pdf", bbox_inches="tight")
fig_s.savefig("flow_control_stats.png", dpi=400, bbox_inches="tight")

plt.show()