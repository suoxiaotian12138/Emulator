"""
e1_analyze_scalability_optimized.py

主要优化：
1. 输出格式改为 PDF (矢量图，适合论文)。
2. 保持原有输入输出接口不变 (argparse defaults preserved)。
3. 代码结构重构，提高可读性。
"""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

import matplotlib.pyplot as plt

# ==========================================
# 1. 全局可视化配置 (Visual Configuration)
# ==========================================
@dataclass
class VizConfig:
    """全局可视化参数配置"""
    # 输出设置
    save_format: str = 'pdf'       # [修改] 默认保存为 PDF
    dpi: int = 300                 # PDF 为矢量，但 DPI 影响混合元素

    # 字体与排版 (学术风格)
    # 'serif' (衬线体) 常用于正文为 Times New Roman 的论文
    # 'sans-serif' (无衬线体) 常用于幻灯片或现代风格论文
    # --- 字体与排版 (修改处) ---
    # 使用 Times New Roman，这是最标准的学术字体
    font_family: str = 'sans-serif'

    # 稍微调大一点字号，配合粗体更清晰
    font_size_base: int = 15  # 原为 14
    title_size: int = 18  # 原为 16
    label_size: int = 16  # 原为 14
    tick_size: int = 14  # 原为 12
    legend_size: int = 14  # 原为 12

    # 绘图尺寸
    fig_size: Tuple[int, int] = (8, 5) # 稍微调小一点，适合双栏论文插入

    # 线条样式
    line_width_thick: float = 2.0  # 主要数据线
    line_width_thin: float = 1.0   # 辅助线/次要数据
    marker_size: int = 6

    # 配色方案 (Color Palette) - 高对比度
    colors = {
        'tor': '#D35400',       # 深橙色
        'tor_light': '#EDBB99', # 浅橙色
        'torbox': '#2980B9',    #以此类推
        'torbox_light': '#A9CCE3',
        'ideal': '#555555',     # 深灰 (理想参考线)
        'grid': '#E0E0E0'       # 浅灰 (网格)
    }

VIZ = VizConfig()


def setup_plot_style():
    """应用全局绘图样式，针对 PDF 输出优化"""
    plt.style.use('seaborn-v0_8-whitegrid')

    params = {
        'font.family': VIZ.font_family,
        # 如果系统没装 Times New Roman，回退到 serif
        'font.serif': ['Times New Roman', 'Times', 'serif'],
        'font.size': VIZ.font_size_base,

        # --- [新增] 全局字体加粗设置 ---
        'font.weight': 'bold',  # 全局文字加粗
        'axes.labelweight': 'bold',  # 坐标轴标签加粗
        'axes.titleweight': 'bold',  # 标题加粗
        # ---------------------------

        'axes.labelsize': VIZ.label_size,
        'axes.titlesize': VIZ.title_size,
        'xtick.labelsize': VIZ.tick_size,
        'ytick.labelsize': VIZ.tick_size,
        'legend.fontsize': VIZ.legend_size,
        'figure.figsize': VIZ.fig_size,

        'axes.grid': True,
        'grid.alpha': 0.5,
        'grid.linestyle': '--',
        'grid.color': VIZ.colors['grid'],

        'pdf.fonttype': 42,
        'ps.fonttype': 42,
    }
    plt.rcParams.update(params)


# ==========================================
# 2. 数据处理逻辑 (Data Processing)
# ==========================================

def percentile(values: List[float], q: float) -> Optional[float]:
    """计算百分位数"""
    if not values:
        return None
    xs = sorted(values)
    k = (len(xs) - 1) * (q / 100.0)
    f = int(k)
    c = min(f + 1, len(xs) - 1)
    if f == c:
        return xs[f]
    return xs[f] + (xs[c] - xs[f]) * (k - f)


def _iter_jsonl_files(path: Path, *, recursive: bool = False) -> List[Path]:
    p = path.expanduser()
    if not p.exists():
        raise FileNotFoundError(f"Input path does not exist: {p}")

    if p.is_file():
        return [p]

    pattern = "**/*.jsonl" if recursive else "*.jsonl"
    files = sorted(p.glob(pattern))

    if not files:
        guesses = [p / "circuits.jsonl", p / "circuits.log", p / "circuits"]
        for g in guesses:
            if g.exists() and g.is_file():
                files.append(g)

    if not files:
        raise FileNotFoundError(f"No JSONL files found under: {p}")
    return files


def read_circuits_jsonl(path: Path, *, recursive: bool = False) -> List[dict]:
    files = _iter_jsonl_files(path, recursive=recursive)
    rows: List[dict] = []
    for fp in files:
        with fp.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return rows


def extract_attempts(rows: List[dict]) -> List[dict]:
    return [r for r in rows if r.get("event") == "circuit_attempt"]


def summarize_by_level(
    attempts: List[dict],
    *,
    timeout_s: float,
    period_s: float,
    measure_s: float,
) -> Tuple[List[int], Dict[int, dict]]:
    """按负载等级聚合统计数据"""
    levels = sorted({int(a["load_level"]) for a in attempts if "load_level" in a})
    stats: Dict[int, dict] = {}

    for lv in levels:
        # 仅统计 measure 阶段
        xs = [a for a in attempts if int(a.get("load_level", -1)) == lv and a.get("phase") == "measure"]
        if not xs:
            continue

        ok = [a for a in xs if a.get("status") == "ok"]
        fail = [a for a in xs if a.get("status") == "fail"]
        drop = [a for a in xs if a.get("status") == "drop"]

        denom = (len(ok) + len(fail))
        success_rate = 0.0 if denom == 0 else (len(ok) / denom)

        offered_rate = lv / period_s if period_s > 0 else None
        goodput = len(ok) / measure_s if measure_s > 0 else None

        ok_lat = []
        for a in ok:
            try:
                ok_lat.append(float(a["latency_ms"]))
            except Exception:
                continue

        p50 = percentile(ok_lat, 50)
        p95 = percentile(ok_lat, 95)
        p99 = percentile(ok_lat, 99)
        p999 = percentile(ok_lat, 99.9) if len(ok_lat) >= 1000 else None

        total = len(xs)
        drop_rate = len(drop) / total if total else 0.0

        timeout_fail = 0
        other_fail = 0
        reasons: List[str] = []
        for a in fail:
            r = str(a.get("reason") or "")
            if r.startswith("TimeoutError"):
                timeout_fail += 1
                reasons.append("TimeoutError")
            else:
                other_fail += 1
                reasons.append(r.split(":", 1)[0] if r else "UnknownError")

        timeout_rate = timeout_fail / total if total else 0.0

        # 统计 Top Failures
        reason_counter = Counter(reasons + (["pacer_overrun"] * len(drop)))
        top_reasons = reason_counter.most_common(5)

        stats[lv] = {
            "level": lv,
            "attempts": total,
            "offered_rps": offered_rate,
            "goodput_rps": goodput,
            "success_rate": success_rate,
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "p999_ms": p999,
            "drop_rate": drop_rate,
            "timeout_rate": timeout_rate,
            "top_reasons": top_reasons,
        }

    return levels, stats


# ==========================================
# 3. 绘图逻辑 (Plotting)
# ==========================================

def _finalize_and_save(ax, title, xlabel, ylabel, output_path):
    """通用的图表保存逻辑，处理边框和图例"""
    ax.set_xlabel(xlabel, fontweight='bold')
    ax.set_ylabel(ylabel, fontweight='bold')

    # 图例样式：半透明背景，置于合适位置
    ax.legend(frameon=True, fancybox=True, framealpha=0.9, edgecolor='#ccc')

    # 移除顶部和右侧边框 (Classic Academic Style)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    plt.tight_layout()
    plt.savefig(output_path, dpi=VIZ.dpi, bbox_inches='tight')
    plt.close()
    print(f"Saved plot: {output_path}")

def plot_compare(
        out_dir: Path,
        tor_levels: List[int],
        tor_stats: Dict[int, dict],
        torbox_levels: List[int],
        torbox_stats: Dict[int, dict],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    setup_plot_style() # 应用全局样式

    # 辅助函数：提取 (x, y) 序列
    def get_series(levels, stats, key_x, key_y):
        xs, ys = [], []
        for lv in levels:
            if lv in stats and stats[lv].get(key_x) is not None and stats[lv].get(key_y) is not None:
                xs.append(stats[lv][key_x])
                ys.append(stats[lv][key_y])
        return xs, ys

    # ===== Figure 1: Latency (P99 & P50) =====
    fig1, ax1 = plt.subplots()

    # Tor
    xt, yt99 = get_series(tor_levels, tor_stats, "offered_rps", "p99_ms")
    xt, yt50 = get_series(tor_levels, tor_stats, "offered_rps", "p50_ms")

    # zorder=3 保证线条在网格之上
    ax1.plot(xt, yt99, label='Tor P99', color=VIZ.colors['tor'],
             marker='o', markersize=VIZ.marker_size, linewidth=VIZ.line_width_thick, zorder=3)
    ax1.plot(xt, yt50, label='Tor P50', color=VIZ.colors['tor_light'],
             marker='o', markersize=VIZ.marker_size*0.7, linestyle='--', linewidth=VIZ.line_width_thin, zorder=3)

    # TorBox
    xb, yb99 = get_series(torbox_levels, torbox_stats, "offered_rps", "p99_ms")
    xb, yb50 = get_series(torbox_levels, torbox_stats, "offered_rps", "p50_ms")

    ax1.plot(xb, yb99, label='TorBox P99', color=VIZ.colors['torbox'],
             marker='s', markersize=VIZ.marker_size, linewidth=VIZ.line_width_thick, zorder=3)
    ax1.plot(xb, yb50, label='TorBox P50', color=VIZ.colors['torbox_light'],
             marker='s', markersize=VIZ.marker_size*0.7, linestyle='--', linewidth=VIZ.line_width_thin, zorder=3)

    _finalize_and_save(
        ax1, 'Tail Latency vs Load',
        'Offered Load (circuits/s)', 'Latency (ms)',
        out_dir / f"p99_latency.{VIZ.save_format}"
    )

    # ===== Figure 2: Goodput =====
    fig2, ax2 = plt.subplots()

    xt, yt = get_series(tor_levels, tor_stats, "offered_rps", "goodput_rps")
    xb, yb = get_series(torbox_levels, torbox_stats, "offered_rps", "goodput_rps")

    # 理想参考线 (Ideal Line)
    all_x = xt + xb
    if all_x:
        max_val = max(all_x)
        ax2.plot([0, max_val], [0, max_val], label='Ideal', color=VIZ.colors['ideal'],
                 linestyle=':', linewidth=VIZ.line_width_thin, zorder=2)

    ax2.plot(xt, yt, label='Tor', color=VIZ.colors['tor'],
             marker='o', markersize=VIZ.marker_size, linewidth=VIZ.line_width_thick, zorder=3)
    ax2.plot(xb, yb, label='TorBox', color=VIZ.colors['torbox'],
             marker='s', markersize=VIZ.marker_size, linewidth=VIZ.line_width_thick, zorder=3)

    _finalize_and_save(
        ax2, 'Goodput vs Offered Load',
        'Offered Load (circuits/s)', 'Goodput (circuits/s)',
        out_dir / f"goodput.{VIZ.save_format}"
    )

    # ===== Figure 3: Success Rate =====
    fig3, ax3 = plt.subplots()

    xt, yt = get_series(tor_levels, tor_stats, "offered_rps", "success_rate")
    xb, yb = get_series(torbox_levels, torbox_stats, "offered_rps", "success_rate")

    # 转换为百分比
    yt = [y * 100 for y in yt]
    yb = [y * 100 for y in yb]

    ax3.plot(xt, yt, label='Tor', color=VIZ.colors['tor'],
             marker='o', markersize=VIZ.marker_size, linewidth=VIZ.line_width_thick, zorder=3)
    ax3.plot(xb, yb, label='TorBox', color=VIZ.colors['torbox'],
             marker='s', markersize=VIZ.marker_size, linewidth=VIZ.line_width_thick, zorder=3)

    ax3.axhline(100, linestyle='--', color=VIZ.colors['ideal'], alpha=0.5, zorder=1)
    ax3.set_ylim(0, 105)

    _finalize_and_save(
        ax3, 'Success Rate Comparison',
        'Offered Load (circuits/s)', 'Success Rate (%)',
        out_dir / f"success_rate.{VIZ.save_format}"
    )


# ==========================================
# 4. 控制台输出逻辑 (Console Output)
# ==========================================

def print_table(name: str, levels: List[int], stats: Dict[int, dict]) -> None:
    print(f"\n=== {name} Summary (Measure Phase) ===")

    # 格式化字符串，固定宽度，确保对齐
    headers = [
        ("Lvl", 5), ("Atts", 6), ("Succ%", 7),
        ("P50ms", 7), ("P99ms", 7),
        ("Drop%", 6), ("TO%", 6), ("Top Reason", 20)
    ]

    # 生成表头
    header_str = " ".join([f"{h[0]:<{h[1]}}" for h in headers])
    print(header_str)
    print("-" * len(header_str))

    for lv in levels:
        if lv not in stats:
            continue
        s = stats[lv]

        # 辅助格式化函数
        def fmt_val(v, width):
            if v is None: return "n/a".ljust(width)
            return f"{v:<{width}.1f}"

        def fmt_pct(v, width):
            if v is None: return "-".ljust(width)
            return f"{v*100:<{width}.1f}"

        top_fail = s["top_reasons"][0][0] if s["top_reasons"] else "-"
        # 截断过长的错误信息
        if len(top_fail) > 18:
            top_fail = top_fail[:16] + "..."

        row = (
            f"{lv:<5} "
            f"{s['attempts']:<6} "
            f"{fmt_pct(s['success_rate'], 7)} "
            f"{fmt_val(s['p50_ms'], 7)} "
            f"{fmt_val(s['p99_ms'], 7)} "
            f"{fmt_pct(s['drop_rate'], 6)} "
            f"{fmt_pct(s['timeout_rate'], 6)} "
            f"{top_fail}"
        )
        print(row)


def run(
    *,
    tor_path: str,
    torbox_path: str,
    out_dir: str,
    timeout_s: float = 5.0,
    period_s: float = 2.0,
    measure_s: float = 120.0,
    recursive: bool = False,
    **kwargs
) -> None:
    print(f"Reading Tor logs from: {tor_path}")
    tor_rows = read_circuits_jsonl(Path(tor_path), recursive=recursive)
    print(f"Reading TorBox logs from: {torbox_path}")
    torbox_rows = read_circuits_jsonl(Path(torbox_path), recursive=recursive)

    tor_attempts = extract_attempts(tor_rows)
    torbox_attempts = extract_attempts(torbox_rows)

    print("Analyzing data...")
    tor_levels, tor_stats = summarize_by_level(
        tor_attempts,
        timeout_s=timeout_s,
        period_s=period_s,
        measure_s=measure_s,
    )
    torbox_levels, torbox_stats = summarize_by_level(
        torbox_attempts,
        timeout_s=timeout_s,
        period_s=period_s,
        measure_s=measure_s,
    )

    print_table("Tor", tor_levels, tor_stats)
    print_table("TorBox", torbox_levels, torbox_stats)

    print(f"\nGenerating plots in: {out_dir}")
    plot_compare(Path(out_dir), tor_levels, tor_stats, torbox_levels, torbox_stats)


def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze Scalability Experiments")
    # 保持原有接口和默认值不变
    ap.add_argument(
        "--tor",
        default="exp/deployment/e1_scalability/logs/tor/circuits",
        help="Tor circuits JSONL file OR directory",
    )
    ap.add_argument(
        "--torbox",
        default="exp/deployment/e1_scalability/logs/torbox/circuits",
        help="TorBox circuits JSONL file OR directory",
    )
    ap.add_argument("--out", default="analysis_out", help="Output directory")
    ap.add_argument("--timeout_s", type=float, default=5.0)
    ap.add_argument("--period_s", type=float, default=2.0)
    ap.add_argument("--measure_s", type=float, default=120.0)
    ap.add_argument("--recursive", action="store_true", help="Read directories recursively")

    args = ap.parse_args()

    try:
        run(
            tor_path=args.tor,
            torbox_path=args.torbox,
            out_dir=args.out,
            timeout_s=args.timeout_s,
            period_s=args.period_s,
            measure_s=args.measure_s,
            recursive=args.recursive,
        )
    except Exception as e:
        print(f"\nError: {e}")

if __name__ == "__main__":
    main()