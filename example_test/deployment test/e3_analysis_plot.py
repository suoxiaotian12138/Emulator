"""
e3_analysis_pub.py (优化版 v2)

出版级绘图脚本，风格与 E2 完全一致。
改进点：
1. 资源图：使用 e3_check_cpu.py 的双轴展示方式，更直观
2. 建路图：用箱线图替代趋势线，真实展示数据分布和稳定性
3. 统一的学术风格：无衬线字体、简洁边框、清晰配色

依赖:
    pip install pandas matplotlib numpy
"""

import argparse
import json
import os
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib
import pandas as pd
import numpy as np

# =============================================================================
# 1. 全局绘图风格设置 (与 E2 完全一致)
# =============================================================================

matplotlib.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['DejaVu Sans', 'Arial', 'Helvetica'],
    'font.size': 20,
    'axes.labelsize': 20,
    'axes.titlesize': 24,
    'xtick.labelsize': 22,
    'ytick.labelsize': 22,
    'legend.fontsize': 22,
    'figure.dpi': 150,
    'lines.linewidth': 2.5,
})

# 配色方案 (与 E2 一致)
COLORS = {
    'CPU_CUM': '#8e44ad',   # Purple (累计CPU)
    'CPU_RATE': '#7f8c8d',  # Gray (使用率)
    'TREND': '#4e79a7',     # Blue (趋势)
    'BOX': '#4e79a7',       # Blue (箱线图)
    'ERROR': '#e15759',     # Red (错误)
}

# =============================================================================
# 2. 数据处理辅助
# =============================================================================

def load_jsonl_as_df(dir_path: Path) -> pd.DataFrame:
    """加载 JSONL 文件为 DataFrame"""
    records = []
    if not dir_path.exists():
        return pd.DataFrame()

    for f in sorted(dir_path.glob("*.jsonl")):
        try:
            with open(f, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except:
                        continue
        except:
            continue

    df = pd.DataFrame(records)
    if df.empty:
        return df

    # 统一时间列
    for col in ['timestamp', 'time', 'ts']:
        if col in df.columns:
            df['ts'] = df[col]
            break

    if 'ts' in df.columns:
        df['ts'] = df['ts'].astype(float)
        df = df.sort_values('ts')
        start_ts = df['ts'].iloc[0]
        df['minutes'] = (df['ts'] - start_ts) / 60.0

    return df


def _style_axes(ax, ylabel, right_ax=None, right_ylabel=None):
    """应用统一的坐标轴样式 (与 E2 一致)"""
    # 主轴样式
    ax.set_ylabel(ylabel, fontweight='bold', labelpad=10)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False if not right_ax else True)
    ax.spines['left'].set_linewidth(1.2)
    ax.spines['bottom'].set_linewidth(1.2)
    ax.grid(axis='y', linestyle='--', alpha=0.5, zorder=0)
    ax.set_axisbelow(True)

    for label in ax.get_yticklabels() + ax.get_xticklabels():
        label.set_fontweight('bold')

    # 右轴样式
    if right_ax:
        right_ax.set_ylabel(right_ylabel, fontweight='bold', labelpad=10)
        right_ax.spines['top'].set_visible(False)
        right_ax.spines['left'].set_visible(False)
        right_ax.spines['right'].set_linewidth(1.2)
        for label in right_ax.get_yticklabels():
            label.set_fontweight('bold')


# =============================================================================
# 3. 绘图逻辑
# =============================================================================

def plot_resources_pub(log_dir: Path, out_dir: Path):
    """
    资源图：参考 e3_check_cpu.py 的风格
    - 左轴：累计 CPU 时间（秒）
    - 右轴：CPU 使用率（平滑后）
    """
    df = load_jsonl_as_df(log_dir / "resources")
    if df.empty:
        return

    # 确定 CPU 列名
    cpu_col = None
    if 'total_cpu_ms' in df.columns:
        cpu_col = 'total_cpu_ms'
    elif 'local_cpu_ms_from_start' in df.columns:
        cpu_col = 'local_cpu_ms_from_start'

    if not cpu_col:
        return

    # 计算累计 CPU 时间（秒）
    df['cpu_seconds'] = df[cpu_col] / 1000.0

    # 计算 CPU 使用率
    df['delta_cpu'] = df[cpu_col].diff()
    df['delta_ts'] = df['ts'].diff() * 1000.0  # 转为 ms
    df['cpu_usage_pct'] = (df['delta_cpu'] / df['delta_ts']) * 100.0

    # 清洗异常值
    df['cpu_usage_pct'] = df['cpu_usage_pct'].replace([np.inf, -np.inf], np.nan)

    # 平滑处理（窗口=5，保持响应性）
    df['cpu_usage_ma'] = df['cpu_usage_pct'].rolling(window=5, min_periods=1).mean()

    # 验证数据有效性
    if df.empty or len(df) < 2:
        print("⚠ Warning: Insufficient data for resources plot")
        return

    # --- 绘图 ---
    fig, ax1 = plt.subplots(figsize=(12, 7))

    # 1. 累计 CPU 时间（左轴，粗实线）
    line1 = ax1.plot(df['minutes'], df['cpu_seconds'],
                     color=COLORS['CPU_CUM'],
                     linewidth=3,
                     label="Cumulative CPU Time (s)",
                     zorder=3)

    # 2. CPU 使用率（右轴，虚线 + 标记点）
    ax2 = ax1.twinx()
    line2 = ax2.plot(df['minutes'], df['cpu_usage_ma'],
                     color=COLORS['CPU_RATE'],
                     linestyle='--',
                     marker='x',
                     markersize=4,
                     linewidth=2,
                     alpha=0.7,
                     label="CPU Usage (%)",
                     zorder=3)

    # 3. 样式调整
    _style_axes(ax1, "Cumulative CPU Time (s)",
                right_ax=ax2, right_ylabel="CPU Usage (%)")
    ax1.set_xlabel("Time (minutes)", fontweight='bold', labelpad=10)

    # 设置右轴范围（留出顶部空间）
    cpu_usage_max = df['cpu_usage_ma'].max()
    if not pd.isna(cpu_usage_max):
        ax2.set_ylim(0, max(20, cpu_usage_max * 1.5))

    # 4. 合并图例（左上角）
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="upper left", frameon=False)

    plt.tight_layout()
    plt.savefig(out_dir / "E3_resources_pub.png", bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✓ Saved E3_resources_pub.png")


def plot_circuit_build_pub(log_dir: Path, out_dir: Path):
    """
    建路时间图：趋势线 + 标准差阴影
    - 主线：滑动平均趋势
    - 阴影区：标准差 (±1σ)，展示波动性
    - 失败点：红色标记
    """
    df_list = []
    for name in ["circuits", "events"]:
        d = load_jsonl_as_df(log_dir / name)
        if not d.empty:
            df_list.append(d)

    if not df_list:
        return
    df = pd.concat(df_list, ignore_index=True).sort_values('ts')

    df_build = df[(df['event'] == 'circuit_start') &
                  (df['build_ms'].notna())].copy()
    if df_build.empty:
        return

    start_ts = df['ts'].min()
    df_build['minutes'] = (df_build['ts'] - start_ts) / 60.0
    df_build['build_ms'] = df_build['build_ms'].astype(float)

    # 过滤极端异常值（保留 99.5% 的数据）
    threshold = df_build['build_ms'].quantile(0.995)
    plot_df = df_build[df_build['build_ms'] <= threshold].copy()

    if plot_df.empty:
        print("⚠ Warning: No valid data for circuit build plot")
        return

    # 计算滑动统计（窗口=20）
    window = 20
    plot_df['mean'] = plot_df['build_ms'].rolling(window=window, min_periods=5).mean()
    plot_df['std'] = plot_df['build_ms'].rolling(window=window, min_periods=5).std()

    # 填充 NaN
    plot_df['mean'] = plot_df['mean'].fillna(0)
    plot_df['std'] = plot_df['std'].fillna(0)

    # 验证数据有效性
    if plot_df.empty or plot_df['mean'].isna().all():
        print("⚠ Warning: Insufficient data for circuit build plot")
        return

    # --- 绘图 ---
    fig, ax = plt.subplots(figsize=(12, 7))

    # 1. 标准差阴影带 (±1σ)
    ax.fill_between(
        plot_df['minutes'],
        plot_df['mean'] - plot_df['std'],
        plot_df['mean'] + plot_df['std'],
        color='#a6cee3',  # 浅蓝
        alpha=0.3,
        zorder=2,
        label="Volatility (±1σ)"
    )

    # 2. 趋势线（主角）
    ax.plot(plot_df['minutes'], plot_df['mean'],
            color=COLORS['TREND'],
            linewidth=3,
            zorder=4,
            label=f"Trend (MA-{window})")

    # 3. 失败点标记（如果存在）
    df_fail = df[df['event'] == 'circuit_build_fail'].copy()
    if not df_fail.empty:
        df_fail['minutes'] = (df_fail['ts'] - start_ts) / 60.0
        ax.scatter(df_fail['minutes'], [0] * len(df_fail),
                   color=COLORS['ERROR'],
                   marker='x',
                   s=100,
                   linewidth=3,
                   label="Build Failure",
                   zorder=5)

    # 4. 样式调整
    _style_axes(ax, "Circuit Build Latency (ms)")
    ax.set_xlabel("Time (minutes)", fontweight='bold', labelpad=10)

    # 安全设置 Y 轴范围
    upper_bound = plot_df['mean'] + plot_df['std']
    max_val = upper_bound.replace([np.inf, -np.inf], np.nan).max()
    if pd.isna(max_val) or max_val <= 0:
        max_val = plot_df['build_ms'].max()
    ax.set_ylim(bottom=0, top=max_val * 1.15)

    # 5. 图例
    ax.legend(loc="upper right", frameon=False)

    plt.tight_layout()
    plt.savefig(out_dir / "E3_circuit_build_pub.png", bbox_inches='tight', dpi=150)
    plt.close()
    print(f"✓ Saved E3_circuit_build_pub.png")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate publication-quality E3 plots (E2-style)"
    )
    parser.add_argument("--log-dir", type=Path,
                        help="Log directory path")
    parser.add_argument("--out", type=Path,
                        help="Output directory for figures")
    args = parser.parse_args()

    # 自动推断 log 目录
    log_dir = args.log_dir
    if not log_dir:
        ratio_label = os.environ.get("RATIO_LABEL", "50%")
        log_dir = Path("exp") / "deployment" / "e3" / ratio_label / "logs"

    if not log_dir.exists():
        print(f"✗ Error: Log directory not found: {log_dir}")
        return

    # 输出目录
    out_dir = args.out or (log_dir / "figures_pub")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"Generating Publication-Quality E3 Plots")
    print(f"{'='*60}")
    print(f"Log Dir:    {log_dir}")
    print(f"Output Dir: {out_dir}\n")

    # 生成图表
    plot_resources_pub(log_dir, out_dir)
    plot_circuit_build_pub(log_dir, out_dir)

    print(f"\n{'='*60}")
    print(f"✓ All plots generated successfully!")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()