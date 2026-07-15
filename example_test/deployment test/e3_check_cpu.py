"""
e3_check_cpu.py

用于验证资源统计是否存在异常。
功能：
1. 绘制 "Cumulative CPU Time" (累计CPU时间) 替代原本的 Memory 曲线。
2. 打印 Memory 和 CPU Time 的统计摘要，对比数值范围。

用法:
    python e3_check_cpu.py --log-dir <LOG_DIR>
"""

import argparse
import json
import matplotlib.pyplot as plt
import pandas as pd
from pathlib import Path
import sys

# 样式设置
plt.style.use('seaborn-v0_8-whitegrid')


def load_resources(log_dir: Path) -> pd.DataFrame:
    records = []
    res_dir = log_dir / "resources"
    if not res_dir.exists():
        print(f"[Error] Directory not found: {res_dir}")
        return pd.DataFrame()

    print(f"[Info] Loading logs from {res_dir}...")
    for f in sorted(res_dir.glob("*.jsonl")):
        with open(f, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line: continue
                try:
                    records.append(json.loads(line))
                except:
                    pass

    if not records:
        print("[Warn] No records found.")
        return pd.DataFrame()

    df = pd.DataFrame(records)

    # 统一时间轴
    ts_col = next((c for c in ['ts', 'timestamp', 'time'] if c in df.columns), None)
    if not ts_col:
        print("[Error] No timestamp column found.")
        return pd.DataFrame()

    df['ts'] = df[ts_col].astype(float)
    df = df.sort_values('ts')
    start_ts = df['ts'].iloc[0]
    df['minutes'] = (df['ts'] - start_ts) / 60.0

    return df


def plot_cpu_check(df: pd.DataFrame, out_dir: Path):
    # 确定列名
    cpu_col = 'total_cpu_ms' if 'total_cpu_ms' in df.columns else 'local_cpu_ms_from_start'
    mem_col = 'total_mem_mb' if 'total_mem_mb' in df.columns else 'local_rss_mb'

    if cpu_col not in df.columns:
        print("[Error] No CPU metrics found in logs.")
        return

    # 准备数据：将 ms 转换为 秒 (Seconds) 以便人类阅读
    df['cpu_seconds'] = df[cpu_col] / 1000.0

    # 计算 CPU 使用率 (差分) 用于右轴
    # Usage % = (delta_cpu_ms / delta_time_ms) * 100
    df['delta_cpu'] = df[cpu_col].diff()
    df['delta_ts'] = df['ts'].diff() * 1000.0  # to ms
    df['cpu_usage_pct'] = (df['delta_cpu'] / df['delta_ts']) * 100.0
    # 平滑一下曲线
    df['cpu_usage_pct_ma'] = df['cpu_usage_pct'].rolling(window=5, min_periods=1).mean()

    # --- 统计检查 (Sanity Check) ---
    print("\n" + "=" * 40)
    print("      DATA SANITY CHECK")
    print("=" * 40)

    if mem_col in df.columns:
        mem_min, mem_max = df[mem_col].min(), df[mem_col].max()
        print(f"Memory (MB) Range:    {mem_min:.2f} -> {mem_max:.2f}")

    cpu_min, cpu_max = df['cpu_seconds'].min(), df['cpu_seconds'].max()
    print(f"CPU Time (Sec) Range: {cpu_min:.2f} -> {cpu_max:.2f}")

    if mem_col in df.columns:
        # 计算相关性
        corr = df[mem_col].corr(df['cpu_seconds'])
        print(f"Correlation (Mem vs CPU Time): {corr:.4f}")
        if corr > 0.95:
            print("(!) Notice: High correlation. Both are growing linearly.")
            print("    This confirms the leak is as constant as time itself.")
        else:
            print("    Correlation is not perfect, shapes differ.")

        # 比例检查
        ratio = df[mem_col].mean() / df['cpu_seconds'].mean() if df['cpu_seconds'].mean() > 0 else 0
        print(f"Magnitude Ratio (Mem / CPU):   ~{ratio:.2f}x")
        print("    (If this was a label mix-up, ratio would be ~1.0)")
    print("=" * 40 + "\n")

    # --- 绘图 ---
    fig, ax1 = plt.subplots(figsize=(12, 6))

    # 左轴：累计 CPU 时间 (替代了 Memory)
    color_cpu_cum = '#8e44ad'  # Purple
    ax1.plot(df['minutes'], df['cpu_seconds'], color=color_cpu_cum, linewidth=2, label='Cumulative CPU Time (s)')
    ax1.set_xlabel('Time (minutes)')
    ax1.set_ylabel('Cumulative CPU Time (Seconds)', color=color_cpu_cum, fontweight='bold')
    ax1.tick_params(axis='y', labelcolor=color_cpu_cum)
    ax1.grid(True, linestyle='--', alpha=0.5)

    # 右轴：CPU 使用率 (保持不变作为参考)
    ax2 = ax1.twinx()
    color_cpu_rate = '#7f8c8d'  # Gray
    ax2.plot(df['minutes'], df['cpu_usage_pct_ma'], color=color_cpu_rate, linestyle='--', marker='x', markersize=4,
             alpha=0.7, label='CPU Usage (%)')
    ax2.set_ylabel('CPU Usage (%)', color=color_cpu_rate)
    ax2.tick_params(axis='y', labelcolor=color_cpu_rate)
    ax2.set_ylim(0, max(20, df['cpu_usage_pct_ma'].max() * 1.5))  # 稍微留空

    # 图例
    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

    plt.title('Sanity Check: Cumulative CPU Time vs CPU Usage', fontweight='bold')

    out_file = out_dir / "debug_cpu_check.png"
    plt.savefig(out_file, dpi=150)
    plt.close()
    print(f"[Plot] Saved chart to {out_file}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log-dir", type=Path, help="Log directory")
    parser.add_argument("--out", type=Path, help="Output directory")
    args = parser.parse_args()

    # 自动推断目录
    log_dir = args.log_dir
    if not log_dir:
        import os
        ratio_label = os.environ.get("RATIO_LABEL", "50%")
        log_dir = Path("exp") / "deployment" / "e3" / ratio_label / "logs"

    if not log_dir.exists():
        print(f"Log directory not found: {log_dir}")
        return

    out_dir = args.out or (log_dir / "figures_debug")
    out_dir.mkdir(parents=True, exist_ok=True)

    df = load_resources(log_dir)
    if not df.empty:
        plot_cpu_check(df, out_dir)


if __name__ == "__main__":
    main()