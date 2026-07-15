"""
Analyze E2 fixed-pacing experiment outputs and generate comparison plots.
(Optimized for Publication-Quality Figures with Data Tables)
"""
from __future__ import annotations

import argparse
import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

import matplotlib.pyplot as plt
import matplotlib
import numpy as np # 引入numpy以方便处理坐标

# --- 1. 全局绘图风格设置 ---
# 使用无衬线字体，更具现代感和学术清晰度
matplotlib.rcParams.update({
    'font.family': 'sans-serif',
    'font.sans-serif': ['DejaVu Sans', 'Arial', 'Helvetica'],
    'font.size': 20,
    'axes.labelsize': 20,
    'axes.titlesize': 22,
    'xtick.labelsize': 18,
    'ytick.labelsize': 18,
    'legend.fontsize': 18,
    'figure.dpi': 150, # 提高默认分辨率
})

# 定义统一的配色方案 (Tableau 风格)
COLORS = {
    'MEAN': '#4e79a7', # Blue
    'P50':  '#59a14f', # Green
    'P90':  '#f28e2b', # Orange
    'P99':  '#e15759', # Red
    'SINGLE': '#4e79a7' # 单一柱状图的默认颜色
}

@dataclass
class RunRecords:
    ratio_label: str
    circuits: List[dict]
    streams: List[dict]
    resources: List[dict]
    source: Path


def _fmt(value: Optional[float]) -> str:
    return f"{value:.2f}" if value is not None else "nan"


def _percentile(values: List[float], pct: float) -> Optional[float]:
    if not values:
        return None
    pct = max(0.0, min(100.0, pct))
    ordered = sorted(values)
    pos = (len(ordered) - 1) * pct / 100.0
    lower = math.floor(pos)
    upper = math.ceil(pos)
    if lower == upper:
        return ordered[int(pos)]
    low_val = ordered[lower]
    high_val = ordered[upper]
    return low_val + (high_val - low_val) * (pos - lower)


def _sort_ratio_labels(labels: List[str]) -> List[str]:
    def extract_number(label: str) -> float:
        match = re.search(r'(\d+(?:\.\d+)?)', label)
        return float(match.group(1)) if match else 0.0
    return sorted(labels, key=extract_number)


import gzip

def _load_jsonl_files(dir_path: Path) -> List[dict]:
    records: List[dict] = []
    if not dir_path.exists():
        print("[miss]", dir_path)
        return records

    files = list(dir_path.glob("*"))
    print("[scan]", dir_path, "files=", len(files), "sample=", [p.name for p in files[:5]])

    def read_lines(fp):
        nonlocal records
        bad = 0
        total = 0
        for line in fp:
            total += 1
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
        print("[read]", dir_path.name, "lines=", total, "ok=", len(records), "bad=", bad)

    # 1) .jsonl
    for file in sorted(dir_path.glob("*.jsonl")):
        with file.open("r", encoding="utf-8") as f:
            read_lines(f)

    # 2) .jsonl.gz
    for file in sorted(dir_path.glob("*.jsonl.gz")):
        with gzip.open(file, "rt", encoding="utf-8") as f:
            read_lines(f)

    return records


def _normalize_log_dir(meta_path: Path, meta: dict) -> Path:
    # 1) 如果 run_meta.json 在 logs 里，logs 就是 log_dir
    if meta_path.parent.name == "logs":
        base_logs = meta_path.parent
    else:
        base_logs = meta_path.parent / "logs"

    # 2) meta 里如果写了 log_dir，处理相对路径
    log_dir = meta.get("log_dir")
    if log_dir:
        p = Path(log_dir)

        # 相对路径按 run_meta.json 所在目录解析
        if not p.is_absolute():
            p = (meta_path.parent / p).resolve()

        # 若解析结果不存在，则回退到 base_logs
        if p.exists():
            return p

    # 3) meta 没写或写错，回退到 base_logs
    if base_logs.exists():
        return base_logs

    # 4) 最后兜底
    return meta_path.parent



def load_run(meta_path: Path) -> Optional[RunRecords]:
    print("start")
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None

    ratio_label = meta.get("ratio_label") or meta_path.parent.name
    log_dir = _normalize_log_dir(meta_path, meta)
    print(log_dir)
    circuits = _load_jsonl_files(log_dir / "circuits")
    streams = _load_jsonl_files(log_dir / "streams")
    resources = _load_jsonl_files(log_dir / "resources")

    print(circuits)
    print(streams)
    print(resources)
    if not any((circuits, streams, resources)):
        return None

    return RunRecords(
        ratio_label=str(ratio_label),
        circuits=circuits,
        streams=streams,
        resources=resources,
        source=meta_path,
    )


def discover_runs(root: Path, explicit_meta: Iterable[Path]) -> List[RunRecords]:
    runs: List[RunRecords] = []
    found = list(root.rglob("run_meta.json"))
    print("found meta =", len(found))
    for p in found[:10]:
        print(" ", p)
    searched: List[Path] = []
    for meta in explicit_meta:
        meta_path = meta if meta.name == "run_meta.json" else meta / "run_meta.json"
        searched.append(meta_path)
        rec = load_run(meta_path)
        if rec:
            runs.append(rec)

    if not explicit_meta:
        for meta_path in root.rglob("run_meta.json"):
            rec = load_run(meta_path)
            if rec:
                runs.append(rec)
                searched.append(meta_path)
    return runs


def summarize_ratio(run: RunRecords) -> dict:
    circuits = [c for c in run.circuits if c.get("success")]
    build_ms = [float(c.get("build_ms", 0.0)) for c in circuits if "build_ms" in c]

    streams_ok = [s for s in run.streams if s.get("status") == "ok"]
    stream_latency = [float(s["latency_ms_total"]) for s in streams_ok if "latency_ms_total" in s]

    local_cpu = [float(r.get("local_cpu_ms_from_start", 0.0)) for r in run.resources if "local_cpu_ms_from_start" in r]
    vm_cpu = [float(r.get("vm_cpu_ms_from_start", 0.0)) for r in run.resources if "vm_cpu_ms_from_start" in r]
    cpu_total_ms = (max(local_cpu) if local_cpu else 0.0) + (max(vm_cpu) if vm_cpu else 0.0)

    peak_mem_mb_candidates = []
    for r in run.resources:
        for key in ("total_mem_mb", "local_rss_mb", "vm_mem_mb"):
            val = r.get(key)
            if isinstance(val, (int, float)):
                peak_mem_mb_candidates.append(float(val))
    peak_mem_mb = max(peak_mem_mb_candidates) if peak_mem_mb_candidates else None

    circuits_count = len(circuits)
    cpu_per_circuit = cpu_total_ms / circuits_count if circuits_count and cpu_total_ms else None

    return {
        "ratio": run.ratio_label,
        "build_ms": build_ms,
        "build_quantiles": {
            "mean": sum(build_ms) / len(build_ms) if build_ms else None,
            "p50": _percentile(build_ms, 50),
            "p90": _percentile(build_ms, 90),
            "p99": _percentile(build_ms, 99),
        },
        "circuit_success": circuits_count,
        "streams_ok": len(streams_ok),
        "stream_latency": stream_latency,
        "stream_latency_avg": sum(stream_latency) / len(stream_latency) if stream_latency else None,
        "stream_latency_p90": _percentile(stream_latency, 90),
        "cpu_total_ms": cpu_total_ms if cpu_total_ms else None,
        "cpu_per_circuit": cpu_per_circuit,
        "peak_mem_mb": peak_mem_mb,
    }


# --- 辅助函数：统一的坐标轴美化 ---
def _style_axes(ax, ylabel):
    ax.set_ylabel(ylabel, fontweight='bold', labelpad=10)
    # 移除顶部和右侧边框
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    # 加粗左侧和底部边框
    ax.spines['left'].set_linewidth(1.2)
    ax.spines['bottom'].set_linewidth(1.2)
    # 添加水平网格线，置于底层
    ax.grid(axis='y', linestyle='--', alpha=0.5, zorder=0)
    ax.set_axisbelow(True)
    for label in ax.get_yticklabels():
        label.set_fontweight('bold')


# --- 核心绘图函数 1：带表格的复杂柱状图 ---
def plot_circuit_build(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = _sort_ratio_labels(list(summary.keys()))
    if not ratios:
        return

    labels = [summary[r]["ratio"] for r in ratios]
    metrics = [summary[r]["build_quantiles"] for r in ratios]

    # 对应键值和颜色
    keys = ["mean", "p50", "p90", "p99"]
    display_keys = ["MEAN", "P50", "P90", "P99"]
    bar_colors = [COLORS['MEAN'], COLORS['P50'], COLORS['P90'], COLORS['P99']]

    # 设置画布
    fig, ax = plt.subplots(figsize=(11, 7)) # 稍微调高一点给表格留空间

    x = np.arange(len(labels))
    width = 0.18
    # 偏移量计算，使柱子居中
    offsets = [-1.5, -0.5, 0.5, 1.5]

    # 1. 绘制柱子 (不再在柱子上写字)
    for i, key in enumerate(keys):
        vals = [(m.get(key) or 0) for m in metrics]
        ax.bar(x + offsets[i] * width, vals, width,
               label=display_keys[i],
               color=bar_colors[i],
               edgecolor='black', linewidth=0.5, zorder=3)

    # 2. 准备表格数据 (行: Ratios, 列: Metrics)
    table_data = []
    for m in metrics:
        row = []
        for key in keys:
            val = m.get(key)
            row.append(f"{val:.1f}" if val is not None else "-")
        table_data.append(row)

    # 3. 绘制右上角表格
    # bbox=[left, bottom, width, height]
    the_table = ax.table(cellText=table_data,
                         rowLabels=labels,
                         colLabels=display_keys,
                         colColours=bar_colors, # 表头颜色与柱子一致
                         loc='upper right',
                         bbox=[0.55, 0.55, 0.42, 0.35]) # 根据实际留白调整位置

    # 4. 表格样式优化
    the_table.auto_set_font_size(False)
    the_table.set_fontsize(16)
    for (row, col), cell in the_table.get_celld().items():
        cell.set_linewidth(1.5)
        cell.set_edgecolor('gray')
        # 设置表头字体为白色加粗
        if row == 0:
            cell.set_text_props(color='white', fontweight='bold')

    # 5. 设置坐标轴和图例
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontweight='bold')
    # 留出顶部空间给表格
    max_val = max((m.get('p99') or 0) for m in metrics)
    ax.set_ylim(0, max_val * 1.15)

    _style_axes(ax, "Circuit build latency (ms)")

    # 图例放左上角，避免遮挡
    ax.legend(loc='upper left', frameon=False, ncol=4)

    fig.tight_layout()
    fig.savefig(out_path / "E2_circuit_build_latency.png", bbox_inches='tight')
    plt.close(fig)


# --- 核心绘图函数 2：简单柱状图 (Memory/CPU) ---
def plot_simple_bar(ratios, values, ylabel, filename, out_path, color=COLORS['SINGLE']):
    if not any(v is not None for v in values):
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(ratios))

    # 绘制柱子
    bars = ax.bar(x, [(v or 0) for v in values],
                  color=color, width=0.5,
                  edgecolor='black', linewidth=0.8, zorder=3)

    # 简单图表保留数值标签 (因为没有表格)
    for bar, val in zip(bars, values):
        if val is not None and val > 0:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height + (height*0.01),
                   f'{val:.1f}',
                   ha='center', va='bottom', fontsize=15, fontweight='bold', color='#333333')

    ax.set_xticks(x)
    ax.set_xticklabels(ratios, fontweight='bold')

    # 统一坐标轴风格
    _style_axes(ax, ylabel)
    # 稍微增加顶部空间
    ax.set_ylim(0, max((v or 0) for v in values) * 1.15)

    fig.tight_layout()
    fig.savefig(out_path / filename, bbox_inches='tight')
    plt.close(fig)


def plot_cpu(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = _sort_ratio_labels(list(summary.keys()))
    values = [summary[r].get("cpu_per_circuit") for r in ratios]
    plot_simple_bar(ratios, values, "CPU ms per built circuit", "cpu_per_circuit.png", out_path)


def plot_memory(summary: Dict[str, dict], out_path: Path) -> None:
    ratios = _sort_ratio_labels(list(summary.keys()))
    mem_values = [summary[r].get("peak_mem_mb") for r in ratios]
    # 使用稍微不同的颜色区分 Memory
    plot_simple_bar(ratios, mem_values, "Peak memory usage (MB)", "E2_resource_memory.png", out_path, color='#7570b3')


def plot_stream_latency(summary: Dict[str, dict], out_path: Path) -> None:
    # 这个图有两个系列 (Mean, P90)，我们保持简单双柱风格，但应用新配色和样式
    ratios = _sort_ratio_labels(list(summary.keys()))
    avg_values = [summary[r].get("stream_latency_avg") for r in ratios]
    p90_values = [summary[r].get("stream_latency_p90") for r in ratios]

    if not any(v is not None for v in avg_values):
        return

    fig, ax = plt.subplots(figsize=(10, 6))
    x = np.arange(len(ratios))
    width = 0.35

    bars1 = ax.bar(x - width/2, [(v or 0) for v in avg_values], width, label='Mean', color=COLORS['MEAN'], edgecolor='black', linewidth=0.5, zorder=3)
    bars2 = ax.bar(x + width/2, [(v or 0) for v in p90_values], width, label='P90', color=COLORS['P90'], edgecolor='black', linewidth=0.5, zorder=3)

    # 添加数值标签
    for bars, vals in [(bars1, avg_values), (bars2, p90_values)]:
        for bar, val in zip(bars, vals):
            if val is not None and val > 0:
                ax.text(bar.get_x() + bar.get_width()/2., bar.get_height(),
                       f'{val:.1f}', ha='center', va='bottom', fontsize=10)

    ax.set_xticks(x)
    ax.set_xticklabels(ratios, fontweight='bold')
    _style_axes(ax, "Stream completion latency (ms)")
    ax.legend(frameon=False, loc='upper left')

    fig.tight_layout()
    fig.savefig(out_path / "stream_latency.png", bbox_inches='tight')
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze E2 fixed-pacing experiment logs")
    parser.add_argument("--root", type=Path, default=Path("exp/deployment/e2"), help="Root directory containing run_meta.json files")
    parser.add_argument("--run", dest="runs", action="append", type=Path, default=[], help="Optional explicit run_meta.json paths or their parent dirs")
    parser.add_argument("--out", type=Path, default=Path("e2_output"), help="Directory to write figures and summaries")
    args = parser.parse_args()

    runs = discover_runs(args.root, args.runs)
    if not runs:
        return

    runs_by_ratio: Dict[str, List[RunRecords]] = defaultdict(list)
    for run in runs:
        runs_by_ratio[run.ratio_label].append(run)

    summary: Dict[str, dict] = {}
    for ratio, ratio_runs in sorted(runs_by_ratio.items()):
        merged = RunRecords(
            ratio_label=ratio,
            circuits=[],
            streams=[],
            resources=[],
            source=ratio_runs[0].source,
        )
        for r in ratio_runs:
            merged.circuits.extend(r.circuits)
            merged.streams.extend(r.streams)
            merged.resources.extend(r.resources)
        summary[ratio] = summarize_ratio(merged)

    args.out.mkdir(parents=True, exist_ok=True)

    # 打印文字摘要
    print("[Summary]")
    for ratio in _sort_ratio_labels(list(summary.keys())):
        metrics = summary[ratio]
        print(f"- {ratio}:")
        build = metrics["build_quantiles"]
        print(f"  circuits={metrics['circuit_success']} build_ms mean={_fmt(build.get('mean'))} ...")

    # 生成图表
    plot_circuit_build(summary, args.out)
    plot_cpu(summary, args.out)
    plot_stream_latency(summary, args.out)
    plot_memory(summary, args.out)


if __name__ == "__main__":
    main()