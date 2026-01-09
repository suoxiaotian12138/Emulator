"""e1_analyze_scalability (IDE-friendly)

Changes compared to the original script:
1) Robust input handling:
   - --tor / --torbox can point to a JSONL file OR a directory containing one or more *.jsonl files.
   - If a directory is provided, we read all *.jsonl under it (non-recursive by default).

2) Windows-path safety:
   - Default paths are expressed as forward-slash style strings so Python does not treat backslashes
     as escape sequences.
   - You can still pass normal Windows paths; Path() will handle them.

3) IDE execution:
   - You can call run_in_ide() directly (set TOR_PATH / TORBOX_PATH / OUT_DIR in that function).
   - CLI execution still works: python e1_analyze_scalability_ide.py --tor ... --torbox ... --out ...

The PermissionError you saw (Errno 13) is most commonly caused by passing a *directory* path
to a function that tries to open it as a file on Windows.
"""

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Iterable

import matplotlib.pyplot as plt


def percentile(values: List[float], q: float) -> Optional[float]:
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
    """Return a list of JSONL files given a file-or-directory path."""
    p = path.expanduser()

    if not p.exists():
        raise FileNotFoundError(f"Input path does not exist: {p}")

    if p.is_file():
        return [p]

    # Directory case
    pattern = "**/*.jsonl" if recursive else "*.jsonl"
    files = sorted(p.glob(pattern))

    # If no *.jsonl, fall back to 'circuits' style: a file without extension named 'circuits.jsonl' is common,
    # but some loggers write directly to 'circuits' (no extension). We try a couple of reasonable guesses.
    if not files:
        guesses = [
            p / "circuits.jsonl",
            p / "circuits.log",
            p / "circuits",  # may still be a file
        ]
        for g in guesses:
            if g.exists() and g.is_file():
                files.append(g)

    if not files:
        raise FileNotFoundError(
            f"No JSONL files found under directory: {p}\n"
            f"Tried: {pattern} and common guesses like circuits.jsonl / circuits.log"
        )
    return files


def _read_jsonl_file(fp: Path) -> List[dict]:
    rows: List[dict] = []
    with fp.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                # Skip broken lines but keep going; large-scale experiments sometimes have partial writes.
                # If you want strict behavior, change this to "raise".
                continue
    return rows


def read_circuits_jsonl(path: Path, *, recursive: bool = False) -> List[dict]:
    """Read circuits logs from a JSONL file or directory.

    - If 'path' is a file: read it as JSONL.
    - If 'path' is a directory: read all *.jsonl inside (optionally recursive).
    """
    files = _iter_jsonl_files(path, recursive=recursive)
    rows: List[dict] = []
    for fp in files:
        rows.extend(_read_jsonl_file(fp))
    return rows


def extract_attempts(rows: List[dict]) -> List[dict]:
    out = []
    for r in rows:
        # Compatible with your writer: event=circuit_attempt
        if r.get("event") != "circuit_attempt":
            continue
        out.append(r)
    return out


def summarize_by_level(
    attempts: List[dict],
    *,
    timeout_s: float,
    period_s: float,
    measure_s: float,
) -> Tuple[List[int], Dict[int, dict]]:
    levels = sorted({int(a["load_level"]) for a in attempts if "load_level" in a})
    stats: Dict[int, dict] = {}

    timeout_ms = timeout_s * 1000.0

    for lv in levels:
        xs = [a for a in attempts if int(a.get("load_level", -1)) == lv and a.get("phase") == "measure"]
        if not xs:
            continue

        ok = [a for a in xs if a.get("status") == "ok"]
        fail = [a for a in xs if a.get("status") == "fail"]
        drop = [a for a in xs if a.get("status") == "drop"]

        # Success rate excludes drop to avoid pacer-policy artifacts
        denom = (len(ok) + len(fail))
        success_rate = 0.0 if denom == 0 else (len(ok) / denom)

        # Offered / achieved
        offered_rate = lv / period_s if period_s > 0 else None
        goodput = len(ok) / measure_s if measure_s > 0 else None

        # Latency percentiles: OK only, total latency_ms
        ok_lat = []
        for a in ok:
            try:
                ok_lat.append(float(a["latency_ms"]))
            except Exception:
                continue

        p50 = percentile(ok_lat, 50)
        p95 = percentile(ok_lat, 95)
        p99 = percentile(ok_lat, 99)

        # Optional p99.9 when sample size is sufficient (>= 1000 OK samples is a decent rule of thumb)
        p999 = percentile(ok_lat, 99.9) if len(ok_lat) >= 1000 else None

        # Failure breakdown (rates computed over all measure attempts, including drop)
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
        other_fail_rate = other_fail / total if total else 0.0

        # For table: include drop as a reason too
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
            "other_fail_rate": other_fail_rate,
            "top_reasons": top_reasons,
        }

    return levels, stats


def plot_compare(
        out_dir: Path,
        tor_levels: List[int],
        tor_stats: Dict[int, dict],
        torbox_levels: List[int],
        torbox_stats: Dict[int, dict],
) -> None:
    """优化后的绘图函数，使用更美观的样式"""
    out_dir.mkdir(parents=True, exist_ok=True)

    # 设置全局样式
    plt.style.use('seaborn-v0_8-darkgrid')
    plt.rcParams['font.size'] = 11
    plt.rcParams['axes.labelsize'] = 12
    plt.rcParams['axes.titlesize'] = 14
    plt.rcParams['legend.fontsize'] = 10
    plt.rcParams['figure.figsize'] = (10, 6)

    # 定义配色方案
    colors = {
        'tor': '#E74C3C',  # 红色系
        'torbox': '#3498DB',  # 蓝色系
        'tor_light': '#F1948A',
        'torbox_light': '#85C1E9',
        'ideal': '#95A5A6'  # 灰色
    }

    def series(levels, stats, x_key, y_key):
        xs, ys = [], []
        for lv in levels:
            if lv in stats and stats[lv].get(x_key) is not None and stats[lv].get(y_key) is not None:
                xs.append(stats[lv][x_key])
                ys.append(stats[lv][y_key])
        return xs, ys

    # ===== Figure 1: 延迟对比图 =====
    fig1, ax1 = plt.subplots(figsize=(12, 7))

    # p99 延迟（实线，粗线条）
    x1, y1 = series(tor_levels, tor_stats, "offered_rps", "p99_ms")
    x2, y2 = series(torbox_levels, torbox_stats, "offered_rps", "p99_ms")
    ax1.plot(x1, y1, marker='o', linewidth=2.5, markersize=8,
             color=colors['tor'], label='Tor p99', alpha=0.9)
    ax1.plot(x2, y2, marker='s', linewidth=2.5, markersize=8,
             color=colors['torbox'], label='TorBox p99', alpha=0.9)

    # p50 延迟（虚线，细线条）
    x1m, y1m = series(tor_levels, tor_stats, "offered_rps", "p50_ms")
    x2m, y2m = series(torbox_levels, torbox_stats, "offered_rps", "p50_ms")
    ax1.plot(x1m, y1m, marker='o', linewidth=2, markersize=6,
             linestyle='--', color=colors['tor_light'], label='Tor p50', alpha=0.8)
    ax1.plot(x2m, y2m, marker='s', linewidth=2, markersize=6,
             linestyle='--', color=colors['torbox_light'], label='TorBox p50', alpha=0.8)

    ax1.set_xlabel('Offered Load (circuits/s)', fontweight='bold')
    ax1.set_ylabel('Circuit Latency (ms)', fontweight='bold')
    ax1.set_title('Tail Latency Comparison: Tor vs TorBox',
                  fontsize=15, fontweight='bold', pad=20)
    ax1.legend(loc='best', framealpha=0.95, shadow=True)
    ax1.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)

    plt.tight_layout()
    fig1.savefig(out_dir / "p99_latency_vs_offered.png", dpi=300, bbox_inches='tight')
    plt.close(fig1)

    # ===== Figure 2: 吞吐量对比图 =====
    fig2, ax2 = plt.subplots(figsize=(12, 7))

    # 实际吞吐量
    x1, y1 = series(tor_levels, tor_stats, "offered_rps", "goodput_rps")
    x2, y2 = series(torbox_levels, torbox_stats, "offered_rps", "goodput_rps")
    ax2.plot(x1, y1, marker='o', linewidth=2.5, markersize=8,
             color=colors['tor'], label='Tor Goodput', alpha=0.9)
    ax2.plot(x2, y2, marker='s', linewidth=2.5, markersize=8,
             color=colors['torbox'], label='TorBox Goodput', alpha=0.9)

    # 理想线（y = x）
    xs_all = sorted(set(x1 + x2))
    if xs_all:
        ax2.plot(xs_all, xs_all, linestyle=':', linewidth=2,
                 color=colors['ideal'], label='Ideal (Goodput = Offered)', alpha=0.7)

    ax2.set_xlabel('Offered Load (circuits/s)', fontweight='bold')
    ax2.set_ylabel('Achieved Goodput (circuits/s)', fontweight='bold')
    ax2.set_title('Goodput Performance: Tor vs TorBox',
                  fontsize=15, fontweight='bold', pad=20)
    ax2.legend(loc='best', framealpha=0.95, shadow=True)
    ax2.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)

    # 添加填充区域显示差距
    if x1 and y1 and xs_all:
        ax2.fill_between(xs_all, xs_all, 0, alpha=0.1, color=colors['ideal'])

    plt.tight_layout()
    fig2.savefig(out_dir / "goodput_vs_offered.png", dpi=300, bbox_inches='tight')
    plt.close(fig2)

    # ===== Figure 3: 成功率对比图（新增） =====
    fig3, ax3 = plt.subplots(figsize=(12, 7))

    x1, y1 = series(tor_levels, tor_stats, "offered_rps", "success_rate")
    x2, y2 = series(torbox_levels, torbox_stats, "offered_rps", "success_rate")

    # 转换为百分比
    y1_pct = [y * 100 for y in y1]
    y2_pct = [y * 100 for y in y2]

    ax3.plot(x1, y1_pct, marker='o', linewidth=2.5, markersize=8,
             color=colors['tor'], label='Tor Success Rate', alpha=0.9)
    ax3.plot(x2, y2_pct, marker='s', linewidth=2.5, markersize=8,
             color=colors['torbox'], label='TorBox Success Rate', alpha=0.9)

    ax3.axhline(y=100, linestyle='--', color=colors['ideal'],
                linewidth=2, alpha=0.5, label='100% Success')
    ax3.set_ylim([0, 105])

    ax3.set_xlabel('Offered Load (circuits/s)', fontweight='bold')
    ax3.set_ylabel('Success Rate (%)', fontweight='bold')
    ax3.set_title('Success Rate Comparison: Tor vs TorBox',
                  fontsize=15, fontweight='bold', pad=20)
    ax3.legend(loc='best', framealpha=0.95, shadow=True)
    ax3.grid(True, alpha=0.3, linestyle='-', linewidth=0.5)
    ax3.spines['top'].set_visible(False)
    ax3.spines['right'].set_visible(False)

    plt.tight_layout()
    fig3.savefig(out_dir / "success_rate_vs_offered.png", dpi=300, bbox_inches='tight')
    plt.close(fig3)


def print_table(name: str, levels: List[int], stats: Dict[int, dict]) -> None:
    print(f"\n=== {name} Summary (measure) ===")
    header = "level  attempts  succ    p50_ms  p90_ms  p95_ms  p99_ms  near%   timeout%  top_fail"
    print(header)
    print("-" * len(header))
    for lv in levels:
        if lv not in stats:
            continue
        s = stats[lv]
        top_fail = s["top_reasons"][0][0] if s["top_reasons"] else "-"

        def fmt(x):
            return "n/a" if x is None else f"{x:.1f}"

        print(
            f"{lv:<5}  {s['attempts']:<8}  {s['success_rate']:<6.3f}  "
            f"{fmt(s['p50_ms']):<6}  {fmt(s['p95_ms']):<6}  {fmt(s['p99_ms']):<6}  "
        )


def run(
    *,
    tor_path: str,
    torbox_path: str,
    out_dir: str,
    timeout_s: float = 5.0,
    period_s: float = 2.0,
    measure_s: float = 120.0,
    slo_factor: float = 0.8,
    near_factor: float = 0.9,
    near_rate_threshold: float = 0.05,
    recursive: bool = False,
) -> None:
    tor_rows = read_circuits_jsonl(Path(tor_path), recursive=recursive)
    torbox_rows = read_circuits_jsonl(Path(torbox_path), recursive=recursive)

    tor_attempts = extract_attempts(tor_rows)
    torbox_attempts = extract_attempts(torbox_rows)

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

    plot_compare(Path(out_dir), tor_levels, tor_stats, torbox_levels, torbox_stats)

    print(f"\nFigures saved to: {Path(out_dir).resolve()}")


# def run_in_ide() -> None:
#     """IDE入口: 直接改这里的路径，然后点运行即可。"""
#     TOR_PATH = "exp/deployment/e1_scalability/logs/tor/circuits"      # file OR directory
#     TORBOX_PATH = "exp/deployment/e1_scalability/logs/torbox/circuits"  # file OR directory
#     OUT_DIR = "analysis_out"
#
#     run(
#         tor_path=TOR_PATH,
#         torbox_path=TORBOX_PATH,
#         out_dir=OUT_DIR,
#         timeout_s=5.0,
#         slo_factor=0.8,
#         near_factor=0.9,
#         near_rate_threshold=0.05,
#         recursive=False,
#     )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--tor",
        default="exp/deployment/e1_scalability/logs/tor/circuits",
        help="Tor circuits JSONL file OR directory containing *.jsonl",
    )
    ap.add_argument(
        "--torbox",
        default="exp/deployment/e1_scalability/logs/torbox/circuits",
        help="TorBox circuits JSONL file OR directory containing *.jsonl",
    )
    ap.add_argument("--out", default="analysis_out", help="Output directory for figures")
    ap.add_argument("--timeout_s", type=float, default=5.0)
    ap.add_argument("--period_s", type=float, default=2.0, help="Per-client period used in the driver")
    ap.add_argument("--measure_s", type=float, default=120.0, help="Measure window seconds used in the driver")

    ap.add_argument("--slo_factor", type=float, default=0.8)
    ap.add_argument("--near_factor", type=float, default=0.9)
    ap.add_argument("--near_rate_threshold", type=float, default=0.05, help="0.05 means 5%")
    ap.add_argument(
        "--recursive",
        action="store_true",
        help="If --tor/--torbox is a directory, read *.jsonl recursively",
    )
    args = ap.parse_args()

    run(
        tor_path=args.tor,
        torbox_path=args.torbox,
        out_dir=args.out,
        timeout_s=args.timeout_s,
        period_s=args.period_s,
        measure_s=args.measure_s,
        slo_factor=args.slo_factor,
        near_factor=args.near_factor,
        near_rate_threshold=args.near_rate_threshold,
        recursive=args.recursive,
    )


if __name__ == "__main__":
    # IDE里直接运行：默认走 main()（兼容命令行）。
    # 如果你更喜欢固定配置运行：把下面一行改成 run_in_ide()
    main()
