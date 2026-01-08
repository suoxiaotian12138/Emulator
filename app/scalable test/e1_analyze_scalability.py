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
    slo_factor: float,
    near_factor: float,
    near_rate_threshold: float,
) -> Tuple[List[int], Dict[int, dict], Optional[int], Optional[int]]:
    levels = sorted({int(a["load_level"]) for a in attempts if "load_level" in a})
    stats: Dict[int, dict] = {}

    knee_slo = None
    knee_near = None

    for lv in levels:
        xs = [a for a in attempts if int(a.get("load_level", -1)) == lv and a.get("phase") == "measure"]
        if not xs:
            continue

        ok = [a for a in xs if a.get("status") == "ok"]
        fail = [a for a in xs if a.get("status") != "ok"]

        success_rate = len(ok) / len(xs)

        ok_lat = []
        for a in ok:
            try:
                ok_lat.append(float(a["latency_ms"]))
            except Exception:
                continue

        p50 = percentile(ok_lat, 50)
        p95 = percentile(ok_lat, 95)
        p90 = percentile(ok_lat, 90)
        p99 = percentile(ok_lat, 99)

        timeout_ms = timeout_s * 1000.0
        slo_ms = slo_factor * timeout_ms
        near_ms = near_factor * timeout_ms

        # These rates are computed over all attempts in measure phase.
        timeout_rate = sum(1 for a in xs if float(a.get("latency_ms", 0.0)) >= timeout_ms) / len(xs)
        near_timeout_rate = sum(1 for a in xs if float(a.get("latency_ms", 0.0)) >= near_ms) / len(xs)

        reasons: List[str] = []
        for a in fail:
            r = a.get("reason")
            if r:
                # Normalize: keep the exception type prefix if present
                reasons.append(str(r).split(":", 1)[0])
        top_reasons = Counter(reasons).most_common(5)

        stats[lv] = {
            "level": lv,
            "attempts": len(xs),
            "success_rate": success_rate,
            "p50_ms": p50,
            "p90_ms": p90,
            "p95_ms": p95,
            "p99_ms": p99,
            "timeout_rate": timeout_rate,
            "near_timeout_rate": near_timeout_rate,
            "top_reasons": top_reasons,
        }

        if knee_slo is None and (p95 is not None) and p95 >= slo_ms:
            knee_slo = lv
        if knee_near is None and near_timeout_rate >= near_rate_threshold:
            knee_near = lv

    return levels, stats, knee_slo, knee_near


def plot_compare(
    out_dir: Path,
    tor_levels: List[int],
    tor_stats: Dict[int, dict],
    torbox_levels: List[int],
    torbox_stats: Dict[int, dict],
    *,
    timeout_s: float,
    slo_factor: float,
    near_factor: float,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    timeout_ms = timeout_s * 1000.0
    slo_ms = slo_factor * timeout_ms

    def series(levels, stats, key):
        xs, ys = [], []
        for lv in levels:
            if lv in stats and stats[lv][key] is not None:
                xs.append(lv)
                ys.append(stats[lv][key])
        return xs, ys

    # 1) p95 latency
    plt.figure()
    x1, y1 = series(tor_levels, tor_stats, "p95_ms")
    x2, y2 = series(torbox_levels, torbox_stats, "p95_ms")
    plt.plot(x1, y1, marker="o", label="Tor")
    plt.plot(x2, y2, marker="o", label="TorBox")
    plt.axhline(slo_ms, linestyle="--", label=f"SLO p95 = {slo_factor:.2f} * timeout")
    plt.xlabel("Users (load_level)")
    plt.ylabel("p95 circuit build latency (ms)")
    plt.title("Tail latency vs load")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "p95_vs_load.png", dpi=180)

    # 2) near-timeout rate
    plt.figure()
    x1, y1 = series(tor_levels, tor_stats, "near_timeout_rate")
    x2, y2 = series(torbox_levels, torbox_stats, "near_timeout_rate")
    plt.plot(x1, y1, marker="o", label="Tor")
    plt.plot(x2, y2, marker="o", label="TorBox")
    plt.xlabel("Users (load_level)")
    plt.ylabel(f"Near-timeout rate (lat >= {near_factor:.2f} * timeout)")
    plt.title("Congestion proximity vs load")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "near_timeout_rate_vs_load.png", dpi=180)

    # 3) success rate
    plt.figure()
    x1, y1 = series(tor_levels, tor_stats, "success_rate")
    x2, y2 = series(torbox_levels, torbox_stats, "success_rate")
    plt.plot(x1, y1, marker="o", label="Tor")
    plt.plot(x2, y2, marker="o", label="TorBox")
    plt.xlabel("Users (load_level)")
    plt.ylabel("Success rate (measure)")
    plt.title("Success rate vs load")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_dir / "success_rate_vs_load.png", dpi=180)


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
            f"{fmt(s['p50_ms']):<6}  {fmt(s['p90_ms']):<6}  {fmt(s['p95_ms']):<6}  {fmt(s['p99_ms']):<6}  "
            f"{s['near_timeout_rate'] * 100:<6.2f} {s['timeout_rate'] * 100:<8.2f} {top_fail}"
        )


def run(
    *,
    tor_path: str,
    torbox_path: str,
    out_dir: str,
    timeout_s: float = 5.0,
    slo_factor: float = 0.8,
    near_factor: float = 0.9,
    near_rate_threshold: float = 0.05,
    recursive: bool = False,
) -> None:
    tor_rows = read_circuits_jsonl(Path(tor_path), recursive=recursive)
    torbox_rows = read_circuits_jsonl(Path(torbox_path), recursive=recursive)

    tor_attempts = extract_attempts(tor_rows)
    torbox_attempts = extract_attempts(torbox_rows)

    tor_levels, tor_stats, tor_knee_slo, tor_knee_near = summarize_by_level(
        tor_attempts,
        timeout_s=timeout_s,
        slo_factor=slo_factor,
        near_factor=near_factor,
        near_rate_threshold=near_rate_threshold,
    )
    torbox_levels, torbox_stats, torbox_knee_slo, torbox_knee_near = summarize_by_level(
        torbox_attempts,
        timeout_s=timeout_s,
        slo_factor=slo_factor,
        near_factor=near_factor,
        near_rate_threshold=near_rate_threshold,
    )

    print_table("Tor", tor_levels, tor_stats)
    print_table("TorBox", torbox_levels, torbox_stats)

    print("\n=== Knee points ===")
    print(f"Tor    knee_slo(p95>={slo_factor:.2f}*timeout): {tor_knee_slo}")
    print(f"Tor    knee_near(near>={near_rate_threshold*100:.1f}%): {tor_knee_near}")
    print(f"TorBox knee_slo(p95>={slo_factor:.2f}*timeout): {torbox_knee_slo}")
    print(f"TorBox knee_near(near>={near_rate_threshold*100:.1f}%): {torbox_knee_near}")

    plot_compare(
        Path(out_dir),
        tor_levels,
        tor_stats,
        torbox_levels,
        torbox_stats,
        timeout_s=timeout_s,
        slo_factor=slo_factor,
        near_factor=near_factor,
    )
    print(f"\nFigures saved to: {Path(out_dir).resolve()}")


def run_in_ide() -> None:
    """IDE入口: 直接改这里的路径，然后点运行即可。"""
    TOR_PATH = "exp/deployment/e1_scalability/logs/tor/circuits"      # file OR directory
    TORBOX_PATH = "exp/deployment/e1_scalability/logs/torbox/circuits"  # file OR directory
    OUT_DIR = "analysis_out"

    run(
        tor_path=TOR_PATH,
        torbox_path=TORBOX_PATH,
        out_dir=OUT_DIR,
        timeout_s=5.0,
        slo_factor=0.8,
        near_factor=0.9,
        near_rate_threshold=0.05,
        recursive=False,
    )


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
        slo_factor=args.slo_factor,
        near_factor=args.near_factor,
        near_rate_threshold=args.near_rate_threshold,
        recursive=args.recursive,
    )


if __name__ == "__main__":
    # IDE里直接运行：默认走 main()（兼容命令行）。
    # 如果你更喜欢固定配置运行：把下面一行改成 run_in_ide()
    main()
