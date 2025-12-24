from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple
import matplotlib
import matplotlib.pyplot as plt
import numpy as np

matplotlib.use("Agg")

CONTROL_SEQUENCE = ["CREATE2", "CREATED2", "EXTEND2", "EXTENDED2", "DESTROY"]
SENDME_NAMES = {"RELAY_SENDME", "SENDME"}
RELAY_DATA_NAMES = {"RELAY_DATA", "DATA"}
RELAY_END_NAMES = {"RELAY_END", "END"}


@dataclass
class LogEvent:
    timestamp: float
    cell_cmd: str
    direction: str
    circ_id: str
    stream_id: str

    @classmethod
    def from_raw(cls, raw: Dict[str, object]) -> "LogEvent":
        ts = None
        for key in ("timestamp", "ts", "time", "t"):
            if key in raw:
                value = raw[key]
                ts = float(value)
                break
        if ts is None:
            raise ValueError("Log line is missing a timestamp (timestamp/ts/time/t)")

        cell_cmd = str(raw.get("cell_cmd") or raw.get("cmd") or "").upper()
        direction = str(raw.get("dir") or raw.get("direction") or "?")
        circ_id = str(raw.get("circ_id") or raw.get("circuit") or "unknown")
        stream_id = str(raw.get("stream_id") or raw.get("stream") or "none")

        return cls(ts, cell_cmd, direction, circ_id, stream_id)


@dataclass
class ControlPlaneStats:
    total_circuits: int
    fully_ordered: int
    partial_ordered: int

    @property
    def full_ratio(self) -> float:
        return 0.0 if self.total_circuits == 0 else self.fully_ordered / self.total_circuits

    @property
    def partial_ratio(self) -> float:
        return 0.0 if self.total_circuits == 0 else self.partial_ordered / self.total_circuits


@dataclass
class RelayConsistency:
    matched: int
    missing: int
    wrong_order: int

    @property
    def match_ratio(self) -> float:
        total = self.matched + self.missing + self.wrong_order
        return 0.0 if total == 0 else self.matched / total


@dataclass
class SendmeStats:
    intervals: np.ndarray

    @property
    def mean(self) -> float:
        return float(np.mean(self.intervals)) if len(self.intervals) else float("nan")

    @property
    def median(self) -> float:
        return float(np.median(self.intervals)) if len(self.intervals) else float("nan")


@dataclass
class SemanticReport:
    control_plane: Dict[str, ControlPlaneStats]
    sendme: Dict[str, SendmeStats]
    relay: Dict[str, RelayConsistency]
    ks_stat: float


def load_log(path: Path) -> List[LogEvent]:
    events: List[LogEvent] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no} of {path}") from exc
            events.append(LogEvent.from_raw(raw))
    events.sort(key=lambda e: e.timestamp)
    return events

def _events_from_meta(meta_path: Path) -> Path:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    log_files = meta.get("log_files") or {}
    candidates = []
    for key in ("events", "event", "events_log", "event_log"):
        if key in log_files:
            candidates.append(log_files[key])
    if "events" in meta and not candidates:
        candidates.append(meta["events"])

    # Fallback: discover events.jsonl under the same directory
    if not candidates:
        events_dir = meta_path.parent / "events"
        jsonl_candidates = sorted(events_dir.glob("*.jsonl")) if events_dir.exists() else []
        if jsonl_candidates:
            return jsonl_candidates[-1]
        raise ValueError(f"No 'events' entry in {meta_path} and no events/*.jsonl found")

    p = Path(candidates[0])

    # 1) Absolute path: use directly
    if p.is_absolute():
        resolved = p
    else:
        # 2) If meta contains a project-root relative path like "exp\..."
        #    resolve it relative to the repository root (two levels up from this file),
        #    or use current working directory as fallback.
        parts = [x.lower() for x in p.parts]
        if parts and parts[0] in ("exp", "."):
            # Prefer repo root = script directory's parent (adjust if your structure differs)
            repo_root = Path(__file__).resolve().parents[2]
            candidate = repo_root / p
            if candidate.exists():
                resolved = candidate
            else:
                # fallback to CWD
                resolved = Path.cwd() / p
        else:
            # 3) Normal relative path: relative to run_meta.json directory
            resolved = meta_path.parent / p

    if not resolved.exists():
        raise FileNotFoundError(f"Events log missing: {resolved}")
    return resolved



def _events_from_directory(base: Path) -> Path:
    # Prefer run_meta.json if present
    meta_path = base / "run_meta.json"
    if meta_path.exists():
        return _events_from_meta(meta_path)

    events_dir = base / "events"
    candidates = sorted(events_dir.glob("*.jsonl")) if events_dir.exists() else []
    if not candidates:
        raise FileNotFoundError(f"No events log found under {base}")
    return candidates[-1]


def discover_runs(input_path: Path, rounds: int) -> List[Path]:
    """Return the events-log paths for one or many runs.

    Supported inputs:
    - events JSONL file path
    - run_meta.json path
    - directory containing run_meta.json or events/ subdir
    - directory containing round_XXX subdirectories when ``rounds > 1``
    - multi_run_manifest.json produced by ``semantic_runner``
    """

    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    # Explicit manifest
    if input_path.name == "multi_run_manifest.json":
        manifest = json.loads(input_path.read_text(encoding="utf-8"))
        paths = [Path(p) for p in manifest.get("meta_paths", [])]
        if not paths:
            raise ValueError(f"Manifest {input_path} contains no meta paths")
        return [_events_from_meta(p) for p in paths]

    # Raw JSONL
    if input_path.is_file() and input_path.suffix == ".jsonl":
        return [input_path]

    # run_meta.json
    if input_path.is_file() and input_path.name == "run_meta.json":
        return [_events_from_meta(input_path)]

    # Directory cases
    if input_path.is_dir():
        if rounds > 1:
            paths: List[Path] = []
            for idx in range(rounds):
                round_dir = input_path / f"round_{idx:03d}"
                paths.append(_events_from_directory(round_dir))
            return paths

        return [_events_from_directory(input_path)]

    raise ValueError(f"Unsupported input: {input_path}")


def control_plane_stats(events: Iterable[LogEvent]) -> ControlPlaneStats:
    per_circ: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.cell_cmd in CONTROL_SEQUENCE:
            per_circ[ev.circ_id].append(ev)

    fully_ordered = 0
    partial_ordered = 0
    for circ_events in per_circ.values():
        circ_events.sort(key=lambda e: e.timestamp)
        last_index = -1
        seen = set()
        ordered = True
        for ev in circ_events:
            idx = CONTROL_SEQUENCE.index(ev.cell_cmd)
            if idx < last_index:
                ordered = False
                break
            last_index = idx
            seen.add(ev.cell_cmd)
        if ordered and len(seen) == len(CONTROL_SEQUENCE):
            fully_ordered += 1
        elif ordered:
            partial_ordered += 1

    return ControlPlaneStats(total_circuits=len(per_circ), fully_ordered=fully_ordered, partial_ordered=partial_ordered)


def sendme_intervals(events: Iterable[LogEvent]) -> SendmeStats:
    by_stream: Dict[Tuple[str, str], List[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.cell_cmd in SENDME_NAMES:
            by_stream[(ev.circ_id, ev.stream_id)].append(ev)

    intervals: List[float] = []
    for stream_events in by_stream.values():
        stream_events.sort(key=lambda e: e.timestamp)
        for first, second in zip(stream_events, stream_events[1:]):
            intervals.append(second.timestamp - first.timestamp)

    return SendmeStats(np.array(intervals, dtype=float))


def ks_2samp(sample1: np.ndarray, sample2: np.ndarray) -> float:
    if len(sample1) == 0 or len(sample2) == 0:
        return float("nan")

    data1 = np.sort(sample1)
    data2 = np.sort(sample2)

    cdf1 = np.arange(1, len(data1) + 1) / len(data1)
    cdf2 = np.arange(1, len(data2) + 1) / len(data2)

    combined = np.sort(np.unique(np.concatenate([data1, data2])))
    cdf1_interp = np.searchsorted(data1, combined, side="right") / len(data1)
    cdf2_interp = np.searchsorted(data2, combined, side="right") / len(data2)

    return float(np.max(np.abs(cdf1_interp - cdf2_interp)))


def relay_consistency(tor_events: Iterable[LogEvent], torbox_events: Iterable[LogEvent]) -> Dict[str, RelayConsistency]:
    def summarize(events: Iterable[LogEvent]) -> Dict[Tuple[str, str], Tuple[bool, bool, bool]]:
        per_stream: Dict[Tuple[str, str], List[LogEvent]] = defaultdict(list)
        for ev in events:
            if ev.cell_cmd in RELAY_DATA_NAMES or ev.cell_cmd in RELAY_END_NAMES:
                per_stream[(ev.circ_id, ev.stream_id)].append(ev)

        summary: Dict[Tuple[str, str], Tuple[bool, bool, bool]] = {}
        for key, stream_events in per_stream.items():
            stream_events.sort(key=lambda e: e.timestamp)
            has_data = any(ev.cell_cmd in RELAY_DATA_NAMES for ev in stream_events)
            has_end = any(ev.cell_cmd in RELAY_END_NAMES for ev in stream_events)
            first_data = next((ev.timestamp for ev in stream_events if ev.cell_cmd in RELAY_DATA_NAMES), None)
            first_end = next((ev.timestamp for ev in stream_events if ev.cell_cmd in RELAY_END_NAMES), None)
            order_ok = False
            if first_data is not None and first_end is not None:
                order_ok = first_data <= first_end
            summary[key] = (has_data, has_end, order_ok)
        return summary

    tor_summary = summarize(tor_events)
    torbox_summary = summarize(torbox_events)
    all_keys = set(tor_summary) | set(torbox_summary)

    matched = 0
    missing = 0
    wrong_order = 0

    for key in all_keys:
        tor_info = tor_summary.get(key)
        tb_info = torbox_summary.get(key)
        if tor_info == tb_info:
            matched += 1
        else:
            missing_case = tor_info is None or tb_info is None
            if missing_case:
                missing += 1
            else:
                if tor_info[2] != tb_info[2]:
                    wrong_order += 1
                else:
                    missing += 1

    return {
        "Tor": RelayConsistency(matched=matched, missing=missing, wrong_order=wrong_order),
        "TorBox": RelayConsistency(matched=matched, missing=missing, wrong_order=wrong_order),
    }


def build_report(tor_events: List[LogEvent], torbox_events: List[LogEvent]) -> SemanticReport:
    control = {
        "Tor": control_plane_stats(tor_events),
        "TorBox": control_plane_stats(torbox_events),
    }
    sendme = {
        "Tor": sendme_intervals(tor_events),
        "TorBox": sendme_intervals(torbox_events),
    }
    ks_stat = ks_2samp(sendme["Tor"].intervals, sendme["TorBox"].intervals)
    relay = relay_consistency(tor_events, torbox_events)
    return SemanticReport(control_plane=control, sendme=sendme, relay=relay, ks_stat=ks_stat)


def plot_report(report: SemanticReport, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    ax_control = axes[0, 0]
    ax_sendme_hist = axes[0, 1]
    ax_sendme_cdf = axes[1, 1]
    ax_relay = axes[1, 0]

    # Control plane
    systems = ["Tor", "TorBox"]
    full = [report.control_plane[s].full_ratio * 100 for s in systems]
    partial = [report.control_plane[s].partial_ratio * 100 for s in systems]

    x = np.arange(len(systems))
    width = 0.35
    ax_control.bar(x - width / 2, full, width, label="完整序列", color="#1E40AF")
    ax_control.bar(x + width / 2, partial, width, label="部分有序", color="#60A5FA")

    ax_control.set_xticks(x)
    ax_control.set_xticklabels(systems)
    ax_control.set_ylabel("电路序列一致率 (%)")
    ax_control.set_title("控制面序列 (CREATE2 → CREATED2 → EXTEND2 → EXTENDED2 → DESTROY)")
    ax_control.legend()
    ax_control.grid(alpha=0.2, axis="y")

    # SENDME histogram
    bins = 20
    for label, color in [("Tor", "#1E3A8A"), ("TorBox", "#EA580C")]:
        data = report.sendme[label].intervals
        if len(data):
            ax_sendme_hist.hist(data, bins=bins, alpha=0.55, label=label, color=color)
    ax_sendme_hist.set_title("SENDME 间隔分布")
    ax_sendme_hist.set_xlabel("间隔 (时间单位)")
    ax_sendme_hist.set_ylabel("计数")
    ax_sendme_hist.grid(alpha=0.25)
    ax_sendme_hist.legend()

    # SENDME CDF + KS
    for label, color in [("Tor", "#1E3A8A"), ("TorBox", "#EA580C")]:
        data = np.sort(report.sendme[label].intervals)
        if len(data):
            y = np.arange(1, len(data) + 1) / len(data)
            ax_sendme_cdf.step(data, y, where="post", label=f"{label} (n={len(data)})", color=color)
    if not np.isnan(report.ks_stat):
        ax_sendme_cdf.text(
            0.02,
            0.95,
            f"KS 距离 = {report.ks_stat:.3f}",
            transform=ax_sendme_cdf.transAxes,
            ha="left",
            va="top",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", alpha=0.9),
        )
    ax_sendme_cdf.set_title("SENDME 间隔 CDF")
    ax_sendme_cdf.set_xlabel("间隔 (时间单位)")
    ax_sendme_cdf.set_ylabel("CDF")
    ax_sendme_cdf.set_ylim(0, 1.05)
    ax_sendme_cdf.grid(alpha=0.25)
    ax_sendme_cdf.legend()

    # Relay consistency
    relay_values = report.relay["Tor"]
    labels = ["匹配", "缺失", "顺序不一致"]
    values = [relay_values.matched, relay_values.missing, relay_values.wrong_order]
    colors = ["#16A34A", "#E5E7EB", "#EF4444"]
    ax_relay.bar(labels, values, color=colors)
    ax_relay.set_title("RELAY_DATA / RELAY_END 可观测一致性")
    ax_relay.set_ylabel("流数量")
    for x_pos, val in zip(labels, values):
        ax_relay.text(x_pos, val, str(val), ha="center", va="bottom", fontweight="bold")
    ax_relay.grid(alpha=0.2, axis="y")

    fig.tight_layout()
    fig.savefig(output_dir / "semantic_overview.png", dpi=300)
    fig.savefig(output_dir / "semantic_overview.pdf")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """
    - 命令行运行：python script.py <tor_input> <torbox_input> --output-dir ... --rounds ...
    - IDE 运行：不传参数时自动使用 DEFAULT_* 变量
    """
    # ===== IDE default config (edit here) =====
    DEFAULT_TOR_INPUT = Path("exp/semantic_logs/tor")
    DEFAULT_TORBOX_INPUT = Path("exp/semantic_logs/torbox")
    DEFAULT_OUTPUT_DIR = Path("exp/semantic_logs/semantic_outputs")
    DEFAULT_ROUNDS = 5
    # ========================================

    parser = argparse.ArgumentParser(
        description=(
            "Tor/TorBox 语义一致性日志分析。"
            "支持单次或多轮次输入 (events.jsonl / run_meta.json / round_XXX 目录 / multi_run_manifest.json)。"
        )
    )
    parser.add_argument(
        "tor_input",
        type=Path,
        nargs="?",
        default=DEFAULT_TOR_INPUT,
        help="Tor 侧输入：JSONL、run_meta.json、目录或 manifest",
    )
    parser.add_argument(
        "torbox_input",
        type=Path,
        nargs="?",
        default=DEFAULT_TORBOX_INPUT,
        help="TorBox 侧输入：JSONL、run_meta.json、目录或 manifest",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="指标与图表输出目录",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=DEFAULT_ROUNDS,
        help="轮次数量。>1 时会读取 round_XXX 子目录或 manifest",
    )

    return parser.parse_args(argv)




def _write_summary(report: SemanticReport, output_dir: Path, title: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "metrics.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"# {title}\n")
        for label in ("Tor", "TorBox"):
            c = report.control_plane[label]
            s = report.sendme[label]
            f.write(
                f"[{label}] 控制面: 完整 {c.fully_ordered}/{c.total_circuits}, 部分 {c.partial_ordered}\n"
            )
            f.write(f"[{label}] SENDME: n={len(s.intervals)}, mean={s.mean:.3f}, median={s.median:.3f}\n")
        relay = report.relay["Tor"]
        f.write(
            f"[Relay] 匹配={relay.matched}, 缺失={relay.missing}, 顺序不一致={relay.wrong_order}\n"
        )
        if not np.isnan(report.ks_stat):
            f.write(f"[SENDME] KS 距离={report.ks_stat:.4f}\n")
    plot_report(report, output_dir)

def main(argv: Sequence[str] | None = None) -> None:
    args = parse_args(argv)

    tor_inputs = discover_runs(args.tor_input, args.rounds)
    torbox_inputs = discover_runs(args.torbox_input, args.rounds)

    if len(tor_inputs) != len(torbox_inputs):
        raise SystemExit(f"Mismatched run counts: Tor={len(tor_inputs)} TorBox={len(torbox_inputs)}")

    all_tor_events: List[LogEvent] = []
    all_torbox_events: List[LogEvent] = []

    for idx, (tor_path, tb_path) in enumerate(zip(tor_inputs, torbox_inputs)):
        tor_events = load_log(tor_path)
        torbox_events = load_log(tb_path)

        round_report = build_report(tor_events, torbox_events)
        round_dir = args.output_dir / f"round_{idx:03d}"
        _write_summary(round_report, round_dir, title=f"Round {idx:03d}")

        all_tor_events.extend(tor_events)
        all_torbox_events.extend(torbox_events)

    aggregate_report = build_report(all_tor_events, all_torbox_events)
    _write_summary(aggregate_report, args.output_dir, title="Aggregated")


if __name__ == "__main__":
    main()