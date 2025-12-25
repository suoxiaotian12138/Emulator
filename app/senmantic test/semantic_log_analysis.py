from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import font_manager

matplotlib.use("Agg")

SENDME_NAMES = {"RELAY_SENDME", "SENDME"}
RELAY_DATA_NAMES = {"RELAY_DATA", "DATA"}
RELAY_END_NAMES = {"RELAY_END", "END"}

TOR_INPUT = Path("exp/semantic_logs/tor")
TORBOX_INPUT = Path("exp/semantic_logs/torbox")
OUTPUT_DIR = Path("exp/semantic_logs/semantic_outputs")
ROUNDS = 5

STAGE_KEYS = [
    "CREATE2",
    "CREATED2",
    "EXTEND2",
    "EXTENDED2",
    "RELAY_CONNECTED",
    "RELAY_DATA",
    "SENDME",
    "DESTROY",
]

STAGE_ALIASES = {
    # 建路
    "CREATE": "CREATE2",
    "CREATE2": "CREATE2",
    "RELAY_CREATE": "CREATE2",
    "RELAY_CREATE2": "CREATE2",
    "CREATED": "CREATED2",
    "CREATED2": "CREATED2",
    "RELAY_CREATED": "CREATED2",
    "RELAY_CREATED2": "CREATED2",
    # 扩展
    "EXTEND": "EXTEND2",
    "EXTEND2": "EXTEND2",
    "RELAY_EXTEND": "EXTEND2",
    "RELAY_EXTEND2": "EXTEND2",
    "EXTENDED": "EXTENDED2",
    "EXTENDED2": "EXTENDED2",
    "RELAY_EXTENDED": "EXTENDED2",
    "RELAY_EXTENDED2": "EXTENDED2",
    # 连接/数据
    "RELAY_CONNECTED": "RELAY_CONNECTED",
    "CONNECTED": "RELAY_CONNECTED",
    "RELAY_DATA": "RELAY_DATA",
    "DATA": "RELAY_DATA",
    "SENDME": "SENDME",
    "RELAY_SENDME": "SENDME",
    "DESTROY": "DESTROY",
    # 可选的常见变体, 你日志里如果出现就能识别
    "RELAY_DESTROY": "DESTROY",
    "CELL_DESTROY": "DESTROY",
}

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
        timestamp_keys = (
            ("timestamp", 1.0),
            ("ts", 1.0),
            ("time", 1.0),
            ("t", 1.0),
            ("ts_ms", 1e-3),
            ("ts_ns", 1e-9),
            ("ts_mono_ns", 1e-9),
        )
        for key, scale in timestamp_keys:
            if key in raw:
                ts = float(raw[key]) * scale
                break
        if ts is None:
            raise ValueError(
                "Log line is missing a timestamp (timestamp/ts/time/t/ts_ms/ts_ns/ts_mono_ns)"
            )

        meta = raw.get("meta") or {}
        cell_cmd = str(
            raw.get("cell_cmd")
            or meta.get("cell_cmd")
            or raw.get("cmd")
            or meta.get("cmd")
            or raw.get("event")
            or meta.get("event")
            or ""
        ).upper()
        direction = str(
            raw.get("dir")
            or raw.get("direction")
            or meta.get("dir")
            or meta.get("direction")
            or "?"
        )
        circ_id = str(
            raw.get("circ_id")
            or raw.get("circuit")
            or meta.get("circ_id")
            or meta.get("circuit")
            or "unknown"
        )
        stream_id = str(
            raw.get("stream_id")
            or raw.get("stream")
            or meta.get("stream_id")
            or meta.get("stream")
            or "none"
        )
        return cls(ts, cell_cmd, direction, circ_id, stream_id)

@dataclass
class ControlPlaneStats:
    counts: Dict[str, int]
    first_ts: Dict[str, float]
    last_ts: Dict[str, float]
    occurrences: Dict[str, List[float]]

    def start_time(self, name: str) -> float | None:
        return self.first_ts.get(name)

    def end_time(self, name: str) -> float | None:
        return self.last_ts.get(name)

    def all_times(self, name: str) -> List[float]:
        return self.occurrences.get(name, [])

@dataclass
class SendmeStats:
    intervals: np.ndarray
    count: int
    first_ts: float | None
    timestamps: List[float]

    @property
    def mean(self) -> float:
        return float(np.mean(self.intervals)) if len(self.intervals) else float("nan")

    @property
    def median(self) -> float:
        return float(np.median(self.intervals)) if len(self.intervals) else float("nan")

@dataclass
class RoundSummary:
    stages: Dict[str, ControlPlaneStats]
    sendme: Dict[str, SendmeStats]
    destroy_ts: Dict[str, float | None]
    base_ts: Dict[str, float | None]

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

    if not candidates:
        events_dir = meta_path.parent / "events"
        jsonl_candidates = sorted(events_dir.glob("*.jsonl")) if events_dir.exists() else []
        if jsonl_candidates:
            return jsonl_candidates[-1]
        raise ValueError(f"No 'events' entry in {meta_path} and no events/*.jsonl found")

    p = Path(candidates[0])
    if p.is_absolute():
        resolved = p
    else:
        parts = [x.lower() for x in p.parts]
        if parts and parts[0] in ("exp", "."):
            repo_root = Path(__file__).resolve().parents[2]
            candidate = repo_root / p
            resolved = candidate if candidate.exists() else Path.cwd() / p
        else:
            resolved = meta_path.parent / p

    if not resolved.exists():
        raise FileNotFoundError(f"Events log missing: {resolved}")
    return resolved

def _events_from_directory(base: Path) -> Path:
    meta_path = base / "run_meta.json"
    if meta_path.exists():
        return _events_from_meta(meta_path)

    events_dir = base / "events"
    candidates = sorted(events_dir.glob("*.jsonl")) if events_dir.exists() else []
    if not candidates:
        raise FileNotFoundError(f"No events log found under {base}")
    return candidates[-1]

def discover_runs(input_path: Path, rounds: int) -> List[Path]:
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    if input_path.name == "multi_run_manifest.json":
        manifest = json.loads(input_path.read_text(encoding="utf-8"))
        paths = [Path(p) for p in manifest.get("meta_paths", [])]
        if not paths:
            raise ValueError(f"Manifest {input_path} contains no meta paths")
        return [_events_from_meta(p) for p in paths]

    if input_path.is_file() and input_path.suffix == ".jsonl":
        return [input_path]

    if input_path.is_file() and input_path.name == "run_meta.json":
        return [_events_from_meta(input_path)]

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
    counts: Dict[str, int] = defaultdict(int)
    first_ts: Dict[str, float] = {}
    last_ts: Dict[str, float] = {}
    occurrences: Dict[str, List[float]] = defaultdict(list)

    def _canonical(name: str) -> str | None:
        return STAGE_ALIASES.get(name)

    for ev in events:
        raw_name = ev.cell_cmd or ""
        name = _canonical(raw_name)
        if not name:
            continue
        counts[name] += 1
        occurrences[name].append(ev.timestamp)
        if name not in first_ts:
            first_ts[name] = ev.timestamp
        last_ts[name] = ev.timestamp

    return ControlPlaneStats(
        counts=dict(counts),
        first_ts=first_ts,
        last_ts=last_ts,
        occurrences={k: sorted(v) for k, v in occurrences.items()},
    )

def sendme_intervals(events: Iterable[LogEvent]) -> SendmeStats:
    by_stream: Dict[Tuple[str, str], List[LogEvent]] = defaultdict(list)
    for ev in events:
        if ev.cell_cmd in SENDME_NAMES:
            by_stream[(ev.circ_id, ev.stream_id)].append(ev)

    intervals: List[float] = []
    first_ts: float | None = None
    total = 0
    all_timestamps: List[float] = []

    for stream_events in by_stream.values():
        stream_events.sort(key=lambda e: e.timestamp)
        if stream_events:
            total += len(stream_events)
            if first_ts is None:
                first_ts = stream_events[0].timestamp
            else:
                first_ts = min(first_ts, stream_events[0].timestamp)
            all_timestamps.extend(ev.timestamp for ev in stream_events)

        for first, second in zip(stream_events, stream_events[1:]):
            intervals.append(second.timestamp - first.timestamp)

    return SendmeStats(
        np.array(intervals, dtype=float),
        count=total,
        first_ts=first_ts,
        timestamps=sorted(all_timestamps),
    )

def infer_destroy(events: List[LogEvent]) -> float | None:
    """
    Final end time rule:
    1) If any explicit DESTROY exists (after alias canonicalization), use the latest DESTROY.
    2) Otherwise use the latest timestamp among all events.
       This guarantees DESTROY_TS is always >= end of SENDME/RELAY_DATA/etc.
    """
    if not events:
        return None

    def _canonical(cmd: str) -> str | None:
        return STAGE_ALIASES.get(cmd)

    destroy_like = [ev.timestamp for ev in events if _canonical(ev.cell_cmd) == "DESTROY"]
    if destroy_like:
        return max(destroy_like)

    return max(ev.timestamp for ev in events)

def build_report(tor_events: List[LogEvent], torbox_events: List[LogEvent]) -> RoundSummary:
    stages = {
        "Tor": control_plane_stats(tor_events),
        "TorBox": control_plane_stats(torbox_events),
    }
    sendme = {
        "Tor": sendme_intervals(tor_events),
        "TorBox": sendme_intervals(torbox_events),
    }
    destroy_ts = {
        "Tor": infer_destroy(tor_events),
        "TorBox": infer_destroy(torbox_events),
    }
    base_ts = {
        "Tor": min((ev.timestamp for ev in tor_events), default=None),
        "TorBox": min((ev.timestamp for ev in torbox_events), default=None),
    }
    return RoundSummary(stages=stages, sendme=sendme, destroy_ts=destroy_ts, base_ts=base_ts)

def _fmt_ts(ts: float | None) -> str:
    return "-" if ts is None else f"{ts:.6f}"

def _write_stage_summary(report: RoundSummary, output_dir: Path, title: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "state_metrics.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"# {title} (建路阶段与事件出现)\n")
        stage_payload = {}
        for label in ("Tor", "TorBox"):
            stats = report.stages[label]
            stage_payload[label] = {}
            f.write(f"[{label}] 阶段事件统计\n")

            for key in STAGE_KEYS:
                cnt = stats.counts.get(key, 0)
                start_val = stats.start_time(key)
                end_val = stats.end_time(key)
                times_list = stats.all_times(key)

                if key in {"SENDME", "RELAY_DATA"}:
                    if times_list:
                        trimmed = [times_list[0]]
                        if len(times_list) > 1:
                            trimmed.append(times_list[-1])
                        times_list = trimmed
                        end_val = times_list[-1]

                # Critical: force DESTROY end to be the inferred final end time
                if key == "DESTROY":
                    end_val = report.destroy_ts.get(label)

                start = _fmt_ts(start_val)
                end = _fmt_ts(end_val)
                times = ", ".join(f"{ts:.6f}" for ts in times_list) or "-"
                f.write(f"  {key}: 次数={cnt}, 起始={start}, 结束={end}, 出现={times}\n")

                stage_payload[label][key] = {
                    "count": cnt,
                    "start": times_list[0] if times_list else None,
                    "end": end_val,
                    "times": times_list,
                }

            destroy_val = _fmt_ts(report.destroy_ts.get(label))
            f.write(f"  推测 DESTROY 时间={destroy_val}\n")
            stage_payload[label]["DESTROY_TS"] = report.destroy_ts.get(label)

        f.write(f"# RAW_STAGE_JSON {json.dumps(stage_payload, ensure_ascii=False)}\n")

def _write_sendme_summary(report: RoundSummary, output_dir: Path, title: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "sendme_metrics.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"# {title} (SENDME 触发)\n")
        payload = {}
        for label in ("Tor", "TorBox"):
            s = report.sendme[label]
            f.write(
                f"[{label}] SENDME: 触发次数={s.count}, 首次时间={_fmt_ts(s.first_ts)}, 间隔样本={len(s.intervals)}, 平均={s.mean:.3f}, 中位数={s.median:.3f}\n"
            )
            if s.first_ts is None:
                delta_str = "-"
            else:
                deltas = [t - s.first_ts for t in s.timestamps]
                delta_str = ", ".join(f"{v:.6f}" for v in deltas) or "-"
            f.write(f"  触发时间差序列(相对首次SENDME)={delta_str}\n")

            payload[label] = {
                "count": s.count,
                "first_ts": s.first_ts,
                "intervals": s.intervals.tolist(),
                "timestamps": s.timestamps,
                "mean": s.mean,
                "median": s.median,
            }
        f.write(f"# RAW_SENDME_JSON {json.dumps(payload, ensure_ascii=False)}\n")

def main(
    *,
    tor_input: Path = TOR_INPUT,
    torbox_input: Path = TORBOX_INPUT,
    output_dir: Path = OUTPUT_DIR,
    rounds: int = ROUNDS,
) -> None:
    tor_inputs = discover_runs(tor_input, rounds)
    torbox_inputs = discover_runs(torbox_input, rounds)

    if len(tor_inputs) != len(torbox_inputs):
        raise SystemExit(f"Mismatched run counts: Tor={len(tor_inputs)} TorBox={len(torbox_inputs)}")

    round_reports: List[RoundSummary] = []
    for idx, (tor_path, tb_path) in enumerate(zip(tor_inputs, torbox_inputs)):
        tor_events = load_log(tor_path)
        torbox_events = load_log(tb_path)

        round_report = build_report(tor_events, torbox_events)
        round_dir = output_dir / f"round_{idx:03d}"
        _write_stage_summary(round_report, round_dir, title=f"Round {idx:03d}")
        _write_sendme_summary(round_report, round_dir, title=f"Round {idx:03d}")
        round_reports.append(round_report)

    if round_reports:
        def _nanmean(values: List[float]) -> float:
            arr = [v for v in values if not np.isnan(v)]
            return float(np.mean(arr)) if arr else float("nan")

        def _clean(value: float | None) -> float | None:
            if value is None or np.isnan(value):
                return None
            return float(value)

        def _offset(value: float | None, base: float | None) -> float:
            if value is None or base is None:
                return float("nan")
            return float(value) - float(base)

        def _mean_per_occurrence(series_per_round: List[List[float]]) -> List[float]:
            max_len = max((len(x) for x in series_per_round), default=0)
            out: List[float] = []
            for i in range(max_len):
                vals = []
                for seq in series_per_round:
                    if i < len(seq):
                        v = seq[i]
                        if not np.isnan(v):
                            vals.append(v)
                out.append(float(np.mean(vals)) if vals else float("nan"))
            return out

        def _occurrence_offsets(r: RoundSummary, label: str, key: str) -> List[float]:
            base = r.base_ts.get(label)
            times = r.stages[label].all_times(key)
            return [_offset(t, base) for t in times if (t is not None and base is not None)]

        avg_state_path = output_dir / "avg_state_metrics.txt"
        with avg_state_path.open("w", encoding="utf-8") as f:
            f.write("# 多轮平均 - 事件出现与推测 DESTROY\n")
            aggregated_payload = {}

            for label in ("Tor", "TorBox"):
                f.write(f"[{label}]\n")
                aggregated_payload[label] = {}

                # Precompute destroy_mean per label, used to override DESTROY end
                destroy_mean = _nanmean([
                    _offset(r.destroy_ts.get(label), r.base_ts.get(label)) for r in round_reports
                ])

                for key in STAGE_KEYS:
                    mean_count = _nanmean([float(r.stages[label].counts.get(key, 0)) for r in round_reports])

                    start_mean = _nanmean([
                        _offset(r.stages[label].start_time(key), r.base_ts.get(label))
                        for r in round_reports
                    ])

                    end_mean = _nanmean([
                        _offset(r.stages[label].end_time(key), r.base_ts.get(label))
                        for r in round_reports
                    ])

                    # Critical: force DESTROY end to inferred global end (destroy_mean)
                    if key == "DESTROY":
                        end_mean = destroy_mean

                    f.write(
                        f"  {key}: 平均次数={mean_count:.2f}, 平均起始={_fmt_ts(start_mean)}, 平均结束={_fmt_ts(end_mean)}\n"
                    )

                    per_round = [_occurrence_offsets(r, label, key) for r in round_reports]
                    mean_seq = [_clean(v) for v in _mean_per_occurrence(per_round)]

                    if key in {"EXTEND2", "EXTENDED2"}:
                        seq_str = ", ".join(_fmt_ts(v) for v in mean_seq if v is not None) if mean_seq else "-"
                        f.write(f"    {key}: 平均出现序列(按第k次)={seq_str}\n")

                    trimmed_seq = mean_seq
                    if key in {"SENDME", "RELAY_DATA"} and mean_seq:
                        trimmed_seq = [mean_seq[0]]
                        if len(mean_seq) > 1 and mean_seq[-1] is not None:
                            trimmed_seq.append(mean_seq[-1])

                    aggregated_payload[label][key] = {
                        "count": mean_count,
                        "start": _clean(trimmed_seq[0]) if trimmed_seq else _clean(start_mean),
                        "end": _clean(end_mean),
                        "times": [v for v in trimmed_seq if v is not None],
                    }

                f.write(f"  平均推测 DESTROY={_fmt_ts(destroy_mean)}\n")
                aggregated_payload[label]["DESTROY_TS"] = _clean(destroy_mean)

            f.write(f"# RAW_STAGE_JSON {json.dumps(aggregated_payload, ensure_ascii=False)}\n")

        avg_sendme_path = output_dir / "avg_sendme_metrics.txt"
        with avg_sendme_path.open("w", encoding="utf-8") as f:
            f.write("# 多轮平均 - SENDME 触发\n")

            aggregated_payload: dict[str, dict[str, object]] = {}
            for label in ("Tor", "TorBox"):
                mean_count = _nanmean([float(r.sendme[label].count) for r in round_reports])
                mean_first = _nanmean([
                    _offset(r.sendme[label].first_ts, r.base_ts.get(label)) for r in round_reports
                ])
                mean_interval_count = _nanmean([float(len(r.sendme[label].intervals)) for r in round_reports])
                mean_val = _nanmean([r.sendme[label].mean for r in round_reports])
                median_val = _nanmean([r.sendme[label].median for r in round_reports])

                f.write(
                    f"[{label}] 平均触发次数={mean_count:.2f}, 平均首次时间={_fmt_ts(mean_first)}, 平均间隔样本={mean_interval_count:.2f}, 平均mean={mean_val:.3f}, 平均median={median_val:.3f}\n"
                )

                per_round_intervals = [r.sendme[label].intervals.tolist() for r in round_reports]
                mean_interval_seq = _mean_per_occurrence(per_round_intervals)
                seq_str = ", ".join(_fmt_ts(v) for v in mean_interval_seq) if mean_interval_seq else "-"
                f.write(f"  平均间隔序列(按第k个间隔)={seq_str}\n")

                per_round_timestamps = [
                    [t - (r.base_ts.get(label) or 0.0) for t in r.sendme[label].timestamps]
                    for r in round_reports
                ]
                mean_timestamp_seq = _mean_per_occurrence(per_round_timestamps)

                aggregated_payload[label] = {
                    "count": _clean(mean_count),
                    "first_ts": _clean(mean_first),
                    "intervals": [_clean(v) for v in mean_interval_seq if not np.isnan(v)],
                    "timestamps": [_clean(v) for v in mean_timestamp_seq if not np.isnan(v)],
                    "mean": _clean(mean_val),
                    "median": _clean(median_val),
                }

            f.write(f"# RAW_SENDME_JSON {json.dumps(aggregated_payload, ensure_ascii=False)}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="统计 Tor/TorBox 语义日志，用于 state.py 与 send_me.py")
    parser.add_argument("--tor", type=Path, default=TOR_INPUT)
    parser.add_argument("--torbox", type=Path, default=TORBOX_INPUT)
    parser.add_argument("--out", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--rounds", type=int, default=ROUNDS, help="当输入目录包含 round_xxx 子目录时使用")
    args = parser.parse_args()

    main(tor_input=args.tor, torbox_input=args.torbox, output_dir=args.out, rounds=args.rounds)
