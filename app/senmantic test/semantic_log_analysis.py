from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np

# ===================== Constants =====================
PKG_WINDOW_INIT = 1000
PKG_WINDOW_SENDME_INC = 100
PKG_WINDOW_DATA_DEC = 1

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
    "CREATE": "CREATE2",
    "CREATE2": "CREATE2",
    "RELAY_CREATE": "CREATE2",
    "RELAY_CREATE2": "CREATE2",
    "CREATED": "CREATED2",
    "CREATED2": "CREATED2",
    "RELAY_CREATED": "CREATED2",
    "RELAY_CREATED2": "CREATED2",
    "EXTEND": "EXTEND2",
    "EXTEND2": "EXTEND2",
    "RELAY_EXTEND": "EXTEND2",
    "RELAY_EXTEND2": "EXTEND2",
    "EXTENDED": "EXTENDED2",
    "EXTENDED2": "EXTENDED2",
    "RELAY_EXTENDED": "EXTENDED2",
    "RELAY_EXTENDED2": "EXTENDED2",
    "RELAY_CONNECTED": "RELAY_CONNECTED",
    "CONNECTED": "RELAY_CONNECTED",
    "RELAY_DATA": "RELAY_DATA",
    "DATA": "RELAY_DATA",
    "SENDME": "SENDME",
    "RELAY_SENDME": "SENDME",
    "DESTROY": "DESTROY",
    "RELAY_DESTROY": "DESTROY",
    "CELL_DESTROY": "DESTROY",
}


def _pick(*vals, default=None):
    """Pick first non-None value."""
    for v in vals:
        if v is not None:
            return v
    return default


@dataclass
class LogEvent:
    """Canonicalized log event with unified field names."""
    timestamp: float
    cell_cmd: str
    direction: str
    circ_id: str
    stream_id: str

    @classmethod
    def from_raw(cls, raw: Dict[str, object]) -> "LogEvent":
        # 1) Timestamp normalization (support multiple formats)
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
                "Log line missing timestamp (timestamp/ts/time/t/ts_ms/ts_ns/ts_mono_ns)"
            )

        # 2) Extract meta if present
        meta = raw.get("meta") or {}

        # 3) cell_cmd normalization (uppercase)
        cell_cmd = str(
            raw.get("cell_cmd")
            or meta.get("cell_cmd")
            or raw.get("cmd")
            or meta.get("cmd")
            or raw.get("event")
            or meta.get("event")
            or ""
        ).upper()

        # 4) direction normalization
        direction = str(
            raw.get("dir")
            or raw.get("direction")
            or meta.get("dir")
            or meta.get("direction")
            or "?"
        ).lower()

        # 5) circ_id extraction
        circ_id_val = _pick(
            raw.get("circ_id"),
            raw.get("circuit"),
            meta.get("circ_id"),
            meta.get("circuit"),
            default="unknown",
        )
        circ_id = str(circ_id_val)

        # 6) stream_id extraction with explicit circuit-level default
        # CRITICAL: for circuit-level events, stream_id should be "0"
        stream_id_val = _pick(
            raw.get("stream_id"),
            raw.get("stream"),
            meta.get("stream_id"),
            meta.get("stream"),
            default=0,
        )
        stream_id = str(stream_id_val)

        return cls(ts, cell_cmd, direction, circ_id, stream_id)


@dataclass
class ControlPlaneStats:
    """Statistics for control plane events (CREATE, EXTEND, etc.)."""
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
    """SENDME statistics and circuit window trace."""
    intervals: np.ndarray  # circuit SENDME intervals
    stream_intervals: np.ndarray  # stream SENDME intervals
    count: int  # circuit SENDME count
    first_ts: float | None
    timestamps: List[float]  # circuit SENDME timestamps
    window_trace_ms: Dict[str, List[float]]  # reconstructed window
    base_ts: float | None
    circ_id: str | None
    relay_data_count: int  # for validation

    @property
    def mean(self) -> float:
        return float(np.mean(self.intervals)) if len(self.intervals) else float("nan")

    @property
    def median(self) -> float:
        return float(np.median(self.intervals)) if len(self.intervals) else float("nan")


@dataclass
class RoundSummary:
    """Summary for one round of experiments."""
    stages: Dict[str, ControlPlaneStats]
    sendme: Dict[str, SendmeStats]
    destroy_ts: Dict[str, float | None]
    base_ts: Dict[str, float | None]


# ===================== Log Loading =====================
def load_log(path: Path) -> List[LogEvent]:
    """Load and parse JSONL log file."""
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
    """Extract events log path from run_meta.json."""
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
    """Find events log in a directory."""
    meta_path = base / "run_meta.json"
    if meta_path.exists():
        return _events_from_meta(meta_path)

    events_dir = base / "events"
    candidates = sorted(events_dir.glob("*.jsonl")) if events_dir.exists() else []
    if not candidates:
        raise FileNotFoundError(f"No events log found under {base}")
    return candidates[-1]


def discover_runs(input_path: Path, rounds: int) -> List[Path]:
    """Discover all run log files."""
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


# ===================== Analysis Functions =====================
def control_plane_stats(events: Iterable[LogEvent]) -> ControlPlaneStats:
    """Compute control plane statistics."""
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


def _select_circuit(events: List[LogEvent]) -> tuple[str | None, List[LogEvent]]:
    """
    Select the most representative circuit for analysis.

    Priority:
    1. Most circuit-level SENDMEs (stream_id == 0, dir == recv)
    2. Most RELAY_DATA sends
    3. Earliest start time
    """
    if not events:
        return None, []

    by_circ: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in events:
        by_circ[str(ev.circ_id)].append(ev)

    def _score(items: List[LogEvent]) -> tuple[int, int, float]:
        # Count circuit-level SENDMEs (stream_id == 0)
        sendme_cnt = sum(
            1
            for ev in items
            if ev.cell_cmd in SENDME_NAMES
            and ev.direction == "recv"
            and str(ev.stream_id) == "0"
        )
        # Count DATA sends
        data_cnt = sum(
            1
            for ev in items
            if ev.cell_cmd in RELAY_DATA_NAMES
            and ev.direction == "send"
        )
        first_ts = min(ev.timestamp for ev in items)
        return (sendme_cnt, data_cnt, -first_ts)

    circ_id, circ_events = max(by_circ.items(), key=lambda kv: _score(kv[1]))
    return circ_id, circ_events


def compute_circuit_pkg_window_trace_ms(
        events: List[LogEvent],
        *,
        base_ts: float | None,
        init_window: int,
        sendme_inc: int,
        data_dec: int = 1,
) -> Dict[str, List[float]]:
    """
    Reconstruct circuit-level packaging window trace.

    Rules:
    - RELAY_DATA send (any stream_id): decrement window by data_dec
    - SENDME recv with stream_id == 0: increment window by sendme_inc
    - Stream-level SENDMEs (stream_id != 0) are IGNORED for circuit window
    """
    if not events:
        return {"time_ms": [], "window": []}

    if base_ts is None:
        base_ts = min(ev.timestamp for ev in events)

    evs = sorted(events, key=lambda e: e.timestamp)

    w = int(init_window)
    times_ms: List[float] = [0.0]
    windows: List[float] = [float(w)]

    for ev in evs:
        cmd = ev.cell_cmd
        d = ev.direction

        # DATA send: consume window
        if cmd in RELAY_DATA_NAMES and d == "send":
            w = max(0, w - int(data_dec))

        # Circuit SENDME recv: refill window
        # CRITICAL: only stream_id == "0" affects circuit window
        elif cmd in SENDME_NAMES and d == "recv" and str(ev.stream_id) == "0":
            w = w + int(sendme_inc)

        else:
            continue

        t_ms = (ev.timestamp - base_ts) * 1000.0
        if t_ms < 0:
            continue
        times_ms.append(float(t_ms))
        windows.append(float(w))

    return {"time_ms": times_ms, "window": windows}


def sendme_intervals(events: Iterable[LogEvent], *, base_ts: float | None = None) -> SendmeStats:
    """
    Compute SENDME statistics and reconstruct circuit window.

    Returns both circuit-level and stream-level SENDME intervals.
    """
    evs = list(events)
    circ_id, circ_events = _select_circuit(evs)

    # 1) Circuit-level SENDMEs only (stream_id == 0, dir == recv)
    circuit_sendmes = [
        ev
        for ev in circ_events
        if (ev.cell_cmd in SENDME_NAMES)
           and (str(ev.stream_id) == "0")
           and (ev.direction == "recv")
    ]
    circuit_sendmes.sort(key=lambda e: e.timestamp)

    # 2) Circuit SENDME intervals
    intervals: List[float] = []
    for a, b in zip(circuit_sendmes, circuit_sendmes[1:]):
        intervals.append(b.timestamp - a.timestamp)

    timestamps = [ev.timestamp for ev in circuit_sendmes]
    first_ts = timestamps[0] if timestamps else None

    # 3) Count RELAY_DATA sends for validation
    relay_data_count = sum(
        1
        for ev in circ_events
        if ev.cell_cmd in RELAY_DATA_NAMES and ev.direction == "send"
    )

    # 4) Reconstruct circuit window trace
    circuit_base_ts = base_ts if base_ts is not None else (
        min(ev.timestamp for ev in circ_events) if circ_events else None
    )
    window_trace_ms = compute_circuit_pkg_window_trace_ms(
        circ_events,
        base_ts=circuit_base_ts,
        init_window=PKG_WINDOW_INIT,
        sendme_inc=PKG_WINDOW_SENDME_INC,
        data_dec=PKG_WINDOW_DATA_DEC,
    )

    # 5) Stream-level SENDME intervals (stream_id != 0, dir == recv)
    stream_sendmes: Dict[str, List[LogEvent]] = defaultdict(list)
    for ev in circ_events:
        if (
                ev.cell_cmd in SENDME_NAMES
                and ev.direction == "recv"
                and str(ev.stream_id) != "0"
        ):
            stream_sendmes[str(ev.stream_id)].append(ev)

    stream_intervals: List[float] = []
    for stream_evs in stream_sendmes.values():
        stream_evs.sort(key=lambda e: e.timestamp)
        for a, b in zip(stream_evs, stream_evs[1:]):
            stream_intervals.append(b.timestamp - a.timestamp)

    return SendmeStats(
        intervals=np.array(intervals, dtype=float),
        stream_intervals=np.array(stream_intervals, dtype=float),
        count=len(circuit_sendmes),
        first_ts=first_ts,
        timestamps=sorted(timestamps),
        window_trace_ms=window_trace_ms,
        base_ts=circuit_base_ts,
        circ_id=circ_id,
        relay_data_count=relay_data_count,
    )


def infer_destroy(events: List[LogEvent]) -> float | None:
    """
    Infer circuit destruction time.

    Rules:
    1. If explicit DESTROY exists, use latest DESTROY timestamp
    2. Otherwise use latest event timestamp
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
    """Build analysis report for one round."""
    base_ts = {
        "Tor": min((ev.timestamp for ev in tor_events), default=None),
        "TorBox": min((ev.timestamp for ev in torbox_events), default=None),
    }

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

    return RoundSummary(stages=stages, sendme=sendme, destroy_ts=destroy_ts, base_ts=base_ts)


# ===================== Output Functions =====================
def _fmt_ts(ts: float | None) -> str:
    return "-" if ts is None else f"{ts:.6f}"


def _write_stage_summary(report: RoundSummary, output_dir: Path, title: str) -> None:
    """Write control plane stage summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "state_metrics.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"# {title} - Control Plane Events\n")
        stage_payload = {}
        for label in ("Tor", "TorBox"):
            stats = report.stages[label]
            stage_payload[label] = {}
            f.write(f"[{label}] Stage Event Statistics\n")

            for key in STAGE_KEYS:
                cnt = stats.counts.get(key, 0)
                start_val = stats.start_time(key)
                end_val = stats.end_time(key)
                times_list = stats.all_times(key)

                # For high-frequency events, only show first and last
                if key in {"SENDME", "RELAY_DATA"}:
                    if times_list:
                        trimmed = [times_list[0]]
                        if len(times_list) > 1:
                            trimmed.append(times_list[-1])
                        times_list = trimmed
                        end_val = times_list[-1]

                # Force DESTROY end to inferred value
                if key == "DESTROY":
                    end_val = report.destroy_ts.get(label)

                start = _fmt_ts(start_val)
                end = _fmt_ts(end_val)
                times = ", ".join(f"{ts:.6f}" for ts in times_list) or "-"
                f.write(f"  {key}: count={cnt}, start={start}, end={end}, occurrences={times}\n")

                stage_payload[label][key] = {
                    "count": cnt,
                    "start": times_list[0] if times_list else None,
                    "end": end_val,
                    "times": times_list,
                }

            destroy_val = _fmt_ts(report.destroy_ts.get(label))
            f.write(f"  Inferred DESTROY time={destroy_val}\n")
            stage_payload[label]["DESTROY_TS"] = report.destroy_ts.get(label)

        f.write(f"# RAW_STAGE_JSON {json.dumps(stage_payload, ensure_ascii=False)}\n")


def _write_sendme_summary(report: RoundSummary, output_dir: Path, title: str) -> None:
    """Write SENDME and circuit window summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "sendme_metrics.txt"
    with summary_path.open("w", encoding="utf-8") as f:
        f.write(f"# {title} - Circuit Window Analysis\n")
        f.write("# This file contains:\n")
        f.write("#   - Circuit-level SENDME statistics (stream_id == 0)\n")
        f.write("#   - Stream-level SENDME statistics (stream_id != 0)\n")
        f.write("#   - Circuit packaging window trace (DATA decrements + circuit SENDME increments)\n")
        f.write("#\n")

        payload = {}
        for label in ("Tor", "TorBox"):
            s = report.sendme[label]

            # Validation warnings
            if s.count == 0:
                f.write(f"[{label}] WARNING: No circuit-level SENDMEs found!\n")
            if s.relay_data_count == 0:
                f.write(f"[{label}] WARNING: No RELAY_DATA sends found!\n")
            if len(s.window_trace_ms.get("time_ms", [])) < 2:
                f.write(f"[{label}] WARNING: Window trace has insufficient data points!\n")

            f.write(
                f"[{label}] Circuit SENDME: count={s.count}, first_ts={_fmt_ts(s.first_ts)}, "
                f"interval_samples={len(s.intervals)}, mean={s.mean:.3f}s, median={s.median:.3f}s, "
                f"circ_id={s.circ_id or '-'}, relay_data_count={s.relay_data_count}\n"
            )

            if s.first_ts is None:
                delta_str = "-"
            else:
                deltas = [t - s.first_ts for t in s.timestamps]
                delta_str = ", ".join(f"{v:.6f}" for v in deltas) or "-"
            f.write(f"  Circuit SENDME timestamps (relative to first)={delta_str}\n")

            # Stream-level SENDME info
            if len(s.stream_intervals) > 0:
                stream_mean = float(np.mean(s.stream_intervals))
                f.write(f"  Stream SENDME: interval_samples={len(s.stream_intervals)}, mean={stream_mean:.3f}s\n")

            payload[label] = {
                "count": s.count,
                "first_ts": s.first_ts,
                "intervals": s.intervals.tolist(),
                "stream_intervals": s.stream_intervals.tolist(),
                "timestamps": s.timestamps,
                "mean": s.mean,
                "median": s.median,
                "window_trace_ms": s.window_trace_ms,
                "base_ts": s.base_ts,
                "circ_id": s.circ_id,
                "relay_data_count": s.relay_data_count,
            }
        f.write(f"# RAW_SENDME_JSON {json.dumps(payload, ensure_ascii=False)}\n")


def main(
        *,
        tor_input: Path = TOR_INPUT,
        torbox_input: Path = TORBOX_INPUT,
        output_dir: Path = OUTPUT_DIR,
        rounds: int = ROUNDS,
) -> None:
    """Main analysis function."""
    tor_inputs = discover_runs(tor_input, rounds)
    torbox_inputs = discover_runs(torbox_input, rounds)

    if len(tor_inputs) != len(torbox_inputs):
        raise SystemExit(f"Mismatched run counts: Tor={len(tor_inputs)} TorBox={len(torbox_inputs)}")

    round_reports: List[RoundSummary] = []
    for idx, (tor_path, tb_path) in enumerate(zip(tor_inputs, torbox_inputs)):
        print(f"Processing round {idx:03d}...")
        tor_events = load_log(tor_path)
        torbox_events = load_log(tb_path)

        round_report = build_report(tor_events, torbox_events)
        round_dir = output_dir / f"round_{idx:03d}"
        _write_stage_summary(round_report, round_dir, title=f"Round {idx:03d}")
        _write_sendme_summary(round_report, round_dir, title=f"Round {idx:03d}")
        round_reports.append(round_report)

    if round_reports:
        print("Generating multi-round averages...")

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

        # Stage metrics
        avg_state_path = output_dir / "avg_state_metrics.txt"
        with avg_state_path.open("w", encoding="utf-8") as f:
            f.write("# Multi-Round Average - Control Plane Events\n")
            aggregated_payload = {}

            for label in ("Tor", "TorBox"):
                f.write(f"[{label}]\n")
                aggregated_payload[label] = {}

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

                    if key == "DESTROY":
                        end_mean = destroy_mean

                    f.write(
                        f"  {key}: avg_count={mean_count:.2f}, avg_start={_fmt_ts(start_mean)}, avg_end={_fmt_ts(end_mean)}\n"
                    )

                    per_round = [_occurrence_offsets(r, label, key) for r in round_reports]
                    mean_seq = [_clean(v) for v in _mean_per_occurrence(per_round)]

                    if key in {"EXTEND2", "EXTENDED2"}:
                        seq_str = ", ".join(_fmt_ts(v) for v in mean_seq if v is not None) if mean_seq else "-"
                        f.write(f"    {key}: avg occurrence sequence={seq_str}\n")

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

                f.write(f"  Avg inferred DESTROY={_fmt_ts(destroy_mean)}\n")
                aggregated_payload[label]["DESTROY_TS"] = _clean(destroy_mean)

            f.write(f"# RAW_STAGE_JSON {json.dumps(aggregated_payload, ensure_ascii=False)}\n")

        # SENDME metrics - use representative round (round_000) for window_trace_ms
        avg_sendme_path = output_dir / "avg_sendme_metrics.txt"
        with avg_sendme_path.open("w", encoding="utf-8") as f:
            f.write("# Multi-Round Average - Circuit Window Analysis\n")
            f.write("# NOTE: window_trace_ms is from round_000 (representative, not averaged)\n")
            f.write("#       Other metrics are averaged across all rounds\n")
            f.write("#\n")

            aggregated_payload: dict[str, dict[str, object]] = {}
            for label in ("Tor", "TorBox"):
                # Use round_000 as representative for window trace
                rep_round = round_reports[0]
                rep_window_trace = rep_round.sendme[label].window_trace_ms
                rep_base_ts = rep_round.sendme[label].base_ts
                rep_circ_id = rep_round.sendme[label].circ_id

                mean_count = _nanmean([float(r.sendme[label].count) for r in round_reports])
                mean_first = _nanmean([
                    _offset(r.sendme[label].first_ts, r.sendme[label].base_ts) for r in round_reports
                ])
                mean_interval_count = _nanmean([float(len(r.sendme[label].intervals)) for r in round_reports])
                mean_val = _nanmean([r.sendme[label].mean for r in round_reports])
                median_val = _nanmean([r.sendme[label].median for r in round_reports])
                mean_data_count = _nanmean([float(r.sendme[label].relay_data_count) for r in round_reports])

                f.write(
                    f"[{label}] Avg circuit SENDME: count={mean_count:.2f}, first_ts={_fmt_ts(mean_first)}, "
                    f"interval_samples={mean_interval_count:.2f}, mean={mean_val:.3f}s, median={median_val:.3f}s, "
                    f"relay_data_count={mean_data_count:.2f}\n"
                )

                per_round_intervals = [r.sendme[label].intervals.tolist() for r in round_reports]
                mean_interval_seq = _mean_per_occurrence(per_round_intervals)
                seq_str = ", ".join(_fmt_ts(v) for v in mean_interval_seq) if mean_interval_seq else "-"
                f.write(f"  Avg interval sequence={seq_str}\n")

                per_round_timestamps = [
                    [t - (r.sendme[label].base_ts or 0.0) for t in r.sendme[label].timestamps]
                    for r in round_reports
                ]
                mean_timestamp_seq = _mean_per_occurrence(per_round_timestamps)

                # Stream-level averages
                per_round_stream_intervals = [r.sendme[label].stream_intervals.tolist() for r in round_reports]
                all_stream_intervals = [item for sublist in per_round_stream_intervals for item in sublist]

                aggregated_payload[label] = {
                    "count": _clean(mean_count),
                    "first_ts": _clean(mean_first),
                    "intervals": [_clean(v) for v in mean_interval_seq if not np.isnan(v)],
                    "stream_intervals": all_stream_intervals,  # combined from all rounds
                    "timestamps": [_clean(v) for v in mean_timestamp_seq if not np.isnan(v)],
                    "mean": _clean(mean_val),
                    "median": _clean(median_val),
                    "window_trace_ms": rep_window_trace,  # from round_000
                    "base_ts": rep_base_ts,
                    "circ_id": rep_circ_id,
                    "relay_data_count": _clean(mean_data_count),
                    "_note": "window_trace_ms is from round_000, not averaged",
                }

            f.write(f"# RAW_SENDME_JSON {json.dumps(aggregated_payload, ensure_ascii=False)}\n")

    print(f"Analysis complete. Results written to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Semantic log analysis for Tor/TorBox circuit packaging window")
    parser.add_argument("--tor", type=Path, default=TOR_INPUT)
    parser.add_argument("--torbox", type=Path, default=TORBOX_INPUT)
    parser.add_argument("--out", type=Path, default=OUTPUT_DIR)
    parser.add_argument("--rounds", type=int, default=ROUNDS)
    args = parser.parse_args()

    main(tor_input=args.tor, torbox_input=args.torbox, output_dir=args.out, rounds=args.rounds)