# -*- coding: utf-8 -*-
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ===================== HARD-CODED PATHS (match your screenshot) =====================
TOR_INPUT = Path("exp/semantic_logs/tor")
TORBOX_INPUT = Path("exp/semantic_logs/torbox")
OUTPUT_DIR = Path("exp/semantic_logs/protocol_outputs")  # output next to tor/torbox/

MAX_CIRCUITS = 200

STAGES = [
    "1. TLS handshake done",
    "2. Tor handshake done",
    "3. CREATE2 sent",
    "4. CREATED2 received",
    "5. EXTEND2 hop2 sent",
    "6. EXTENDED2 hop2 received",
    "7. EXTEND2 hop3 sent",
    "8. EXTENDED2 hop3 received",
    "9. RELAY_CONNECTED received",
    "10. first RELAY_DATA sent/recv",
]


def read_jsonl(path: Path) -> List[dict]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s:
                continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError:
                continue
    return rows


def ns_to_ms(ns: int) -> float:
    return float(ns) / 1e6


def _meta(row: dict) -> dict:
    m = row.get("meta") or {}
    return m if isinstance(m, dict) else {}


def _time_ms(row: dict) -> Optional[float]:
    # your logs use ts_mono_ns
    if "ts_mono_ns" in row:
        return ns_to_ms(int(row["ts_mono_ns"]))
    if "ts_ns" in row:
        return ns_to_ms(int(row["ts_ns"]))
    if "ts_ms" in row:
        return float(row["ts_ms"])
    # (optional) fallbacks
    if "timestamp" in row:
        return float(row["timestamp"]) * 1000.0
    return None


def _circ_id(row: dict) -> Optional[int]:
    m = _meta(row)
    cid = m.get("circ_id") or row.get("circ_id")
    if cid is None:
        return None
    try:
        return int(cid)
    except Exception:
        return None


# ===================== Discover rounds and events log =====================

def _events_from_meta(meta_path: Path) -> Optional[Path]:
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    log_files = meta.get("log_files") or {}
    p = log_files.get("events") or meta.get("events")
    if not p:
        return None
    p = Path(p)
    if not p.is_absolute():
        p = meta_path.parent / p
    return p if p.exists() else None


def find_events_log(round_dir: Path) -> Path:
    # 1) try run_meta.json
    meta_path = round_dir / "run_meta.json"
    if meta_path.exists():
        p = _events_from_meta(meta_path)
        if p is not None:
            return p

    # 2) fallback: round_dir/events/*.jsonl
    events_dir = round_dir / "events"
    if events_dir.exists():
        files = sorted(events_dir.glob("*.jsonl"))
        if files:
            return files[-1]

    raise FileNotFoundError(f"No events log found under {round_dir}")


def discover_round_dirs(base: Path) -> List[Path]:
    # if only round_000 exists, this will just return that
    rounds = sorted([p for p in base.glob("round_*") if p.is_dir()])
    if not rounds:
        raise FileNotFoundError(f"No round_* directories under {base}")
    return rounds


# ===================== Timeline Extraction =====================

@dataclass
class CircuitTimeline:
    circ_id: int
    stages: Dict[str, float]
    tls_done: Optional[float]
    tor_done: Optional[float]


def build_timelines(rows: List[dict], max_circuits: int) -> Dict[int, CircuitTimeline]:
    timelines: Dict[int, CircuitTimeline] = {}
    extend_send_cnt = defaultdict(int)
    extend_recv_cnt = defaultdict(int)

    for row in rows:
        t = _time_ms(row)
        if t is None:
            continue
        cid = _circ_id(row)
        if cid is None:
            continue

        if cid not in timelines:
            if len(timelines) >= max_circuits:
                continue
            timelines[cid] = CircuitTimeline(cid, {}, None, None)

        tl = timelines[cid]
        ev = row.get("event")
        meta = _meta(row)

        if ev == "tls_handshake_done":
            tl.tls_done = tl.tls_done or t
            tl.stages.setdefault(STAGES[0], t)  # record stage 1 time explicitly

        elif ev == "tor_handshake_done":
            tl.tor_done = tl.tor_done or t
            tl.stages.setdefault(STAGES[1], t)

        elif ev == "cell_trace":
            cmd = meta.get("cell_cmd")
            d = meta.get("dir")

            if cmd == "CREATE2" and d == "send":
                tl.stages.setdefault(STAGES[2], t)
            elif cmd == "CREATED2" and d == "recv":
                tl.stages.setdefault(STAGES[3], t)

            elif cmd == "EXTEND2" and d == "send":
                extend_send_cnt[cid] += 1
                hop = extend_send_cnt[cid] + 1  # hop2 for first EXTEND2
                if hop == 2:
                    tl.stages.setdefault(STAGES[4], t)
                elif hop == 3:
                    tl.stages.setdefault(STAGES[6], t)

            elif cmd == "EXTENDED2" and d == "recv":
                extend_recv_cnt[cid] += 1
                hop = extend_recv_cnt[cid] + 1
                if hop == 2:
                    tl.stages.setdefault(STAGES[5], t)
                elif hop == 3:
                    tl.stages.setdefault(STAGES[7], t)

            elif cmd == "RELAY_CONNECTED" and d == "recv":
                tl.stages.setdefault(STAGES[8], t)

            elif cmd == "RELAY_DATA":
                tl.stages.setdefault(STAGES[9], t)

    return timelines


def extract_series(timelines: Dict[int, CircuitTimeline]) -> List[List[float]]:
    series = []
    for tl in timelines.values():
        # x-axis origin: TLS done (strict absolute timeline)
        t0 = tl.tls_done
        if t0 is None:
            continue

        row = []
        ok = True
        for s in STAGES:
            if s not in tl.stages:
                ok = False
                break
            row.append(tl.stages[s] - t0)

        if ok:
            series.append(row)
    return series


# ===================== Plot =====================

def plot_alignment(tor_s: List[List[float]], emu_s: List[List[float]]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    y = np.arange(1, len(STAGES) + 1)

    fig, axes = plt.subplots(1, 2, figsize=(13, 6), sharey=True)

    def panel(ax, data, color, title):
        for r in data:
            ax.plot(r, y, color=color, alpha=0.25, lw=1.1)
        ax.set_title(title)
        ax.set_xlabel("Relative Time (ms)")
        ax.grid(axis="x", alpha=0.3, linestyle="--")

    panel(axes[0], tor_s, "#1E40AF", f"Real Tor Client (N={len(tor_s)})")
    panel(axes[1], emu_s, "#B91C1C", f"Emulator Client (N={len(emu_s)})")

    axes[0].set_yticks(y)
    axes[0].set_yticklabels(STAGES)
    axes[1].tick_params(labelleft=False)

    fig.suptitle("Client Protocol Progress Timeline Alignment", fontsize=14, fontweight="bold")
    fig.tight_layout(rect=[0, 0.02, 1, 0.93])

    fig.savefig(OUTPUT_DIR / "timeline_alignment.png", dpi=300)
    fig.savefig(OUTPUT_DIR / "timeline_alignment.pdf")
    plt.close(fig)


# ===================== Contracts (minimal baseline, you can extend) =====================

@dataclass
class Assertion:
    name: str
    total: int
    violations: int

def run_contracts(timelines: Dict[int, CircuitTimeline]) -> List[Assertion]:
    stats = {
        "A1_created2_after_create2": [0, 0],
        "A2_extend_pairing_and_order": [0, 0],
        "A3_no_relay_before_built": [0, 0],
        "A4_relay_connected_before_data": [0, 0],
    }

    for tl in timelines.values():
        s = tl.stages

        if STAGES[2] in s and STAGES[3] in s:
            stats["A1_created2_after_create2"][0] += 1
            if s[STAGES[3]] < s[STAGES[2]]:
                stats["A1_created2_after_create2"][1] += 1

        if all(k in s for k in (STAGES[4], STAGES[5], STAGES[6], STAGES[7])):
            stats["A2_extend_pairing_and_order"][0] += 1
            if not (s[STAGES[5]] >= s[STAGES[4]] and s[STAGES[6]] >= s[STAGES[5]] and s[STAGES[7]] >= s[STAGES[6]]):
                stats["A2_extend_pairing_and_order"][1] += 1

        if STAGES[7] in s and STAGES[9] in s:
            stats["A3_no_relay_before_built"][0] += 1
            if s[STAGES[9]] < s[STAGES[7]]:
                stats["A3_no_relay_before_built"][1] += 1

        if STAGES[8] in s and STAGES[9] in s:
            stats["A4_relay_connected_before_data"][0] += 1
            if s[STAGES[9]] < s[STAGES[8]]:
                stats["A4_relay_connected_before_data"][1] += 1

    return [Assertion(k, v[0], v[1]) for k, v in stats.items()]


def write_contract_csv(tor_res: List[Assertion], emu_res: List[Assertion]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUTPUT_DIR / "contract_assertions.csv"

    tor_map = {a.name: a for a in tor_res}
    emu_map = {a.name: a for a in emu_res}

    lines = ["assertion,tor_total,tor_viol,tor_rate,emu_total,emu_viol,emu_rate"]
    for name in sorted(tor_map.keys()):
        t = tor_map[name]
        e = emu_map[name]
        tr = (t.violations / t.total) if t.total else 0.0
        er = (e.violations / e.total) if e.total else 0.0
        lines.append(f"{name},{t.total},{t.violations},{tr:.6f},{e.total},{e.violations},{er:.6f}")

    path.write_text("\n".join(lines), encoding="utf-8")


# ===================== Main =====================

def main():
    tor_rounds = discover_round_dirs(TOR_INPUT)
    emu_rounds = discover_round_dirs(TORBOX_INPUT)

    # align counts
    n = min(len(tor_rounds), len(emu_rounds))
    tor_rounds = tor_rounds[:n]
    emu_rounds = emu_rounds[:n]

    tor_series_all: List[List[float]] = []
    emu_series_all: List[List[float]] = []

    # aggregate contract totals across rounds (simple sum)
    tor_assert_sum = defaultdict(lambda: [0, 0])
    emu_assert_sum = defaultdict(lambda: [0, 0])

    for i, (trd, erd) in enumerate(zip(tor_rounds, emu_rounds)):
        tor_log = find_events_log(trd)
        emu_log = find_events_log(erd)

        tor_rows = read_jsonl(tor_log)
        emu_rows = read_jsonl(emu_log)

        tor_tl = build_timelines(tor_rows, MAX_CIRCUITS)
        emu_tl = build_timelines(emu_rows, MAX_CIRCUITS)

        tor_series_all.extend(extract_series(tor_tl))
        emu_series_all.extend(extract_series(emu_tl))

        for a in run_contracts(tor_tl):
            tor_assert_sum[a.name][0] += a.total
            tor_assert_sum[a.name][1] += a.violations
        for a in run_contracts(emu_tl):
            emu_assert_sum[a.name][0] += a.total
            emu_assert_sum[a.name][1] += a.violations

        print(f"Round {i:03d}: Tor circuits={len(tor_tl)} Emu circuits={len(emu_tl)}")

    plot_alignment(tor_series_all, emu_series_all)

    tor_res = [Assertion(k, v[0], v[1]) for k, v in tor_assert_sum.items()]
    emu_res = [Assertion(k, v[0], v[1]) for k, v in emu_assert_sum.items()]
    write_contract_csv(sorted(tor_res, key=lambda x: x.name), sorted(emu_res, key=lambda x: x.name))

    print("Outputs:", OUTPUT_DIR.resolve())


if __name__ == "__main__":
    main()
