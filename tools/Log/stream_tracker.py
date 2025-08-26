# stream_tracker.py
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

def _now_ns() -> int:
    return time.monotonic_ns()

@dataclass
class StreamRec:
    stream_uid: str         # 全局唯一：建议 "client:circuit_id:stream_id"
    src: str                # 客户端名（或节点名）
    dst: str                # 目标 "host:port"
    t_start_ns: int = field(default_factory=_now_ns)
    t_first_ns: Optional[int] = None
    t_end_ns: Optional[int] = None
    bytes_down: int = 0
    retries: int = 0
    status: str = "ok"      # "ok"|"timeout"|"reset"|"error"|"cancel"

    def as_dict(self) -> dict:
        t_first = (self.t_first_ns - self.t_start_ns) / 1e6 if self.t_first_ns else None
        t_total = ((self.t_end_ns or _now_ns()) - self.t_start_ns) / 1e6
        thr_bps = None
        if self.bytes_down > 0 and t_total and t_total > 0:
            thr_bps = (self.bytes_down * 8) / (t_total / 1e3)
        return {
            "stream_id": self.stream_uid,     # ← 字段改名为 stream_id
            "src": self.src,
            "dst": self.dst,
            "bytes": self.bytes_down,
            "latency_ms_first": t_first,
            "latency_ms_total": t_total,
            "throughput_bps": thr_bps,
            "retries": self.retries,
            "status": self.status,
        }

class StreamTracker:
    def __init__(self) -> None:
        self._items: Dict[str, StreamRec] = {}

    def start(self, stream_uid: str, src: str, dst: str) -> None:
        self._items.setdefault(stream_uid, StreamRec(stream_uid=stream_uid, src=src, dst=dst))

    def on_down_chunk(self, stream_uid: str, nbytes: int) -> None:
        rec = self._items.get(stream_uid)
        if not rec:
            return
        if rec.t_first_ns is None:
            rec.t_first_ns = _now_ns()
        rec.bytes_down += int(nbytes)

    def add_retry(self, stream_uid: str) -> None:
        rec = self._items.get(stream_uid)
        if rec:
            rec.retries += 1

    def set_status(self, stream_uid: str, status: str) -> None:
        rec = self._items.get(stream_uid)
        if rec:
            rec.status = status

    def end(self, stream_uid: str) -> Optional[dict]:
        rec = self._items.pop(stream_uid, None)
        if not rec:
            return None
        if rec.t_end_ns is None:
            rec.t_end_ns = _now_ns()
        return rec.as_dict()
