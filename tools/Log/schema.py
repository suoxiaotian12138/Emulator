# twintor/logging/schema.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

# All timestamps use monotonic_ns for ordering, plus optional wall clock for humans
class Event(BaseModel):
    ts_mono_ns: int
    ts_wall_ns: Optional[int] = None
    node_id: str
    role: str  # client|guard|middle|exit|dir
    event: str # "handshake_done" | "circuit_built" | ...
    meta: Dict[str, Any] = Field(default_factory=dict)

class Circuit(BaseModel):
    ts_mono_ns: int
    circ_id: str
    client: str
    guard: str
    middle: Optional[str] = None
    exit: str
    build_ms: float
    success: bool
    fail_reason: Optional[str] = None

class Stream(BaseModel):
    ts_mono_ns: int
    stream_id: str
    src: str
    dst: str
    bytes: int
    latency_ms: Optional[float] = None
    retries: int = 0
    status: str = "ok"  # ok|timeout|reset|error

class Resource(BaseModel):
    ts_mono_ns: int
    node_id: str
    cpu_pct: float
    mem_mb: float
    fd: Optional[int] = None
    loop_lag_ms: Optional[float] = None

class PathSel(BaseModel):
    ts_mono_ns: int
    client: str
    guard: str
    middle: Optional[str] = None
    exit: str
    weight_guard: float
    weight_exit: float
    consensus_id: Optional[str] = None
