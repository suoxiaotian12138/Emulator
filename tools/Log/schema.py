# twintor/logging/schema.py
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

# All timestamps use monotonic_ns for ordering, plus optional wall clock for humans
class Event(BaseModel):
    """
    可观测语义事件字段约定：

    * ``cell_cmd``：创建/扩展/销毁等可观测单元的细分指令，使用 CREATE2、CREATED2、EXTEND2、EXTENDED2、SENDME、DESTROY、RELAY 等固定枚举值。
    * ``dir``：事件方向，限定为 send（向外发出）或 recv（从对端接收）。
    * ``side``：当前所在角色视角，client/relay/exit 三选一，便于跨节点对齐同一事件。
    * ``circ_id``：电路标识，记录为字符串以保持与 Tor 字段一致；若无则省略。
    * ``stream_id``：流标识，字符串形式，可选。
    * ``hop``：所在跳数（0 基），仅在需要区分路径位置时填写。
    * ``peer``：对端节点/连接的标识（例如 IP:Port 或 node_id），用于外部可观测的通道确认。

    语义一致性 = 外部可观测行为：实验与分析脚本应只依赖以上可观测字段的取值与顺序，不假设内部实现细节。
    """
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
