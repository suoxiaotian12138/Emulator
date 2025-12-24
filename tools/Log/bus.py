# logging_bus.py
import time
from typing import Any, Callable
from tools.Log.writer import AsyncJsonlWriter

class NoOpBus:
    def ev(self, *a, **k): pass
    def circuit(self, *a, **k): pass
    def path(self, *a, **k): pass
    def stream(self, *a, **k): pass

class GlobalBus:
    _writer = None
    _role_default = "node"
    @classmethod
    def set_default(cls, writer: AsyncJsonlWriter, role_default="node"):
        cls._writer = writer; cls._role_default = role_default
    @classmethod
    def for_node(cls, node_id: str, role: str | None = None):
        if cls._writer is None:
            return NoOpBus()
        return EventBus(cls._writer.emit_nowait, node_id=node_id, role=role or cls._role_default)

class EventBus:
    def __init__(self, emitter: Callable[[str, dict], None], node_id: str, role: str):
        self.emit = emitter
        self.node_id = node_id
        self.role = role

    def _t(self): return time.monotonic_ns()

    # 控制面事件
    def ev(self, name: str, **meta: Any):
        """记录单个控制面事件。

        meta 中涉及可观测语义的字段请遵守 schema.Event 的约定：
        cell_cmd=CREATE2|CREATED2|EXTEND2|EXTENDED2|SENDME|DESTROY|RELAY,
        dir=send|recv, side=client|relay|exit，并保持 circ_id/stream_id/hop/peer 等字段名一致。
        """
        self.emit("events", {"ts_mono_ns": self._t(), "node_id": self.node_id, "role": self.role, "event": name, "meta": meta})


    # 电路
    def circuit(self, circ_id: str, client: str, guard: str, exit: str, build_ms: float, success: bool, fail_reason: str | None = None, middle: str | None = None):
        self.emit("circuits", {"ts_mono_ns": self._t(), "circ_id": circ_id, "client": client, "guard": guard, "middle": middle, "exit": exit, "build_ms": build_ms, "success": success, "fail_reason": fail_reason})

    # 路径
    def path(self, client: str, guard: str, middle: str | None, exit: str, wg: float, we: float, consensus_id: str | None):
        self.emit("paths", {"ts_mono_ns": self._t(), "client": client, "guard": guard, "middle": middle, "exit": exit, "weight_guard": float(wg), "weight_exit": float(we), "consensus_id": consensus_id})

    # 流
    def stream(self, **fields: Any):
        fields.setdefault("ts_mono_ns", self._t())
        self.emit("streams", fields)
