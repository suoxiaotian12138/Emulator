# 注册器：node_id -> { rate_bps, burst_bytes }
# 让节点在启动时能自动找到带宽限制参数。
from __future__ import annotations

from typing import Optional, Dict

_REGISTRY: Dict[str, dict] = {}
_DEFAULT: Optional[dict] = None


def _normalize(rate_bps: float, burst_bytes: Optional[float]) -> dict:
    if rate_bps <= 0:
        raise ValueError("rate_bps must be positive")
    if burst_bytes is None:
        burst_bytes = rate_bps
    if burst_bytes <= 0:
        raise ValueError("burst_bytes must be positive")
    return {
        "rate_bps": float(rate_bps),
        "burst_bytes": float(burst_bytes),
    }


def register_bandwidth_env(
    node_id: str,
    *,
    rate_bps: float,
    burst_bytes: Optional[float] = None,
) -> None:
    _REGISTRY[node_id] = _normalize(rate_bps, burst_bytes)


def unregister_bandwidth_env(node_id: str) -> None:
    _REGISTRY.pop(node_id, None)


def clear_all() -> None:
    _REGISTRY.clear()


def set_default_env(
    *,
    rate_bps: float,
    burst_bytes: Optional[float] = None,
) -> None:
    global _DEFAULT
    _DEFAULT = _normalize(rate_bps, burst_bytes)


def clear_default_env() -> None:
    global _DEFAULT
    _DEFAULT = None


def get_bandwidth_cfg_for(node_id: Optional[str]) -> Optional[dict]:
    if node_id and node_id in _REGISTRY:
        return _REGISTRY[node_id]
    return _DEFAULT