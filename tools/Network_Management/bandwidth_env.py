from __future__ import annotations

from typing import Optional, Dict, Tuple

from .bandwidth_limiter import BandwidthLimiter, init_global_limiter_from_env
from .bandwidth_registry import get_bandwidth_cfg_for

_LIMITERS: Dict[str, Tuple[Tuple[float, float], BandwidthLimiter]] = {}
_DEFAULT_KEY = "__default__"


def _build_limiter(rate_bps: float, burst_bytes: float) -> BandwidthLimiter:
    return BandwidthLimiter(rate_bps=rate_bps, burst_bytes=burst_bytes)


def get_limiter(node_id: Optional[str]) -> Optional[BandwidthLimiter]:
    cfg = get_bandwidth_cfg_for(node_id)
    if cfg is not None:
        key = node_id or _DEFAULT_KEY
        rate_bps = float(cfg["rate_bps"])
        burst_bytes = float(cfg["burst_bytes"])
        config_key = (rate_bps, burst_bytes)
        cached = _LIMITERS.get(key)
        if cached is None or cached[0] != config_key:
            limiter = _build_limiter(rate_bps, burst_bytes)
            _LIMITERS[key] = (config_key, limiter)
            return limiter
        return cached[1]

    return init_global_limiter_from_env()


def clear_limiter_cache() -> None:
    _LIMITERS.clear()