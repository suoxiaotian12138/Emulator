from __future__ import annotations

from typing import Optional

from .bandwidth_limiter import BandwidthLimiter, build_limiter_from_env
from .bandwidth_registry import get_bandwidth_cfg_for


def _build_limiter(rate_bps: float, burst_bytes: float) -> BandwidthLimiter:
    return BandwidthLimiter(rate_bps=rate_bps, burst_bytes=burst_bytes)


def get_limiter(node_id: Optional[str]) -> Optional[BandwidthLimiter]:
    cfg = get_bandwidth_cfg_for(node_id)
    if cfg is not None:
        rate_bps = float(cfg["rate_bps"])
        burst_bytes = float(cfg["burst_bytes"])
        config_key = (rate_bps, burst_bytes)
        return _build_limiter(rate_bps, burst_bytes)
    return build_limiter_from_env()

def clear_limiter_cache() -> None:
    return None