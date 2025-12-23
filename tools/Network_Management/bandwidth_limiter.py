import asyncio
import os
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Optional


@dataclass
class LimiterStats:
    total_bytes: int
    average_rate_bps: float
    peak_rate_bps: float


class BandwidthLimiter:
    def __init__(self, rate_bps: float, burst_bytes: float, window_seconds: float = 1.0):
        if rate_bps <= 0:
            raise ValueError("rate_bps must be positive")
        if burst_bytes <= 0:
            raise ValueError("burst_bytes must be positive")

        self.rate_bps = float(rate_bps)
        self.burst_bytes = float(burst_bytes)
        self._tokens = float(burst_bytes)
        self._updated_at = time.monotonic()
        self._lock = asyncio.Lock()

        self._start_time = self._updated_at
        self._total_bytes = 0
        self._peak_rate_bps = 0.0
        self._window_seconds = float(window_seconds)
        self._window: Deque[tuple[float, int]] = deque()

    def _refill(self, now: float) -> None:
        elapsed = max(0.0, now - self._updated_at)
        if elapsed <= 0:
            return
        self._tokens = min(self.burst_bytes, self._tokens + elapsed * self.rate_bps)
        self._updated_at = now

    def _record(self, now: float, nbytes: int) -> None:
        self._total_bytes += nbytes
        self._window.append((now, nbytes))

        cutoff = now - self._window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()

        if not self._window:
            return

        window_bytes = sum(item[1] for item in self._window)
        window_duration = max(1e-6, now - self._window[0][0])
        window_rate = window_bytes / window_duration
        self._peak_rate_bps = max(self._peak_rate_bps, window_rate)

    async def _consume_once(self, nbytes: int) -> None:
        if nbytes <= 0:
            return

        while True:
            async with self._lock:
                now = time.monotonic()
                self._refill(now)

                if self._tokens >= nbytes:
                    self._tokens -= nbytes
                    self._record(now, nbytes)
                    return

                missing = nbytes - self._tokens
                wait_time = missing / self.rate_bps

            await asyncio.sleep(wait_time)

    async def consume(self, nbytes: int) -> None:
        if nbytes <= 0:
            return

        if nbytes <= self.burst_bytes:
            await self._consume_once(nbytes)
            return

        remaining = nbytes
        while remaining > 0:
            chunk = int(min(remaining, self.burst_bytes))
            await self._consume_once(chunk)
            remaining -= chunk

    def stats(self) -> LimiterStats:
        now = time.monotonic()
        duration = max(1e-6, now - self._start_time)
        average_rate = self._total_bytes / duration
        return LimiterStats(
            total_bytes=self._total_bytes,
            average_rate_bps=average_rate,
            peak_rate_bps=self._peak_rate_bps,
        )


_GLOBAL_LIMITER: Optional[BandwidthLimiter] = None


def _env_float(name: str) -> Optional[float]:
    value = os.environ.get(name)
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def init_global_limiter_from_env() -> Optional[BandwidthLimiter]:
    global _GLOBAL_LIMITER
    if _GLOBAL_LIMITER is not None:
        return _GLOBAL_LIMITER

    rate = _env_float("GLOBAL_RATE_BPS")
    if rate is None or rate <= 0:
        return None

    burst = _env_float("GLOBAL_BURST_BYTES")
    if burst is None or burst <= 0:
        burst = rate

    _GLOBAL_LIMITER = BandwidthLimiter(rate_bps=rate, burst_bytes=burst)
    return _GLOBAL_LIMITER


def get_global_limiter() -> Optional[BandwidthLimiter]:
    return _GLOBAL_LIMITER