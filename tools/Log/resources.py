# resource_probe.py
import asyncio, psutil, os, time

def _fd_count():
    try: return len(os.listdir("/proc/self/fd"))
    except Exception: return None

async def resource_probe(node_id: str, role: str, emit, interval_s: float = 1.0, lag_tick_ms: int = 100):
    proc = psutil.Process(os.getpid())
    loop = asyncio.get_running_loop()
    tick = lag_tick_ms / 1000.0

    async def loop_lag_ms():
        t0 = loop.time()
        await asyncio.sleep(tick)
        return max(0.0, (loop.time() - t0 - tick)) * 1000.0

    while True:
        try:
            cpu = psutil.cpu_percent(interval=None)
            mem_mb = proc.memory_info().rss / (1024*1024)
            lag = await loop_lag_ms()
            emit("resources", {
                "ts_mono_ns": time.monotonic_ns(),
                "node_id": node_id, "role": role,
                "cpu_pct": float(cpu), "mem_mb": float(mem_mb),
                "fd": _fd_count(), "loop_lag_ms": lag
            })
            await asyncio.sleep(interval_s)
        except asyncio.CancelledError:
            break
