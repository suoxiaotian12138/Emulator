# server_sink_async.py
import asyncio
import os
import time
from pathlib import Path
from typing import Optional

HOST = os.environ.get("SINK_HOST", "192.168.66.243")
PORT = int(os.environ.get("SINK_PORT", "8000"))
BACKLOG = int(os.environ.get("SINK_BACKLOG", "1024"))
RECV_BUF = int(os.environ.get("SINK_RECV_BUF", "65536"))
PRINT_EVERY_MB = int(os.environ.get("SINK_PRINT_EVERY_MB", "10"))

LOG_DIR = os.environ.get("SINK_LOG_DIR", "./exp/e2/tor/stream_time")
LOG_FILE_NAME = os.environ.get("SINK_LOG_FILE", "sink.log")

# Concurrency controls
MAX_CONNS = int(os.environ.get("SINK_MAX_CONNS", "20000"))
# If semaphore is saturated, do not let the connection wait forever.
ACQUIRE_TIMEOUT_SEC = float(os.environ.get("SINK_ACQUIRE_TIMEOUT_SEC", "0.2"))

# Do not kill slow streams unless you really want to.
# If you set it, it is "no data for X seconds".
IDLE_TIMEOUT_SEC = float(os.environ.get("SINK_IDLE_TIMEOUT_SEC", "0"))
SEND_OK = os.environ.get("SINK_SEND_OK", "1") not in ("0", "false", "False")

_log_lock: Optional[asyncio.Lock] = None
_conn_sem: Optional[asyncio.Semaphore] = None


def _now_ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _append_line_sync(path: Path, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line)
        if not line.endswith("\n"):
            f.write("\n")


async def append_log_line(line: str) -> None:
    global _log_lock
    if _log_lock is None:
        _log_lock = asyncio.Lock()

    log_dir = Path(LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / LOG_FILE_NAME

    async with _log_lock:
        await asyncio.to_thread(_append_line_sync, log_path, line)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    global _conn_sem
    if _conn_sem is None:
        _conn_sem = asyncio.Semaphore(MAX_CONNS)

    peer = writer.get_extra_info("peername")
    addr = str(peer) if peer else "unknown"

    wait_t0 = time.time()
    acquired = False
    try:
        # Prevent long queueing. If overloaded, reject quickly.
        await asyncio.wait_for(_conn_sem.acquire(), timeout=ACQUIRE_TIMEOUT_SEC)
        acquired = True
    except asyncio.TimeoutError:
        # Overloaded. Close immediately to avoid "connected but not reading".
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await append_log_line(f"{_now_ts()} addr={addr} rejected=1 reason=overload_wait_timeout")
        return

    wait_sec = time.time() - wait_t0

    t0 = time.time()
    total = 0
    last_print_mb = 0
    reason = "closed_by_client"

    try:
        while True:
            if IDLE_TIMEOUT_SEC > 0:
                try:
                    chunk = await asyncio.wait_for(reader.read(RECV_BUF), timeout=IDLE_TIMEOUT_SEC)
                except asyncio.TimeoutError:
                    reason = "idle_timeout"
                    break
            else:
                chunk = await reader.read(RECV_BUF)

            if not chunk:
                break

            total += len(chunk)
            mb = total // (1024 * 1024)
            if PRINT_EVERY_MB > 0 and (mb - last_print_mb) >= PRINT_EVERY_MB:
                last_print_mb = mb
                print(f"[SINK] {addr} received {mb} MB ...")

        if SEND_OK:
            try:
                writer.write(b"OK")
                await writer.drain()
            except Exception:
                reason = "send_failed"

    except Exception as e:
        reason = f"error:{type(e).__name__}"
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        io_sec = time.time() - t0
        mb_f = total / (1024 * 1024)
        mbps = (mb_f * 8.0 / io_sec) if io_sec > 0 else 0.0

        print(f"[SINK] {addr} closed. total={mb_f:.2f} MB, io={io_sec:.2f}s, wait={wait_sec:.3f}s, reason={reason}")

        log_line = (
            f"{_now_ts()} addr={addr} bytes={total} mb={mb_f:.3f} "
            f"io_sec={io_sec:.6f} wait_sec={wait_sec:.6f} mbps={mbps:.3f} reason={reason}"
        )
        await append_log_line(log_line)

        if acquired:
            _conn_sem.release()


async def main() -> None:
    # Increase StreamReader internal buffer limit to reduce pause/resume churn
    reader_limit = int(os.environ.get("SINK_READER_LIMIT", str(RECV_BUF * 64)))

    server = await asyncio.start_server(
        handle_client,
        host=HOST,
        port=PORT,
        backlog=BACKLOG,
        reuse_address=True,
        start_serving=True,
        limit=reader_limit,
    )

    socknames = ", ".join(str(s.getsockname()) for s in (server.sockets or []))
    print(f"[SINK] Listening on {socknames} backlog={BACKLOG}")
    print(f"[SINK] Log: {Path(LOG_DIR).resolve()}/{LOG_FILE_NAME}")
    print(f"[SINK] Limits: max_conns={MAX_CONNS} acquire_timeout={ACQUIRE_TIMEOUT_SEC}s idle_timeout={IDLE_TIMEOUT_SEC}s recv_buf={RECV_BUF} reader_limit={reader_limit}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
