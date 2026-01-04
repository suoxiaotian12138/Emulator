# writer.py
import asyncio
import time
from pathlib import Path
from typing import Any, Dict, Literal, List, Optional, Tuple

import aiofiles
import orjson

Kind = Literal["events", "circuits", "streams", "paths", "resources", "stability"]

# A unique sentinel object (cannot collide with any real queue item)
_STOP = object()


class AsyncJsonlWriter:
    """
    Async JSONL writer with:
      - real batch_size support (flush when buffer reaches batch_size)
      - periodic flush (flush_every_ms)
      - JSON encoding offloaded to a thread to avoid blocking the event loop
      - per-kind persistent file handles (no open/close on every flush)
      - graceful stop that flushes remaining buffers

    Interface compatible with your current usage:
      - start()
      - emit_nowait(kind, record)
      - stop()
    """

    _KINDS: Tuple[Kind, ...] = (
        "events",
        "circuits",
        "streams",
        "paths",
        "resources",
        "stability",
    )

    def __init__(
        self,
        out_dir: str,
        rotate_mb: int = 100,
        batch_size: int = 200,
        flush_every_ms: int = 100,
        queue_max: int = 100_000,
    ):
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)

        self.rotate = int(rotate_mb) * 1024 * 1024
        self.batch = int(batch_size)
        self.tick = float(flush_every_ms) / 1000.0

        # Queue items are either (kind, record) or the _STOP sentinel.
        self.q: "asyncio.Queue[Any]" = asyncio.Queue(queue_max)
        self.task: Optional[asyncio.Task] = None

        # Current file path and approximate bytes written for rotation decisions
        self.files: Dict[Kind, Path] = {}
        self.sizes: Dict[Kind, int] = {}

        # Persistent open handles per kind
        self._handles: Dict[Kind, Any] = {}

        # Separate locks per kind
        self.locks: Dict[Kind, asyncio.Lock] = {k: asyncio.Lock() for k in self._KINDS}

        # Counters for debugging/monitoring
        self.dropped = 0
        self.written_rows = 0
        self.written_bytes = 0

    def start(self) -> None:
        if self.task is None:
            self.task = asyncio.create_task(self._consumer(), name="jsonl-writer")

    async def stop(self) -> None:
        """
        Signal consumer to stop, then wait for it to flush and close.
        Never blocks the event loop on I/O directly: all work is awaited in the consumer.
        """
        if self.task is None:
            return

        # Ensure the consumer will wake up quickly even if idle
        try:
            self.q.put_nowait(_STOP)
        except asyncio.QueueFull:
            # If queue is full, we still must stop. Cancel and do best-effort cleanup.
            self.task.cancel()

        try:
            await self.task
        except asyncio.CancelledError:
            # Best-effort close handles on cancel
            await self._close_all_handles()
        finally:
            self.task = None

    def emit_nowait(self, kind: Kind, record: Dict[str, Any]) -> None:
        """
        Non-blocking emit. If queue is full, drop instead of slowing the simulation.
        """
        try:
            self.q.put_nowait((kind, record))
        except asyncio.QueueFull:
            self.dropped += 1

    def _roll(self, kind: Kind) -> Path:
        (self.out / kind).mkdir(parents=True, exist_ok=True)
        return self.out / kind / f"{kind}-{int(time.time())}.jsonl"

    async def _ensure_handle(self, kind: Kind) -> Any:
        """
        Ensure there is an open aiofiles handle for current file of kind.
        Rotate if needed.
        """
        p = self.files.get(kind)
        if p is None:
            p = self._roll(kind)
            self.files[kind] = p
            self.sizes[kind] = 0

        # Rotation check (cheap counter first, then stat as a safety net)
        if self.sizes.get(kind, 0) >= self.rotate:
            await self._close_handle(kind)
            p = self._roll(kind)
            self.files[kind] = p
            self.sizes[kind] = 0
        else:
            try:
                if p.exists() and p.stat().st_size >= self.rotate:
                    await self._close_handle(kind)
                    p = self._roll(kind)
                    self.files[kind] = p
                    self.sizes[kind] = 0
            except OSError:
                pass

        h = self._handles.get(kind)
        if h is None:
            h = await aiofiles.open(self.files[kind], "ab")
            self._handles[kind] = h
        return h

    async def _close_handle(self, kind: Kind) -> None:
        h = self._handles.pop(kind, None)
        if h is None:
            return
        try:
            await h.flush()
        except Exception:
            pass
        try:
            await h.close()
        except Exception:
            pass

    async def _close_all_handles(self) -> None:
        for k in list(self._handles.keys()):
            await self._close_handle(k)

    @staticmethod
    def _encode_rows(rows: List[Dict[str, Any]]) -> bytes:
        # CPU work: keep out of the event loop via asyncio.to_thread
        return b"".join(orjson.dumps(r) + b"\n" for r in rows)

    async def _append(self, kind: Kind, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return
        async with self.locks[kind]:
            h = await self._ensure_handle(kind)

            blob = await asyncio.to_thread(self._encode_rows, rows)

            try:
                await h.write(blob)
            except Exception:
                # Try reopen once
                await self._close_handle(kind)
                h = await self._ensure_handle(kind)
                await h.write(blob)

            self.written_rows += len(rows)
            self.written_bytes += len(blob)
            self.sizes[kind] = self.sizes.get(kind, 0) + len(blob)

    async def _flush_kind(self, kind: Kind, buf: List[Dict[str, Any]]) -> None:
        if buf:
            await self._append(kind, buf)
            buf.clear()

    async def _flush_all(self, bufs: Dict[Kind, List[Dict[str, Any]]]) -> None:
        for k in self._KINDS:
            await self._flush_kind(k, bufs[k])

    async def _consumer(self) -> None:
        bufs: Dict[Kind, List[Dict[str, Any]]] = {k: [] for k in self._KINDS}
        last_flush = time.perf_counter()

        try:
            while True:
                # Wake either when data arrives or when it's time to flush
                timeout = max(0.0, self.tick - (time.perf_counter() - last_flush))

                try:
                    item = await asyncio.wait_for(self.q.get(), timeout=timeout)
                except asyncio.TimeoutError:
                    item = None

                if item is _STOP:
                    # Final flush and exit
                    await self._flush_all(bufs)
                    await self._close_all_handles()
                    return

                if item is None:
                    # Periodic flush tick
                    await self._flush_all(bufs)
                    last_flush = time.perf_counter()
                    continue

                # Normal record
                k, rec = item  # type: ignore[misc]
                bufs[k].append(rec)

                # Batch flush for this kind
                if self.batch > 0 and len(bufs[k]) >= self.batch:
                    await self._flush_kind(k, bufs[k])

                # Time-based flush
                now = time.perf_counter()
                if now - last_flush >= self.tick:
                    await self._flush_all(bufs)
                    last_flush = now

        except asyncio.CancelledError:
            # Best effort flush on cancellation
            try:
                await self._flush_all(bufs)
            except Exception:
                pass
            await self._close_all_handles()
            raise
