# logging_writer.py
import asyncio, orjson, time
from pathlib import Path
from typing import Dict, Any, Literal, List
import aiofiles

Kind = Literal["events","circuits","streams","paths","resources"]

class AsyncJsonlWriter:
    def __init__(self, out_dir: str, rotate_mb: int = 100, batch_size: int = 200, flush_every_ms: int = 100):
        self.out = Path(out_dir); self.out.mkdir(parents=True, exist_ok=True)
        self.rotate = rotate_mb * 1024 * 1024
        self.batch = batch_size
        self.tick = flush_every_ms / 1000.0
        self.q: "asyncio.Queue[tuple[Kind, Dict[str, Any]]]" = asyncio.Queue(100_000)
        self.task: asyncio.Task | None = None
        self.files: dict[Kind, Path] = {}
        self.sizes: dict[Kind, int] = {}
        self.locks: dict[Kind, asyncio.Lock] = {k: asyncio.Lock() for k in ["events","circuits","streams","paths","resources"]}

    def start(self):
        if not self.task:
            self.task = asyncio.create_task(self._consumer(), name="jsonl-writer")

    async def stop(self):
        if self.task:
            self.task.cancel()
            try: await self.task
            except asyncio.CancelledError: pass
            self.task = None

    def emit_nowait(self, kind: Kind, record: Dict[str, Any]):
        self.q.put_nowait((kind, record))

    def _roll(self, kind: Kind) -> Path:
        (self.out / kind).mkdir(parents=True, exist_ok=True)
        return (self.out / kind / f"{kind}-{int(time.time())}.jsonl")

    async def _append(self, kind: Kind, rows: List[Dict[str, Any]]):
        async with self.locks[kind]:
            p = self.files.get(kind)
            if p is None: p = self._roll(kind)
            size = self.sizes.get(kind, 0)
            if p.exists() and p.stat().st_size >= self.rotate:
                p = self._roll(kind); size = 0
            blob = b"".join(orjson.dumps(r) + b"\n" for r in rows)
            async with aiofiles.open(p, "ab") as f:
                await f.write(blob)
            self.files[kind] = p; self.sizes[kind] = size + len(blob)

    async def _consumer(self):
        bufs: dict[Kind, List[Dict[str, Any]]] = {k: [] for k in ["events","circuits","streams","paths","resources"]}
        last = time.perf_counter()
        while True:
            try:
                k, rec = await asyncio.wait_for(self.q.get(), timeout=self.tick)
                bufs[k].append(rec)
            except asyncio.TimeoutError:
                pass
            now = time.perf_counter()
            if now - last >= self.tick:
                for k, buf in list(bufs.items()):
                    if buf:
                        await self._append(k, buf[:]); bufs[k].clear()
                last = now
