"""
Multi-user, multi-circuit, file-stream test runner.

Behavior:
1) Build clients and circuits once.
2) Scan a local input directory for text/image files.
3) Each detected file is sent through one independent Tor stream.
4) A file stream is fully sent and closed before the next file stream starts.
"""

import random
import asyncio
import binascii
import concurrent.futures
import contextlib
import hashlib
import json
import os
import sys
import struct
import threading
import time
import zlib
from pathlib import Path

from tools.Log.writer import AsyncJsonlWriter
from network_src.TorCore.Tor_Client import Tor_Client
from network_src.TorCore.Tor_Circuit import compute_isolation_key
from tools.Log.bus import EventBus

REALISTIC_DEFAULTS = {
    "USERS": "1",
    "CIRCUITS_PER_USER": "1",
    "LOG_DIR": "exp/e2/tor",
    "EXP_LABEL": "file-stream",

    # Local input directory. Files in this directory will be sent to the server.
    "INPUT_DIR": "input",

    # Supported file extensions. Empty value means all regular files.
    "INPUT_FILE_EXTENSIONS": ".txt,.text,.md,.png,.jpg,.jpeg,.gif,.bmp,.webp",

    # If 0, send the current snapshot and exit.
    # If 1, keep watching the directory until RUN_DURATION_S expires.
    "FOLLOW_INPUT_DIR": "0",
    "RUN_DURATION_S": "300",
    "SCAN_INTERVAL_S": "1.0",

    # Avoid reading files that are still being written.
    "FILE_STABLE_S": "0.5",

    # Delete a file after it is successfully sent.
    "DELETE_AFTER_SEND": "0",

    # Optional metadata header at the beginning of each stream.
    # Keep disabled unless the server has matching parsing logic.
    "SEND_FILE_HEADER": "1",

    # Stream sending controls.
    "CHUNK_KB": "32",
    "WARMUP_KB": "0",
    "INTER_CHUNK_SLEEP_MS": "0",
    "START_TIMEOUT_S": "30",
    "WAIT_INTERVAL_RANGE_S": "0.0,0.0",
}


def ensure_seed() -> int:
    seed_env = os.environ.get("RANDOM_SEED")
    if seed_env is None:
        seed_env = str(int(time.time()))
        os.environ["RANDOM_SEED"] = seed_env
    seed = int(seed_env)
    random.seed(seed)
    return seed


def build_writer(log_dir: str) -> AsyncJsonlWriter:
    writer = AsyncJsonlWriter(out_dir=log_dir, rotate_mb=50, batch_size=200, flush_every_ms=100)
    writer.start()
    return writer


for key, value in REALISTIC_DEFAULTS.items():
    os.environ.setdefault(key, value)


if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)


def _env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


def _env_float(key: str, default: float) -> float:
    v = os.environ.get(key)
    return default if v is None else float(v)


def _env_bool(key: str, default: bool = False) -> bool:
    v = os.environ.get(key)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_wait_range_s(value: str, default_min: float = 0.0, default_max: float = 0.0) -> tuple[float, float]:
    """
    Parse "a,b" into (min_s, max_s). Accept whitespace. If invalid, fallback to defaults.
    """
    if not value:
        return (default_min, default_max)
    parts = [p.strip() for p in value.split(",") if p.strip()]
    if len(parts) != 2:
        return (default_min, default_max)
    try:
        a = float(parts[0])
        b = float(parts[1])
        lo = min(a, b)
        hi = max(a, b)
        if lo < 0:
            lo = 0.0
        if hi < 0:
            hi = 0.0
        return (lo, hi)
    except Exception:
        return (default_min, default_max)


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
STEGO_MAGIC = b"ONI-STEG-v1\0"


def _sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def _safe_local_filename(name: str) -> str:
    keep = []
    for ch in Path(name).name:
        if ch.isalnum() or ch in {".", "_", "-"}:
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep).strip("._") or "image"


def _png_chunk(ctype: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(ctype)
    crc = binascii.crc32(payload, crc) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)


def _read_png_chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("only PNG images are supported for steganography")

    chunks: list[tuple[bytes, bytes]] = []
    pos = len(PNG_SIGNATURE)
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        ctype = data[pos:pos + 4]
        pos += 4
        payload = data[pos:pos + length]
        pos += length
        pos += 4  # CRC
        if len(ctype) != 4 or len(payload) != length:
            raise ValueError("truncated PNG chunk")
        chunks.append((ctype, payload))
        if ctype == b"IEND":
            break

    return chunks


def _png_channels(color_type: int) -> int:
    if color_type == 2:
        return 3
    if color_type == 6:
        return 4
    raise ValueError("only 8-bit RGB/RGBA PNG images are supported")


def _paeth_predictor(left: int, up: int, up_left: int) -> int:
    p = left + up - up_left
    pa = abs(p - left)
    pb = abs(p - up)
    pc = abs(p - up_left)
    if pa <= pb and pa <= pc:
        return left
    if pb <= pc:
        return up
    return up_left


def _png_unfilter(raw: bytes, width: int, height: int, channels: int) -> bytearray:
    row_len = width * channels
    bpp = channels
    rows = bytearray()
    prev = bytearray(row_len)
    pos = 0

    for _ in range(height):
        if pos >= len(raw):
            raise ValueError("PNG image data ended early")
        ftype = raw[pos]
        pos += 1
        row = bytearray(raw[pos:pos + row_len])
        pos += row_len
        if len(row) != row_len:
            raise ValueError("truncated PNG scanline")

        for i in range(row_len):
            left = row[i - bpp] if i >= bpp else 0
            up = prev[i]
            up_left = prev[i - bpp] if i >= bpp else 0
            if ftype == 0:
                pass
            elif ftype == 1:
                row[i] = (row[i] + left) & 0xFF
            elif ftype == 2:
                row[i] = (row[i] + up) & 0xFF
            elif ftype == 3:
                row[i] = (row[i] + ((left + up) // 2)) & 0xFF
            elif ftype == 4:
                row[i] = (row[i] + _paeth_predictor(left, up, up_left)) & 0xFF
            else:
                raise ValueError(f"unsupported PNG filter type: {ftype}")

        rows.extend(row)
        prev = row

    return rows


def _png_filter_none(pixels: bytes, width: int, height: int, channels: int) -> bytes:
    row_len = width * channels
    raw = bytearray()
    for row_index in range(height):
        start = row_index * row_len
        end = start + row_len
        raw.append(0)
        raw.extend(pixels[start:end])
    return bytes(raw)


def _load_png_pixels(path: Path) -> tuple[list[tuple[bytes, bytes]], int, int, int, bytearray]:
    data = path.read_bytes()
    chunks = _read_png_chunks(data)
    ihdr = next((payload for ctype, payload in chunks if ctype == b"IHDR"), None)
    if ihdr is None or len(ihdr) != 13:
        raise ValueError("invalid PNG: missing IHDR")

    width, height, bit_depth, color_type, compression, filter_method, interlace = struct.unpack(">IIBBBBB", ihdr)
    if bit_depth != 8 or compression != 0 or filter_method != 0 or interlace != 0:
        raise ValueError("only non-interlaced 8-bit PNG images are supported")

    channels = _png_channels(color_type)
    idat = b"".join(payload for ctype, payload in chunks if ctype == b"IDAT")
    if not idat:
        raise ValueError("invalid PNG: missing IDAT")

    raw = zlib.decompress(idat)
    pixels = _png_unfilter(raw, width, height, channels)
    return chunks, width, height, channels, pixels


def _write_png_pixels(
    path: Path,
    chunks: list[tuple[bytes, bytes]],
    width: int,
    height: int,
    channels: int,
    pixels: bytes,
) -> None:
    raw = _png_filter_none(pixels, width, height, channels)
    compressed = zlib.compress(raw, level=6)

    out = bytearray(PNG_SIGNATURE)
    wrote_idat = False
    for ctype, payload in chunks:
        if ctype == b"IDAT":
            if not wrote_idat:
                out.extend(_png_chunk(b"IDAT", compressed))
                wrote_idat = True
            continue
        if ctype == b"IEND" and not wrote_idat:
            out.extend(_png_chunk(b"IDAT", compressed))
            wrote_idat = True
        out.extend(_png_chunk(ctype, payload))

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(out))


def embed_message_in_png(source_path: Path, message: str, output_path: Path) -> Path:
    msg = message.encode("utf-8")
    payload = STEGO_MAGIC + struct.pack(">I", len(msg)) + msg
    chunks, width, height, channels, pixels = _load_png_pixels(source_path)

    capacity_bits = width * height * 3
    needed_bits = len(payload) * 8
    if needed_bits > capacity_bits:
        capacity_bytes = max(0, capacity_bits // 8 - len(STEGO_MAGIC) - 4)
        raise ValueError(f"message too large for this image; capacity is about {capacity_bytes} UTF-8 bytes")

    bit_index = 0
    for offset in range(0, len(pixels), channels):
        for channel in range(3):
            if bit_index >= needed_bits:
                break
            bit = (payload[bit_index // 8] >> (7 - (bit_index % 8))) & 1
            pixels[offset + channel] = (pixels[offset + channel] & 0xFE) | bit
            bit_index += 1
        if bit_index >= needed_bits:
            break

    _write_png_pixels(output_path, chunks, width, height, channels, pixels)
    return output_path


async def _open_stream_on_circuit(client: Tor_Client, circuit, addr):
    await client.ready_to_send.wait()

    socket = client.socket_map.get(client.guard.addr, None)
    if socket is None:
        raise RuntimeError("no socket to guard")

    stream = circuit.create_stream()
    stream_id = stream.id
    stream_uid = f"{client.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
    dst = f"{addr[0]}:{addr[1]}"
    client.stream_tracker.start(stream_uid, src=client.name, dst=dst)

    if stream_id is not None:
        client._sid2uid[stream_id] = stream_uid

    try:
        connect_cell = stream.make_connect(addr)
        await socket.send_cell(connect_cell)
        await stream.wait_connect_ack()
        client.stream_tracker.mark_connected(stream_uid)
    except Exception:
        client.stream_tracker.set_status(stream_uid, "connect_fail")
        rec = client.stream_tracker.end(stream_uid)
        client._stream(**rec) if rec else None
        raise

    return stream


async def _build_user_circuits_once(
    client: Tor_Client,
    addr,
    hop: int,
    circuits_per_user: int,
    start_timeout_s: int,
):
    await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

    if client.circuit_mgr.isolation_enabled:
        isolation_key = compute_isolation_key(addr[0], addr[1])
    else:
        isolation_key = "general"

    circuits = []
    for _ in range(circuits_per_user):
        circuit = await client.circuit_mgr.get_or_build(
            isolation_key,
            hops_count=hop,
            prefer_new=True,  # only at bootstrap
        )
        circuits.append(circuit)

    return circuits



def _parse_extensions(value: str) -> set[str]:
    """
    Parse ".txt,.png" into a lowercase extension set.
    Empty value means all regular files are allowed.
    """
    if not value.strip():
        return set()

    exts = set()
    for item in value.split(","):
        item = item.strip().lower()
        if not item:
            continue
        if not item.startswith("."):
            item = "." + item
        exts.add(item)
    return exts


def _list_candidate_files(input_dir: Path, allowed_exts: set[str]) -> list[Path]:
    """
    Return candidate files in a stable order.
    This function only scans the top-level directory. Use rglob if recursive scan is needed.
    """
    if not input_dir.exists():
        raise FileNotFoundError(f"input directory does not exist: {input_dir}")

    files = []
    for path in input_dir.iterdir():
        if not path.is_file():
            continue
        if path.name.startswith("."):
            continue
        if allowed_exts and path.suffix.lower() not in allowed_exts:
            continue
        files.append(path)

    return sorted(files, key=lambda p: (p.stat().st_mtime, p.name))


def _is_file_stable(path: Path, stable_s: float) -> bool:
    """
    Avoid sending a file that is still being copied into the input directory.
    """
    if stable_s <= 0:
        return True
    try:
        return (time.time() - path.stat().st_mtime) >= stable_s
    except FileNotFoundError:
        return False


async def _send_file_payload(
    client: Tor_Client,
    circuit,
    stream,
    file_path: Path,
    chunk_kb: int,
    warmup_kb: int,
    inter_chunk_sleep_ms: int,
    send_file_header: bool,
    header_extra: dict | None = None,
):
    """
    Send one local file through one stream.

    By default, only raw file bytes are sent. If SEND_FILE_HEADER=1, a JSON header
    line is sent before the file body. The server must explicitly support that mode.
    """
    if warmup_kb > 0:
        warmup = b"W" * (warmup_kb * 1024)
        await client.stream_write(circuit, stream, warmup)

    if send_file_header:
        st = file_path.stat()
        header = {
            "type": "file",
            "name": file_path.name,
            "filename": file_path.name,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "sha256": _sha256_file(file_path),
        }
        if header_extra:
            header.update(header_extra)
        header_bytes = (json.dumps(header, ensure_ascii=False) + "\n").encode("utf-8")
        await client.stream_write(circuit, stream, header_bytes)

    chunk_bytes = chunk_kb * 1024
    if chunk_bytes <= 0:
        raise ValueError("CHUNK_KB must be greater than 0")

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_bytes)
            if not chunk:
                break

            await client.stream_write(circuit, stream, chunk)

            if inter_chunk_sleep_ms > 0:
                await asyncio.sleep(inter_chunk_sleep_ms / 1000)


async def _one_file_stream(
    *,
    client: Tor_Client,
    addr,
    circuits,
    file_path: Path,
    chunk_kb: int,
    warmup_kb: int,
    start_timeout_s: int,
    inter_chunk_sleep_ms: int,
    wait_min_s: float,
    wait_max_s: float,
    send_file_header: bool,
    header_extra: dict | None = None,
):
    """
    One file equals one stream connect + file send + stream close.
    """
    await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

    if wait_max_s > 0 or wait_min_s > 0:
        delay = random.uniform(wait_min_s, wait_max_s)
        if delay > 0:
            await asyncio.sleep(delay)

    circuit = random.choice(circuits)
    client.circuit_mgr.mark_used(circuit)

    stream = await _open_stream_on_circuit(client, circuit, addr)
    try:
        print(f"[FileStream] sending {file_path} via {client.name}, circuit={circuit.id}, stream={stream.id}")
        await _send_file_payload(
            client,
            circuit,
            stream,
            file_path=file_path,
            chunk_kb=chunk_kb,
            warmup_kb=warmup_kb,
            inter_chunk_sleep_ms=inter_chunk_sleep_ms,
            send_file_header=send_file_header,
            header_extra=header_extra,
        )
        print(f"[FileStream] sent {file_path}")
    finally:
        with contextlib.suppress(Exception):
            await client.close_stream(circuit, stream)


async def _run_files_sequential(
    *,
    clients: list[Tor_Client],
    addr,
    client_circuits: dict,
    input_dir: Path,
    allowed_exts: set[str],
    chunk_kb: int,
    warmup_kb: int,
    start_timeout_s: int,
    inter_chunk_sleep_ms: int,
    wait_min_s: float,
    wait_max_s: float,
    follow_input_dir: bool,
    run_duration_s: int,
    scan_interval_s: float,
    file_stable_s: float,
    delete_after_send: bool,
    send_file_header: bool,
):
    """
    Scan input_dir and send each file sequentially.

    Even with multiple clients, this function awaits each file stream before scheduling
    the next one, so global file sending remains one stream at a time. When multiple
    clients exist, files are assigned round-robin.
    """
    if not clients:
        return

    for client in clients:
        await asyncio.wait_for(client.ready_to_send.wait(), timeout=start_timeout_s)

    sent_or_seen: set[str] = set()
    next_client_index = 0
    end_ts = time.time() + run_duration_s

    while True:
        if follow_input_dir and time.time() >= end_ts:
            break

        candidates = _list_candidate_files(input_dir, allowed_exts)
        pending = []
        for file_path in candidates:
            key = str(file_path.resolve())
            if key in sent_or_seen:
                continue
            if not _is_file_stable(file_path, file_stable_s):
                continue
            pending.append(file_path)

        if not pending:
            if follow_input_dir:
                await asyncio.sleep(max(scan_interval_s, 0.1))
                continue
            break

        for file_path in pending:
            key = str(file_path.resolve())
            if key in sent_or_seen:
                continue

            client = clients[next_client_index % len(clients)]
            next_client_index += 1

            await _one_file_stream(
                client=client,
                addr=addr,
                circuits=client_circuits[client],
                file_path=file_path,
                chunk_kb=chunk_kb,
                warmup_kb=warmup_kb,
                start_timeout_s=start_timeout_s,
                inter_chunk_sleep_ms=inter_chunk_sleep_ms,
                wait_min_s=wait_min_s,
                wait_max_s=wait_max_s,
                send_file_header=send_file_header,
            )

            sent_or_seen.add(key)

            if delete_after_send:
                with contextlib.suppress(FileNotFoundError):
                    file_path.unlink()

        if not follow_input_dir:
            break

    print(f"[FileStream] completed, files_sent={len(sent_or_seen)}")


class AsyncChatSender:
    """
    Keeps Tor clients/circuits alive in a background asyncio loop and opens a new
    stream each time the GUI sends a stego image.
    """

    def __init__(self, status_callback=None):
        self.status_callback = status_callback or (lambda _msg: None)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, name="chat-sender-asyncio", daemon=True)
        self.ready = threading.Event()
        self.clients: list[Tor_Client] = []
        self.protocol_tasks: list[asyncio.Task] = []
        self.client_circuits: dict = {}
        self.writer: AsyncJsonlWriter | None = None
        self.addr = None
        self.config = {}

    def _status(self, msg: str) -> None:
        self.status_callback(msg)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def start(self):
        self.thread.start()
        return asyncio.run_coroutine_threadsafe(self._start_async(), self.loop)

    async def _start_async(self) -> None:
        loop = asyncio.get_running_loop()
        log_dir = _env_str("LOG_DIR", "exp/e2")
        seed = ensure_seed()

        log_dir_path = Path(log_dir)
        log_dir_path.mkdir(parents=True, exist_ok=True)
        self.writer = build_writer(log_dir)

        def bus_factory(node_name: str) -> EventBus:
            return EventBus(self.writer.emit_nowait, node_id=node_name, role="client")

        max_workers = _env_int("MAX_TLS_THREADS", 128)
        loop.set_default_executor(
            concurrent.futures.ThreadPoolExecutor(
                max_workers=max_workers,
                thread_name_prefix="tls-worker",
            )
        )

        directory_addr = _env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
        os.environ["DIRECTORY_ADDR"] = directory_addr

        node_addr = _env_str("NODE_ADDR", "192.168.66.242")
        hop = _env_int("HOPS", 3)
        target_host = _env_str("TARGET_HOST", "192.168.66.243")
        target_port = _env_int("TARGET_PORT", 8000)
        self.addr = (target_host, target_port)
        users = _env_int("USERS", 1)
        circuits_per_user = _env_int("CIRCUITS_PER_USER", 1)
        start_timeout_s = _env_int("START_TIMEOUT_S", 30)

        self.config = {
            "seed": seed,
            "log_dir": str(log_dir_path.resolve()),
            "node_addr": node_addr,
            "addr": self.addr,
            "hop": hop,
            "start_timeout_s": start_timeout_s,
            "chunk_kb": _env_int("CHUNK_KB", 32),
            "warmup_kb": _env_int("WARMUP_KB", 0),
            "inter_chunk_sleep_ms": _env_int("INTER_CHUNK_SLEEP_MS", 0),
        }

        self._status(f"connecting to target {self.addr[0]}:{self.addr[1]} ...")
        for user_index in range(users):
            name = f"user{user_index}"
            port = 9102 + user_index
            client = Tor_Client(name=name, host=node_addr, port=port, model="sim")
            client.attach_bus(bus_factory(name))
            client.emit = client.event_bus.emit
            self.clients.append(client)
            self.protocol_tasks.append(asyncio.create_task(client.start_protocol()))

        for client in self.clients:
            self.client_circuits[client] = await _build_user_circuits_once(
                client=client,
                addr=self.addr,
                hop=hop,
                circuits_per_user=circuits_per_user,
                start_timeout_s=start_timeout_s,
            )

        self.ready.set()
        self._status("sender ready")

    async def _embed_and_send(self, source_path: str, hidden_message: str) -> Path:
        if not self.ready.is_set():
            raise RuntimeError("sender is not ready yet")
        if not self.clients:
            raise RuntimeError("no sender clients are available")

        source = Path(source_path)
        outbox = Path(_env_str("CHAT_OUTBOX_DIR", "chat_outbox"))
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        stem = _safe_local_filename(source.stem)
        output_path = outbox / f"{timestamp}_{int(time.time() * 1000) % 1000:03d}_{stem}_stego.png"

        embed_message_in_png(source, hidden_message, output_path)
        client = random.choice(self.clients)
        header_extra = {
            "kind": "stego_image",
            "embedded_message": True,
            "original_name": source.name,
        }
        await _one_file_stream(
            client=client,
            addr=self.addr,
            circuits=self.client_circuits[client],
            file_path=output_path,
            chunk_kb=self.config["chunk_kb"],
            warmup_kb=self.config["warmup_kb"],
            start_timeout_s=self.config["start_timeout_s"],
            inter_chunk_sleep_ms=self.config["inter_chunk_sleep_ms"],
            wait_min_s=0.0,
            wait_max_s=0.0,
            send_file_header=True,
            header_extra=header_extra,
        )
        self._status(f"sent {output_path.name}")
        return output_path

    def send_image(self, source_path: str, hidden_message: str):
        return asyncio.run_coroutine_threadsafe(
            self._embed_and_send(source_path, hidden_message),
            self.loop,
        )

    async def _close_async(self) -> None:
        for client in self.clients:
            for circuit in self.client_circuits.get(client, []):
                with contextlib.suppress(Exception):
                    if hasattr(client, "close_circuit"):
                        await client.close_circuit(circuit)

        for client in self.clients:
            with contextlib.suppress(Exception):
                await client.stop_protocol()

        for task in self.protocol_tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        if self.writer is not None:
            await self.writer.stop()

    def stop(self) -> None:
        if not self.loop.is_running():
            return
        future = asyncio.run_coroutine_threadsafe(self._close_async(), self.loop)
        with contextlib.suppress(Exception):
            future.result(timeout=10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(timeout=10)


def run_sender_chat_gui() -> None:
    import queue
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    status_queue: queue.Queue[str] = queue.Queue()
    sender = AsyncChatSender(status_queue.put)

    root = tk.Tk()
    root.title("Stego Chat Sender")
    root.geometry("720x520")

    image_var = tk.StringVar()
    status_var = tk.StringVar(value="starting sender ...")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill=tk.BOTH, expand=True)

    path_row = ttk.Frame(frame)
    path_row.pack(fill=tk.X)
    ttk.Entry(path_row, textvariable=image_var).pack(side=tk.LEFT, fill=tk.X, expand=True)

    def choose_image() -> None:
        path = filedialog.askopenfilename(
            title="Choose a PNG image",
            filetypes=[("PNG images", "*.png"), ("All files", "*.*")],
        )
        if path:
            image_var.set(path)

    ttk.Button(path_row, text="Choose Image", command=choose_image).pack(side=tk.LEFT, padx=(8, 0))

    ttk.Label(frame, text="Hidden message").pack(anchor=tk.W, pady=(12, 4))
    message_box = tk.Text(frame, height=8, wrap=tk.WORD)
    message_box.pack(fill=tk.BOTH, expand=True)

    log_box = tk.Text(frame, height=9, wrap=tk.WORD, state=tk.DISABLED)
    log_box.pack(fill=tk.BOTH, expand=True, pady=(12, 0))

    def log(msg: str) -> None:
        log_box.configure(state=tk.NORMAL)
        log_box.insert(tk.END, f"{time.strftime('%H:%M:%S')}  {msg}\n")
        log_box.see(tk.END)
        log_box.configure(state=tk.DISABLED)
        status_var.set(msg)

    def poll_status() -> None:
        while True:
            try:
                log(status_queue.get_nowait())
            except queue.Empty:
                break
        root.after(200, poll_status)

    def send_now() -> None:
        image_path = image_var.get().strip()
        hidden_message = message_box.get("1.0", tk.END).strip()
        if not image_path:
            messagebox.showwarning("Missing image", "Choose a PNG image first.")
            return
        if not hidden_message:
            messagebox.showwarning("Missing message", "Type a hidden message first.")
            return

        log("embedding message and opening a stream ...")
        future = sender.send_image(image_path, hidden_message)

        def done_callback(done_future) -> None:
            try:
                output = done_future.result()
                root.after(0, lambda: log(f"sent stego image: {output}"))
                root.after(0, lambda: message_box.delete("1.0", tk.END))
            except Exception as exc:
                error = repr(exc)
                root.after(0, lambda: messagebox.showerror("Send failed", error))
                root.after(0, lambda: log(f"send failed: {error}"))

        future.add_done_callback(done_callback)

    bottom = ttk.Frame(frame)
    bottom.pack(fill=tk.X, pady=(12, 0))
    ttk.Label(bottom, textvariable=status_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
    ttk.Button(bottom, text="Send Image", command=send_now).pack(side=tk.RIGHT)

    def on_close() -> None:
        status_var.set("stopping sender ...")
        sender.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    startup_future = sender.start()

    def startup_done(done_future) -> None:
        try:
            done_future.result()
        except Exception as exc:
            error = repr(exc)
            root.after(0, lambda: messagebox.showerror("Sender failed to start", error))
            root.after(0, lambda: log(f"sender failed to start: {error}"))

    startup_future.add_done_callback(startup_done)
    poll_status()
    root.mainloop()


async def main():
    loop = asyncio.get_running_loop()
    log_dir = _env_str("LOG_DIR", "exp/e2")
    exp_label = _env_str("EXP_LABEL", "e2")
    seed = ensure_seed()

    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)

    writer = build_writer(log_dir)
    meta_path = log_dir_path / "run_meta.json"
    run_meta = {
        "started_at": time.time(),
        "exp_label": exp_label,
        "random_seed": seed,
        "log_dir": str(log_dir_path.resolve()),
    }

    def bus_factory(node_name: str) -> EventBus:
        return EventBus(writer.emit_nowait, node_id=node_name, role="client")

    max_workers = _env_int("MAX_TLS_THREADS", 128)
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker",
        )
    )

    directory_addr = _env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
    os.environ["DIRECTORY_ADDR"] = directory_addr

    node_addr = _env_str("NODE_ADDR", "192.168.66.242")

    hop = _env_int("HOPS", 3)
    target_host = _env_str("TARGET_HOST", "192.168.66.243")
    target_port = _env_int("TARGET_PORT", 8000)
    addr = (target_host, target_port)

    input_dir = Path(_env_str("INPUT_DIR", "input")).expanduser()
    allowed_exts = _parse_extensions(_env_str("INPUT_FILE_EXTENSIONS", ".txt,.png,.jpg,.jpeg"))
    follow_input_dir = _env_bool("FOLLOW_INPUT_DIR", False)
    scan_interval_s = _env_float("SCAN_INTERVAL_S", 1.0)
    file_stable_s = _env_float("FILE_STABLE_S", 0.5)
    delete_after_send = _env_bool("DELETE_AFTER_SEND", False)
    send_file_header = _env_bool("SEND_FILE_HEADER", False)

    chunk_kb = _env_int("CHUNK_KB", 32)
    warmup_kb = _env_int("WARMUP_KB", 0)
    start_timeout_s = _env_int("START_TIMEOUT_S", 30)
    inter_chunk_sleep_ms = _env_int("INTER_CHUNK_SLEEP_MS", 0)

    users = _env_int("USERS", 1)
    circuits_per_user = _env_int("CIRCUITS_PER_USER", 1)

    run_duration_s = _env_int("RUN_DURATION_S", 600)
    wait_range_raw = _env_str("WAIT_INTERVAL_RANGE_S", "0.0,0.0")
    wait_min_s, wait_max_s = _parse_wait_range_s(wait_range_raw, 0.0, 0.0)

    print(f"[Config] DIRECTORY_ADDR={directory_addr}")
    print(f"[Config] NODE_ADDR={node_addr}")
    print(f"[Config] users={users} circuits_per_user={circuits_per_user}")
    print(f"[Config] target={addr} hop={hop}")
    print(f"[Config] input_dir={input_dir.resolve()}")
    print(f"[Config] input_file_extensions={sorted(allowed_exts) if allowed_exts else 'ALL'}")
    print(f"[Config] follow_input_dir={follow_input_dir} run_duration_s={run_duration_s}")
    print(f"[Config] scan_interval_s={scan_interval_s} file_stable_s={file_stable_s}")
    print(f"[Config] delete_after_send={delete_after_send} send_file_header={send_file_header}")
    print(f"[Config] chunk_kb={chunk_kb} warmup_kb={warmup_kb}")
    print(f"[Config] start_timeout_s={start_timeout_s} inter_chunk_sleep_ms={inter_chunk_sleep_ms}")
    print(f"[Config] max_tls_threads={max_workers}")
    print(f"[Config] wait_interval_range_s={wait_min_s},{wait_max_s}")

    clients = []
    protocol_tasks = []
    client_circuits = {}

    try:
        # 1) Create all clients first
        for user_index in range(users):
            name = f"user{user_index}"
            port = 9102 + user_index

            client = Tor_Client(name=name, host=node_addr, port=port, model="sim")
            client.attach_bus(bus_factory(name))
            client.emit = client.event_bus.emit
            clients.append(client)
            protocol_tasks.append(asyncio.create_task(client.start_protocol()))

        # 2) Build circuits ONCE per client
        for client in clients:
            client_circuits[client] = await _build_user_circuits_once(
                client=client,
                addr=addr,
                hop=hop,
                circuits_per_user=circuits_per_user,
                start_timeout_s=start_timeout_s,
            )

        # 3) Scan local files and send them sequentially.
        await _run_files_sequential(
            clients=clients,
            addr=addr,
            client_circuits=client_circuits,
            input_dir=input_dir,
            allowed_exts=allowed_exts,
            chunk_kb=chunk_kb,
            warmup_kb=warmup_kb,
            start_timeout_s=start_timeout_s,
            inter_chunk_sleep_ms=inter_chunk_sleep_ms,
            wait_min_s=wait_min_s,
            wait_max_s=wait_max_s,
            follow_input_dir=follow_input_dir,
            run_duration_s=run_duration_s,
            scan_interval_s=scan_interval_s,
            file_stable_s=file_stable_s,
            delete_after_send=delete_after_send,
            send_file_header=send_file_header,
        )

    finally:
        # (Optional) close circuits once, safely
        for client in clients:
            for c in client_circuits.get(client, []):
                with contextlib.suppress(Exception):
                    if hasattr(client, "close_circuit"):
                        await client.close_circuit(c)

        # stop protocols
        for client in clients:
            with contextlib.suppress(Exception):
                await client.stop_protocol()

        for task in protocol_tasks:
            if not task.done():
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task

        run_meta.update(
            {
                "finished_at": time.time(),
                "config": {
                    "directory_addr": directory_addr,
                    "node_addr": node_addr,
                    "users": users,
                    "circuits_per_user": circuits_per_user,
                    "hop": hop,
                    "input_dir": str(input_dir.resolve()),
                    "input_file_extensions": sorted(allowed_exts),
                    "follow_input_dir": follow_input_dir,
                    "scan_interval_s": scan_interval_s,
                    "file_stable_s": file_stable_s,
                    "delete_after_send": delete_after_send,
                    "send_file_header": send_file_header,
                    "chunk_kb": chunk_kb,
                    "warmup_kb": warmup_kb,
                    "start_timeout_s": start_timeout_s,
                    "inter_chunk_sleep_ms": inter_chunk_sleep_ms,
                    "run_duration_s": run_duration_s,
                    "wait_interval_range_s": [wait_min_s, wait_max_s],
                },
                "log_files": {k: str(p) for k, p in writer.files.items()},
            }
        )

        meta_path.write_text(json.dumps(run_meta, indent=2), encoding="utf-8")
        await writer.stop()
        print(f"[RealisticRunner] run metadata written to {meta_path}")

    return meta_path


if __name__ == "__main__":
    # if "--chat-gui" in sys.argv or _env_bool("CHAT_GUI", False):
    #     run_sender_chat_gui()
    # else:
    #     asyncio.run(main())
    run_sender_chat_gui()

