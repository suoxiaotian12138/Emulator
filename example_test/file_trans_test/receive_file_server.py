"""
Async file receiver for one-file-per-stream transmission.

Protocol modes:
1) Raw mode:
   - Each TCP connection/stream is treated as one file.
   - The server writes all received bytes to a generated filename.
   - Verification is done out-of-band by comparing SHA256 hashes.

2) Header mode, recommended:
   - The client sends one JSON line before file bytes.
   - Header example:
     {"name":"a.txt","size":123,"sha256":"..."}\n
   - The server reads exactly `size` bytes after the header.
   - The server verifies received size and SHA256 automatically.

Environment variables:
    HOST=0.0.0.0
    PORT=8000
    OUTPUT_DIR=received_files
    CHUNK_KB=32
    EXPECT_HEADER=1
    MAX_HEADER_BYTES=8192
"""

import asyncio
import hashlib
import json
import os
import re
import struct
import sys
import threading
import time
import zlib
from pathlib import Path
from typing import Callable, Optional, Tuple


def _env_int(key: str, default: int) -> int:
    value = os.environ.get(key)
    return default if value is None else int(value)


def _env_str(key: str, default: str) -> str:
    value = os.environ.get(key)
    return default if value is None else value


def _env_bool(key: str, default: bool) -> bool:
    value = os.environ.get(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _safe_filename(name: str) -> str:
    """Keep only a safe basename to avoid path traversal and invalid filenames."""
    base = Path(name).name
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    return base or "unnamed.bin"


def _unique_path(output_dir: Path, filename: str) -> Path:
    """Return a non-existing path under output_dir."""
    filename = _safe_filename(filename)
    path = output_dir / filename
    if not path.exists():
        return path

    stem = path.stem
    suffix = path.suffix
    counter = 1
    while True:
        candidate = output_dir / f"{stem}_{counter}{suffix}"
        if not candidate.exists():
            return candidate
        counter += 1


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
STEGO_MAGIC = b"ONI-STEG-v1\0"


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
        pos += 4
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


def _load_png_pixels(path: Path) -> tuple[int, int, int, bytearray]:
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
    return width, height, channels, _png_unfilter(raw, width, height, channels)


def _bytes_from_lsb(pixels: bytearray, channels: int):
    value = 0
    bit_count = 0
    for offset in range(0, len(pixels), channels):
        for channel in range(3):
            value = (value << 1) | (pixels[offset + channel] & 1)
            bit_count += 1
            if bit_count == 8:
                yield value
                value = 0
                bit_count = 0


def _take_lsb_bytes(stream, count: int) -> bytes:
    out = bytearray()
    for _ in range(count):
        try:
            out.append(next(stream))
        except StopIteration as exc:
            raise ValueError("image ended before the hidden data was complete") from exc
    return bytes(out)


def extract_message_from_png(path: Path) -> str:
    width, height, channels, pixels = _load_png_pixels(path)
    stream = _bytes_from_lsb(pixels, channels)
    header_len = len(STEGO_MAGIC) + 4

    header = _take_lsb_bytes(stream, header_len)

    if not header.startswith(STEGO_MAGIC):
        raise ValueError("no supported hidden message was found")

    msg_len = struct.unpack(">I", header[len(STEGO_MAGIC):])[0]
    max_len = max(0, (width * height * 3) // 8 - header_len)
    if msg_len > max_len:
        raise ValueError("hidden message length is invalid for this image")

    msg = _take_lsb_bytes(stream, msg_len)

    return msg.decode("utf-8")


def _generated_filename(peer: Tuple[str, int]) -> str:
    ts_ns = time.time_ns()
    host, port = peer
    safe_host = host.replace(":", "_").replace(".", "_")
    return f"stream_{ts_ns}_{safe_host}_{port}.bin"


async def _read_header(reader: asyncio.StreamReader, max_header_bytes: int) -> dict:
    """Read one JSON header line."""
    line = await reader.readline()
    if not line:
        raise EOFError("connection closed before header")
    if len(line) > max_header_bytes:
        raise ValueError(f"header too large: {len(line)} bytes")

    try:
        header = json.loads(line.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid JSON header: {exc}") from exc

    if not isinstance(header, dict):
        raise ValueError("header must be a JSON object")

    size = header.get("size")
    if not isinstance(size, int) or size < 0:
        raise ValueError("header.size must be a non-negative integer")

    name = header.get("name", header.get("filename", "unnamed.bin"))
    if not isinstance(name, str):
        raise ValueError("header.name/header.filename must be a string")
    header["name"] = name

    sha256 = header.get("sha256")
    if sha256 is not None:
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
            raise ValueError("header.sha256 must be a 64-character hex string")
        header["sha256"] = sha256.lower()

    return header


async def _receive_raw(
    reader: asyncio.StreamReader,
    output_path: Path,
    chunk_bytes: int,
) -> tuple[int, str]:
    """Receive until EOF and write all bytes to output_path."""
    sha = hashlib.sha256()
    total = 0

    with output_path.open("wb") as f:
        while True:
            chunk = await reader.read(chunk_bytes)
            if not chunk:
                break
            f.write(chunk)
            sha.update(chunk)
            total += len(chunk)

    return total, sha.hexdigest()


async def _receive_exact_file(
    reader: asyncio.StreamReader,
    output_path: Path,
    expected_size: int,
    chunk_bytes: int,
) -> tuple[int, str]:
    """Receive exactly expected_size bytes and write them to output_path."""
    sha = hashlib.sha256()
    total = 0
    remaining = expected_size

    with output_path.open("wb") as f:
        while remaining > 0:
            n = min(chunk_bytes, remaining)
            chunk = await reader.read(n)
            if not chunk:
                raise EOFError(f"connection closed early: received={total}, expected={expected_size}")
            f.write(chunk)
            sha.update(chunk)
            total += len(chunk)
            remaining -= len(chunk)

    return total, sha.hexdigest()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    output_dir: Path,
    chunk_bytes: int,
    expect_header: bool,
    max_header_bytes: int,
    on_received: Optional[Callable[[dict], None]] = None,
) -> None:
    peer = writer.get_extra_info("peername") or ("unknown", 0)

    try:
        if expect_header:
            header = await _read_header(reader, max_header_bytes=max_header_bytes)
            filename = _safe_filename(header.get("name", "unnamed.bin"))
            expected_size = int(header["size"])
            expected_sha256: Optional[str] = header.get("sha256")

            output_path = _unique_path(output_dir, filename)
            received_size, actual_sha256 = await _receive_exact_file(
                reader=reader,
                output_path=output_path,
                expected_size=expected_size,
                chunk_bytes=chunk_bytes,
            )

            size_ok = received_size == expected_size
            hash_ok = expected_sha256 is None or actual_sha256 == expected_sha256
            verified = size_ok and hash_ok

            result = {
                "peer": f"{peer[0]}:{peer[1]}",
                "path": str(output_path),
                "name": filename,
                "header": header,
                "received_size": received_size,
                "expected_size": expected_size,
                "actual_sha256": actual_sha256,
                "expected_sha256": expected_sha256,
                "size_ok": size_ok,
                "hash_ok": hash_ok,
                "verified": verified,
            }
            print(json.dumps(result, ensure_ascii=False))
            if on_received is not None:
                on_received(result)

        else:
            output_path = _unique_path(output_dir, _generated_filename(peer))
            received_size, actual_sha256 = await _receive_raw(
                reader=reader,
                output_path=output_path,
                chunk_bytes=chunk_bytes,
            )

            result = {
                "peer": f"{peer[0]}:{peer[1]}",
                "path": str(output_path),
                "name": output_path.name,
                "header": None,
                "received_size": received_size,
                "actual_sha256": actual_sha256,
                "verified": None,
                "note": "raw mode: compare this SHA256 with the sender-side file SHA256",
            }
            print(json.dumps(result, ensure_ascii=False))
            if on_received is not None:
                on_received(result)

    except Exception as exc:
        error_path = output_dir / "receive_errors.jsonl"
        record = {
            "peer": f"{peer[0]}:{peer[1]}" if isinstance(peer, tuple) else str(peer),
            "error": repr(exc),
            "time": time.time(),
        }
        with error_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"[Receiver] error from {peer}: {exc!r}")

    finally:
        writer.close()
        with contextlib_suppress():
            await writer.wait_closed()


class contextlib_suppress:
    """Small async-compatible suppress helper to avoid importing contextlib for one use."""
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return True


async def run_receive_server(on_received: Optional[Callable[[dict], None]] = None) -> None:
    host = _env_str("HOST", "192.168.66.243")
    port = _env_int("PORT", 8000)
    output_dir = Path(_env_str("OUTPUT_DIR", "received_files"))
    chunk_kb = _env_int("CHUNK_KB", 32)
    expect_header = _env_bool("EXPECT_HEADER", True)
    max_header_bytes = _env_int("MAX_HEADER_BYTES", 8192)

    output_dir.mkdir(parents=True, exist_ok=True)
    chunk_bytes = max(1, chunk_kb) * 1024

    server = await asyncio.start_server(
        lambda reader, writer: handle_client(
            reader=reader,
            writer=writer,
            output_dir=output_dir,
            chunk_bytes=chunk_bytes,
            expect_header=expect_header,
            max_header_bytes=max_header_bytes,
            on_received=on_received,
        ),
        host=host,
        port=port,
    )

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    print(f"[Receiver] listening on {addrs}")
    print(f"[Receiver] output_dir={output_dir.resolve()}")
    print(f"[Receiver] expect_header={expect_header}")

    async with server:
        await server.serve_forever()


async def main() -> None:
    await run_receive_server()


def run_receiver_chat_gui() -> None:
    import queue
    import tkinter as tk
    from tkinter import messagebox, ttk

    received_queue: queue.Queue[dict] = queue.Queue()
    loop = asyncio.new_event_loop()

    def server_worker() -> None:
        asyncio.set_event_loop(loop)
        task = loop.create_task(run_receive_server(received_queue.put))
        try:
            loop.run_forever()
        finally:
            task.cancel()
            with contextlib_suppress():
                loop.run_until_complete(task)
            loop.close()

    thread = threading.Thread(target=server_worker, name="stego-receiver-server", daemon=True)
    thread.start()

    root = tk.Tk()
    root.title("Stego Chat Receiver")
    root.geometry("820x560")

    results: list[dict] = []
    status_var = tk.StringVar(value="receiver starting ...")

    frame = ttk.Frame(root, padding=12)
    frame.pack(fill=tk.BOTH, expand=True)

    top = ttk.Frame(frame)
    top.pack(fill=tk.BOTH, expand=True)

    list_frame = ttk.Frame(top)
    list_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    ttk.Label(list_frame, text="Received images").pack(anchor=tk.W)
    listbox = tk.Listbox(list_frame, activestyle="dotbox")
    listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    listbox.configure(yscrollcommand=scrollbar.set)

    message_frame = ttk.Frame(top)
    message_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 0))
    ttk.Label(message_frame, text="Recovered message").pack(anchor=tk.W)
    message_box = tk.Text(message_frame, wrap=tk.WORD)
    message_box.pack(fill=tk.BOTH, expand=True)

    def show_message(text: str) -> None:
        message_box.delete("1.0", tk.END)
        message_box.insert(tk.END, text)

    def selected_result() -> Optional[dict]:
        selection = listbox.curselection()
        if not selection:
            return None
        return results[selection[0]]

    def extract_selected() -> None:
        item = selected_result()
        if item is None:
            messagebox.showinfo("No image selected", "Select a received image first.")
            return
        try:
            text = extract_message_from_png(Path(item["path"]))
        except Exception as exc:
            messagebox.showerror("Extract failed", repr(exc))
            status_var.set(f"extract failed: {exc!r}")
            return
        show_message(text)
        status_var.set(f"recovered message from {Path(item['path']).name}")

    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Extract Hidden Message", command=extract_selected)

    def show_context_menu(event) -> None:
        index = listbox.nearest(event.y)
        if index >= 0:
            listbox.selection_clear(0, tk.END)
            listbox.selection_set(index)
            listbox.activate(index)
        menu.tk_popup(event.x_root, event.y_root)

    listbox.bind("<Button-3>", show_context_menu)
    listbox.bind("<Double-Button-1>", lambda _event: extract_selected())

    bottom = ttk.Frame(frame)
    bottom.pack(fill=tk.X, pady=(12, 0))
    ttk.Label(bottom, textvariable=status_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
    ttk.Button(bottom, text="Extract", command=extract_selected).pack(side=tk.RIGHT)

    def poll_received() -> None:
        while True:
            try:
                result = received_queue.get_nowait()
            except queue.Empty:
                break

            results.append(result)
            path = Path(result["path"])
            verified = result.get("verified")
            prefix = "OK" if verified else "UNVERIFIED"
            listbox.insert(tk.END, f"{prefix}  {path.name}  ({result.get('received_size', 0)} bytes)")
            status_var.set(f"received {path.name}")

        root.after(200, poll_received)

    def on_close() -> None:
        with contextlib_suppress():
            loop.call_soon_threadsafe(loop.stop)
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    poll_received()
    root.mainloop()


if __name__ == "__main__":
    # if "--chat-gui" in sys.argv or "--receiver-gui" in sys.argv or _env_bool("RECEIVER_GUI", False):
    #     run_receiver_chat_gui()
    # else:
    #     asyncio.run(main())
    run_receiver_chat_gui()
