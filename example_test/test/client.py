import random
import asyncio
import concurrent.futures
import contextlib
import json
import os
import sys
import time
import queue
import threading
import tempfile
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from PIL import Image, ImageTk

from tools.Log.writer import AsyncJsonlWriter
from network_src.TorCore.Tor_Client import Tor_Client
from network_src.TorCore.Tor_Circuit import compute_isolation_key
from tools.Log.bus import EventBus

from stego_chat import (
    IMAGE_EXTS,
    build_text_header,
    build_image_header,
    validate_chat_header,
    embed_message_in_image,
    extract_message_from_image,
    format_ts,
    unique_path,
    ensure_dir,
    open_path,
    open_folder,
    load_history,
    save_history,
    sha256_file,
)


REALISTIC_DEFAULTS = {
    "USERS": "1",
    "CIRCUITS_PER_USER": "1",
    "LOG_DIR": "exp/e2/tor",
    "EXP_LABEL": "stego-chat-bidirectional",
    "CHUNK_KB": "32",
    "WARMUP_KB": "0",
    "INTER_CHUNK_SLEEP_MS": "0",
    "START_TIMEOUT_S": "30",
    "WAIT_INTERVAL_RANGE_S": "0.0,0.0",
    "DIRECTORY_ADDR": "192.168.66.241:9030",
    "NODE_ADDR": "192.168.66.242",
    "HOPS": "3",
    "LOCAL_HOST": "0.0.0.0",
    "LOCAL_PORT": "8000",
    "REMOTE_HOST": "127.0.0.1",
    "REMOTE_PORT": "8001",
    "DISPLAY_NAME": "Alice",
    "CHAT_DATA_DIR": "chat_data",
}


for key, value in REALISTIC_DEFAULTS.items():
    os.environ.setdefault(key, value)

if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


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


def _env_int(key: str, default: int) -> int:
    v = os.environ.get(key)
    return default if v is None else int(v)


def _env_str(key: str, default: str) -> str:
    v = os.environ.get(key)
    return default if v is None else v


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


async def _build_user_circuits_once(client: Tor_Client, addr, hop: int, circuits_per_user: int, start_timeout_s: int):
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
            prefer_new=True,
        )
        circuits.append(circuit)

    return circuits


async def _send_text_payload(client: Tor_Client, circuit, stream, header):
    await client.stream_write(circuit, stream, header.to_json_line())


async def _send_image_payload(client: Tor_Client, circuit, stream, header, file_path: Path, chunk_kb: int, inter_chunk_sleep_ms: int):
    await client.stream_write(circuit, stream, header.to_json_line())
    chunk_bytes = max(1, chunk_kb) * 1024
    with file_path.open("rb") as f:
        while True:
            chunk = f.read(chunk_bytes)
            if not chunk:
                break
            await client.stream_write(circuit, stream, chunk)
            if inter_chunk_sleep_ms > 0:
                await asyncio.sleep(inter_chunk_sleep_ms / 1000)


async def _read_header(reader: asyncio.StreamReader, max_header_bytes: int) -> dict:
    line = await reader.readline()
    if not line:
        raise EOFError("connection closed before header")
    if len(line) > max_header_bytes:
        raise ValueError(f"header too large: {len(line)} bytes")
    return json.loads(line.decode("utf-8"))


async def _receive_exact_file(reader: asyncio.StreamReader, output_path: Path, expected_size: int, chunk_bytes: int):
    total = 0
    remaining = expected_size
    with output_path.open("wb") as f:
        while remaining > 0:
            n = min(chunk_bytes, remaining)
            chunk = await reader.read(n)
            if not chunk:
                raise EOFError(f"connection closed early: received={total}, expected={expected_size}")
            f.write(chunk)
            total += len(chunk)
            remaining -= len(chunk)
    return total


@dataclass
class SendJob:
    kind: str
    sender: str
    text: str = ""
    file_path: Optional[Path] = None
    stego: bool = False
    display_text: str = ""


class MessageBubble(tk.Frame):
    def __init__(self, parent, record: dict, is_self: bool, on_click_image, on_context_menu):
        super().__init__(parent, bg="#0f172a")
        self.record = record
        self.on_click_image = on_click_image
        self.on_context_menu = on_context_menu
        self.img_ref = None

        anchor = "e" if is_self else "w"
        outer = tk.Frame(self, bg="#0f172a")
        outer.pack(anchor=anchor, padx=10, pady=4)

        meta_color = "#94a3b8"
        tk.Label(
            outer,
            text=f'{record.get("sender", "Unknown")}  {format_ts(record.get("timestamp", time.time()))}',
            bg="#0f172a",
            fg=meta_color,
            font=("Segoe UI", 9),
        ).pack(anchor=anchor)

        bubble_bg = "#2563eb" if is_self else "#1f2937"
        bubble = tk.Frame(outer, bg=bubble_bg, padx=12, pady=8, cursor="arrow")
        bubble.pack(anchor=anchor)

        bubble.bind("<Button-3>", self._show_context_menu)

        msg_type = record.get("msg_type")
        if msg_type == "image":
            path = record.get("path", "")
            if path:
                try:
                    image = Image.open(path)
                    image.thumbnail((220, 220))
                    self.img_ref = ImageTk.PhotoImage(image)
                    img_label = tk.Label(bubble, image=self.img_ref, bg=bubble_bg, cursor="hand2")
                    img_label.pack(anchor="w")
                    img_label.bind("<Button-1>", lambda e: self.on_click_image(self.record))
                    img_label.bind("<Button-3>", self._show_context_menu)
                except Exception:
                    tk.Label(bubble, text="[图片预览失败]", bg=bubble_bg, fg="white", font=("Segoe UI", 10)).pack(anchor="w")

        text = record.get("display_text", "")
        if text:
            tk.Label(
                bubble,
                text=text,
                bg=bubble_bg,
                fg="white",
                font=("Segoe UI", 11),
                justify="left",
                wraplength=360,
            ).pack(anchor="w")

    def _show_context_menu(self, event):
        self.on_context_menu(event, self.record)


class ScrollableChat(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, bg="#0f172a", highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg="#0f172a")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.bind("<Configure>", self._resize)

    def _resize(self, event):
        self.canvas.itemconfig(self.window, width=event.width)

    def add_message_widget(self, widget: MessageBubble):
        widget.pack(fill="x", pady=2)
        self.update_idletasks()
        self.canvas.yview_moveto(1.0)


class ChatRuntimeService:
    def __init__(self, ui_callback, local_host, local_port, remote_host, remote_port, chat_data_dir: Path):
        self.ui_callback = ui_callback
        self.local_host = local_host
        self.local_port = local_port
        self.remote_host = remote_host
        self.remote_port = remote_port
        self.chat_data_dir = chat_data_dir

        self.thread = None
        self.loop = None
        self.stop_event = None
        self.ready_event = threading.Event()
        self.jobs = queue.Queue()

        self.temp_dir = chat_data_dir / "temp"
        self.recv_dir = chat_data_dir / "received"
        ensure_dir(self.temp_dir)
        ensure_dir(self.recv_dir)

    def start(self):
        self.thread = threading.Thread(target=self._runner, daemon=True)
        self.thread.start()

    def submit(self, job: SendJob):
        self.jobs.put(job)

    def stop(self):
        if self.loop and self.stop_event:
            self.loop.call_soon_threadsafe(self.stop_event.set)

    def _runner(self):
        asyncio.run(self._main())

    async def _main(self):
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()

        log_dir = _env_str("LOG_DIR", "exp/e2/tor")
        writer = build_writer(log_dir)
        ensure_seed()

        def bus_factory(node_name: str) -> EventBus:
            return EventBus(writer.emit_nowait, node_id=node_name, role="client")

        max_workers = _env_int("MAX_TLS_THREADS", 128)
        self.loop.set_default_executor(
            concurrent.futures.ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="tls-worker")
        )

        directory_addr = _env_str("DIRECTORY_ADDR", "192.168.66.241:9030")
        os.environ["DIRECTORY_ADDR"] = directory_addr
        node_addr = _env_str("NODE_ADDR", "192.168.66.242")
        hop = _env_int("HOPS", 3)
        addr = (self.remote_host, self.remote_port)
        users = _env_int("USERS", 1)
        circuits_per_user = _env_int("CIRCUITS_PER_USER", 1)
        chunk_kb = _env_int("CHUNK_KB", 32)
        start_timeout_s = _env_int("START_TIMEOUT_S", 30)
        inter_chunk_sleep_ms = _env_int("INTER_CHUNK_SLEEP_MS", 0)
        max_header_bytes = 8192

        clients = []
        protocol_tasks = []
        client_circuits = {}
        server = None

        try:
            # start sender side tor clients
            for user_index in range(users):
                name = f"user{user_index}"
                port = 9102 + user_index
                client = Tor_Client(name=name, host=node_addr, port=port, model="sim")
                client.attach_bus(bus_factory(name))
                client.emit = client.event_bus.emit
                clients.append(client)
                protocol_tasks.append(asyncio.create_task(client.start_protocol()))

            for client in clients:
                client_circuits[client] = await _build_user_circuits_once(
                    client=client,
                    addr=addr,
                    hop=hop,
                    circuits_per_user=circuits_per_user,
                    start_timeout_s=start_timeout_s,
                )

            async def handle_client(reader: asyncio.StreamReader, writer_obj: asyncio.StreamWriter):
                peer = writer_obj.get_extra_info("peername") or ("unknown", 0)
                try:
                    raw_header = await _read_header(reader, max_header_bytes)
                    header = validate_chat_header(raw_header)

                    if header.msg_type == "text":
                        record = {
                            "direction": "in",
                            "sender": header.sender,
                            "timestamp": header.timestamp,
                            "message_id": header.message_id,
                            "msg_type": "text",
                            "text": header.text,
                            "display_text": header.text,
                            "stego": False,
                        }
                        self.ui_callback(("message", record))
                        self.ui_callback(("log", f"[Recv Text] from {header.sender} @ {peer}"))
                    else:
                        output_path = unique_path(self.recv_dir, header.name or "image.bin")
                        received_size = await _receive_exact_file(
                            reader=reader,
                            output_path=output_path,
                            expected_size=header.size,
                            chunk_bytes=max(1, chunk_kb) * 1024,
                        )
                        actual_sha256 = sha256_file(output_path)
                        verified = (received_size == header.size) and (not header.sha256 or actual_sha256 == header.sha256)
                        record = {
                            "direction": "in",
                            "sender": header.sender,
                            "timestamp": header.timestamp,
                            "message_id": header.message_id,
                            "msg_type": "image",
                            "path": str(output_path),
                            "text": "",
                            "display_text": "",
                            "stego": header.stego,
                            "verified": verified,
                        }

                        self.ui_callback(("message", record))
                        self.ui_callback(("log", f"[Recv Image] {output_path.name}, verified={verified}, from={header.sender}"))
                except Exception as exc:
                    self.ui_callback(("log", f"[Receiver Error] {peer}: {exc!r}"))
                finally:
                    writer_obj.close()
                    with contextlib.suppress(Exception):
                        await writer_obj.wait_closed()

            server = await asyncio.start_server(handle_client, host=self.local_host, port=self.local_port)

            addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
            self.ui_callback(("log", f"[Server] listening on {addrs}"))
            self.ui_callback(("log", f"[Remote] target={self.remote_host}:{self.remote_port}"))
            self.ready_event.set()

            async def serve_task():
                async with server:
                    await server.serve_forever()

            server_task = asyncio.create_task(serve_task())
            next_client_index = 0

            while not self.stop_event.is_set():
                try:
                    job = self.jobs.get(timeout=0.2)
                except queue.Empty:
                    await asyncio.sleep(0.05)
                    continue

                try:
                    file_to_send = job.file_path
                    if job.kind == "image" and job.stego and job.file_path:
                        src = job.file_path
                        ext = src.suffix.lower()
                        name = f"{int(time.time() * 1000)}_{src.stem}_stego{ext if ext in {'.png', '.bmp'} else '.png'}"
                        out_path = self.temp_dir / name
                        file_to_send = embed_message_in_image(src, out_path, job.text)

                    client = clients[next_client_index % len(clients)]
                    next_client_index += 1
                    circuit = random.choice(client_circuits[client])
                    client.circuit_mgr.mark_used(circuit)
                    stream = await _open_stream_on_circuit(client, circuit, addr)

                    try:
                        if job.kind == "text":
                            header = build_text_header(job.sender, job.text)
                            await _send_text_payload(client, circuit, stream, header)
                            msg_id = header.message_id
                            ts = header.timestamp
                        else:
                            header = build_image_header(job.sender, file_to_send, stego=job.stego)
                            await _send_image_payload(client, circuit, stream, header, file_to_send, chunk_kb, inter_chunk_sleep_ms)
                            msg_id = header.message_id
                            ts = header.timestamp
                    finally:
                        with contextlib.suppress(Exception):
                            await client.close_stream(circuit, stream)

                    record = {
                        "direction": "out",
                        "sender": job.sender,
                        "timestamp": ts,
                        "message_id": msg_id,
                        "msg_type": job.kind,
                        "text": job.text,
                        "display_text": job.display_text if job.display_text else job.text,
                        "path": str(file_to_send) if file_to_send else "",
                        "stego": job.stego,
                    }
                    self.ui_callback(("message", record))
                    self.ui_callback(("log", "[Sent] message sent"))
                except Exception as exc:
                    self.ui_callback(("log", f"[Send Error] {exc!r}"))

            server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await server_task

        finally:
            if server:
                server.close()
                with contextlib.suppress(Exception):
                    await server.wait_closed()

            for client in clients:
                for c in client_circuits.get(client, []):
                    with contextlib.suppress(Exception):
                        if hasattr(client, "close_circuit"):
                            await client.close_circuit(c)

            for client in clients:
                with contextlib.suppress(Exception):
                    await client.stop_protocol()

            for task in protocol_tasks:
                if not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await task

            await writer.stop()


class BidirectionalChatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Stego Bidirectional Chat")
        self.root.geometry("1360x840")
        self.root.configure(bg="#0b1120")

        self.display_name = _env_str("DISPLAY_NAME", "Alice")
        self.local_host = _env_str("LOCAL_HOST", "0.0.0.0")
        self.local_port = _env_int("LOCAL_PORT", 8000)
        self.remote_host = _env_str("REMOTE_HOST", "127.0.0.1")
        self.remote_port = _env_int("REMOTE_PORT", 8001)

        self.chat_data_dir = Path(_env_str("CHAT_DATA_DIR", "chat_data")) / f"{self.display_name}_{self.local_port}"
        ensure_dir(self.chat_data_dir)
        ensure_dir(self.chat_data_dir / "received")
        ensure_dir(self.chat_data_dir / "temp")
        self.history_path = self.chat_data_dir / "history.json"

        self.selected_image: Optional[Path] = None
        self.preview_ref = None
        self.current_preview_path: Optional[Path] = None
        self.records = load_history(self.history_path)

        self.event_queue = queue.Queue()

        self._build_style()
        self._build_ui()
        self._load_history_to_ui()

        self.runtime = ChatRuntimeService(
            ui_callback=self._enqueue_event,
            local_host=self.local_host,
            local_port=self.local_port,
            remote_host=self.remote_host,
            remote_port=self.remote_port,
            chat_data_dir=self.chat_data_dir,
        )
        self.runtime.start()

        self.root.after(120, self._poll_events)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure("TFrame", background="#0b1120")
        style.configure("Panel.TFrame", background="#111827")
        style.configure("Sidebar.TFrame", background="#0f172a")
        style.configure("Title.TLabel", background="#0b1120", foreground="#f8fafc", font=("Segoe UI", 18, "bold"))
        style.configure("PanelTitle.TLabel", background="#111827", foreground="#e5e7eb", font=("Segoe UI", 11, "bold"))
        style.configure("Muted.TLabel", background="#111827", foreground="#94a3b8", font=("Segoe UI", 10))
        style.configure("SideTitle.TLabel", background="#0f172a", foreground="#f8fafc", font=("Segoe UI", 12, "bold"))
        style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))

    def _build_ui(self):
        root_frame = ttk.Frame(self.root)
        root_frame.pack(fill="both", expand=True, padx=14, pady=14)

        header = ttk.Frame(root_frame)
        header.pack(fill="x", pady=(0, 12))

        ttk.Label(header, text="Stego Instant Messenger", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header,
            text=f"{self.display_name}   Local: {self.local_host}:{self.local_port}   Remote: {self.remote_host}:{self.remote_port}",
            style="Muted.TLabel",
        ).pack(side="left", padx=18)

        body = ttk.Frame(root_frame)
        body.pack(fill="both", expand=True)

        left = ttk.Frame(body, style="Panel.TFrame", width=300)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)

        center = ttk.Frame(body, style="Panel.TFrame")
        center.pack(side="left", fill="both", expand=True, padx=8)

        right = ttk.Frame(body, style="Sidebar.TFrame", width=330)
        right.pack(side="right", fill="y", padx=(8, 0))
        right.pack_propagate(False)

        # left panel
        ttk.Label(left, text="会话信息", style="PanelTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))

        info_text = (
            f"昵称: {self.display_name}\n"
            f"监听: {self.local_host}:{self.local_port}\n"
            f"对端: {self.remote_host}:{self.remote_port}\n\n"
            f"支持:\n"
            f"- 普通文本消息\n"
            f"- 普通图片消息\n"
            f"- 图片隐写消息\n"
            f"- 右键菜单 / 点击图片"
        )
        self.info_label = tk.Label(left, text=info_text, justify="left", bg="#111827", fg="#cbd5e1", font=("Segoe UI", 10))
        self.info_label.pack(anchor="w", padx=12, pady=(0, 12))

        ttk.Label(left, text="系统日志", style="PanelTitle.TLabel").pack(anchor="w", padx=12)
        self.log_box = tk.Text(
            left,
            bg="#0f172a",
            fg="#d1fae5",
            relief="flat",
            font=("Consolas", 10),
            state="disabled",
            wrap="word",
            padx=10,
            pady=10,
        )
        self.log_box.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        # center panel
        top_bar = ttk.Frame(center, style="Panel.TFrame")
        top_bar.pack(fill="x", padx=12, pady=12)
        ttk.Label(top_bar, text="聊天记录", style="PanelTitle.TLabel").pack(side="left")
        ttk.Label(top_bar, text="点击图片预览，右键图片消息可提取隐写", style="Muted.TLabel").pack(side="left", padx=12)

        self.chat = ScrollableChat(center)
        self.chat.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        composer = ttk.Frame(center, style="Panel.TFrame")
        composer.pack(fill="x", padx=12, pady=(0, 12))

        row1 = ttk.Frame(composer, style="Panel.TFrame")
        row1.pack(fill="x", pady=(0, 8))
        ttk.Label(row1, text="发送者", style="PanelTitle.TLabel").pack(side="left")
        self.name_var = tk.StringVar(value=self.display_name)
        self.name_entry = tk.Entry(row1, textvariable=self.name_var, bg="#1f2937", fg="#f8fafc", insertbackground="#f8fafc", relief="flat", font=("Segoe UI", 11))
        self.name_entry.pack(side="left", fill="x", expand=True, padx=(8, 0), ipady=6)

        ttk.Label(composer, text="消息内容", style="PanelTitle.TLabel").pack(anchor="w")
        self.text_box = tk.Text(
            composer,
            height=5,
            bg="#1f2937",
            fg="#f8fafc",
            insertbackground="#f8fafc",
            relief="flat",
            font=("Segoe UI", 11),
            wrap="word",
            padx=10,
            pady=10,
        )
        self.text_box.pack(fill="x", pady=(6, 10))

        row2 = ttk.Frame(composer, style="Panel.TFrame")
        row2.pack(fill="x")
        ttk.Button(row2, text="发送文本", command=self.send_text, style="Accent.TButton").pack(side="left")
        ttk.Button(row2, text="选择图片", command=self.pick_image).pack(side="left", padx=8)
        ttk.Button(row2, text="发送普通图片", command=self.send_plain_image).pack(side="left")
        ttk.Button(row2, text="发送图片隐写", command=self.send_stego_image, style="Accent.TButton").pack(side="left", padx=8)

        self.image_info = ttk.Label(composer, text="未选择图片", style="Muted.TLabel")
        self.image_info.pack(anchor="w", pady=(8, 0))

        # right panel
        ttk.Label(right, text="图片预览", style="SideTitle.TLabel").pack(anchor="w", padx=12, pady=(12, 8))
        self.preview_label = tk.Label(right, bg="#111827", fg="#94a3b8", text="暂无图片", relief="flat")
        self.preview_label.pack(fill="x", padx=12, pady=(0, 12), ipady=24)

        btn_row = ttk.Frame(right, style="Sidebar.TFrame")
        btn_row.pack(fill="x", padx=12, pady=(0, 10))
        ttk.Button(btn_row, text="提取当前图片隐写", command=self.extract_current_image, style="Accent.TButton").pack(side="left")
        ttk.Button(btn_row, text="打开原图", command=self.open_current_image).pack(side="left", padx=8)

        ttk.Label(right, text="提取结果", style="SideTitle.TLabel").pack(anchor="w", padx=12)
        self.extract_box = tk.Text(
            right,
            height=12,
            bg="#1f2937",
            fg="#f8fafc",
            relief="flat",
            font=("Segoe UI", 11),
            wrap="word",
            padx=10,
            pady=10,
        )
        self.extract_box.pack(fill="x", padx=12, pady=(8, 12))

        ttk.Label(right, text="文件操作", style="SideTitle.TLabel").pack(anchor="w", padx=12)
        file_ops = ttk.Frame(right, style="Sidebar.TFrame")
        file_ops.pack(fill="x", padx=12, pady=(8, 12))
        ttk.Button(file_ops, text="打开当前图片所在目录", command=self.open_current_folder).pack(side="left")

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="提取隐写消息", command=self._ctx_extract)
        self.context_menu.add_command(label="打开原图", command=self._ctx_open_image)
        self.context_menu.add_command(label="打开所在文件夹", command=self._ctx_open_folder)
        self._ctx_record = None

    def _enqueue_event(self, event):
        self.event_queue.put(event)

    def _append_log(self, text: str):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", text + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _poll_events(self):
        while True:
            try:
                kind, payload = self.event_queue.get_nowait()
            except queue.Empty:
                break

            if kind == "log":
                self._append_log(payload)
            elif kind == "message":
                self._add_record(payload)

        self.root.after(120, self._poll_events)

    def _add_record(self, record: dict):
        self.records.append(record)
        save_history(self.history_path, self.records)
        self._append_message_to_ui(record)

    def _append_message_to_ui(self, record: dict):
        is_self = record.get("direction") == "out"
        widget = MessageBubble(
            self.chat.inner,
            record=record,
            is_self=is_self,
            on_click_image=self._on_click_image_record,
            on_context_menu=self._show_context_menu,
        )
        self.chat.add_message_widget(widget)

    def _load_history_to_ui(self):
        for record in self.records:
            self._append_message_to_ui(record)

    def _on_click_image_record(self, record: dict):
        path = record.get("path")
        if path:
            self.current_preview_path = Path(path)
            self._show_preview(self.current_preview_path)
            if record.get("stego"):
                try:
                    msg = extract_message_from_image(self.current_preview_path)
                    self.extract_box.delete("1.0", "end")
                    self.extract_box.insert("1.0", msg)
                except Exception:
                    pass

    def _show_preview(self, path: Path):
        try:
            image = Image.open(path)
            image.thumbnail((280, 280))
            self.preview_ref = ImageTk.PhotoImage(image)
            self.preview_label.config(image=self.preview_ref, text="")
        except Exception as exc:
            self.preview_label.config(image="", text=f"预览失败: {exc}")

    def _show_context_menu(self, event, record: dict):
        self._ctx_record = record
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _ctx_extract(self):
        if not self._ctx_record:
            return
        path = self._ctx_record.get("path")
        if not path:
            messagebox.showwarning("提示", "这条消息不是图片消息。")
            return
        try:
            msg = extract_message_from_image(Path(path))
            self.current_preview_path = Path(path)
            self._show_preview(self.current_preview_path)
            self.extract_box.delete("1.0", "end")
            self.extract_box.insert("1.0", msg)
            self._append_log(f"[Extracted] {Path(path).name}")
        except Exception:
            messagebox.showinfo("提示", "这不是一个隐写文件")

    def _ctx_open_image(self):
        if self._ctx_record and self._ctx_record.get("path"):
            open_path(Path(self._ctx_record["path"]))

    def _ctx_open_folder(self):
        if self._ctx_record and self._ctx_record.get("path"):
            open_folder(Path(self._ctx_record["path"]))

    def pick_image(self):
        path = filedialog.askopenfilename(
            title="选择图片",
            filetypes=[
                ("Images", "*.png *.bmp *.jpg *.jpeg *.webp *.gif"),
                ("All Files", "*.*"),
            ],
        )
        if not path:
            return
        self.selected_image = Path(path)
        self.image_info.config(text=str(self.selected_image))
        self._show_preview(self.selected_image)
        self.current_preview_path = self.selected_image

    def send_text(self):
        sender = self.name_var.get().strip() or self.display_name
        text = self.text_box.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("提示", "请输入文本消息。")
            return
        if not self.runtime.ready_event.is_set():
            messagebox.showinfo("提示", "通信服务尚未准备完成。")
            return

        self.runtime.submit(
            SendJob(
                kind="text",
                sender=sender,
                text=text,
                display_text=text,
            )
        )
        self.text_box.delete("1.0", "end")

    def send_plain_image(self):
        sender = self.name_var.get().strip() or self.display_name
        if not self.selected_image:
            messagebox.showwarning("提示", "请先选择图片。")
            return
        if not self.runtime.ready_event.is_set():
            messagebox.showinfo("提示", "通信服务尚未准备完成。")
            return

        display_text = ""

        self.runtime.submit(
            SendJob(
                kind="image",
                sender=sender,
                text="",
                file_path=self.selected_image,
                stego=False,
                display_text=display_text,
            )
        )
        self.text_box.delete("1.0", "end")

    def send_stego_image(self):
        sender = self.name_var.get().strip() or self.display_name
        if not self.selected_image:
            messagebox.showwarning("提示", "请先选择图片。")
            return

        text = self.text_box.get("1.0", "end").strip()
        if not text:
            messagebox.showwarning("提示", "请输入要隐写进图片的文本。")
            return

        if not self.runtime.ready_event.is_set():
            messagebox.showinfo("提示", "通信服务尚未准备完成。")
            return

        self.runtime.submit(
            SendJob(
                kind="image",
                sender=sender,
                text=text,
                file_path=self.selected_image,
                stego=True,
                display_text="",
            )
        )
        self.text_box.delete("1.0", "end")

    def extract_current_image(self):
        if not self.current_preview_path:
            messagebox.showwarning("提示", "当前没有可提取的图片。")
            return
        try:
            msg = extract_message_from_image(self.current_preview_path)
            self.extract_box.delete("1.0", "end")
            self.extract_box.insert("1.0", msg)
            self._append_log(f"[Extracted] {self.current_preview_path.name}")
        except Exception as exc:
            messagebox.showerror("提取失败", f"无法恢复隐写消息：\n{exc}")

    def open_current_image(self):
        if not self.current_preview_path:
            messagebox.showwarning("提示", "当前没有图片。")
            return
        open_path(self.current_preview_path)

    def open_current_folder(self):
        if not self.current_preview_path:
            messagebox.showwarning("提示", "当前没有图片。")
            return
        open_folder(self.current_preview_path)

    def on_close(self):
        save_history(self.history_path, self.records)
        self.runtime.stop()
        self.root.destroy()


def main():
    root = tk.Tk()
    BidirectionalChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
