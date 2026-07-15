import hashlib
import json
import os
import time
import uuid
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from PIL import Image


STEGO_MAGIC = b"STEG0"
STEGO_VERSION = 1

IMAGE_EXTS = {".png", ".bmp", ".jpg", ".jpeg", ".webp", ".gif"}


@dataclass
class ChatHeader:
    kind: str
    msg_type: str
    sender: str
    timestamp: float
    message_id: str
    stego: bool = False
    text: str = ""
    name: str = ""
    size: int = 0
    sha256: str = ""

    def to_json_line(self) -> bytes:
        return (json.dumps(asdict(self), ensure_ascii=False) + "\n").encode("utf-8")

    @staticmethod
    def from_dict(data: dict) -> "ChatHeader":
        return ChatHeader(
            kind=str(data.get("kind", "chat")),
            msg_type=str(data.get("msg_type", "")),
            sender=str(data.get("sender", "Unknown")),
            timestamp=float(data.get("timestamp", time.time())),
            message_id=str(data.get("message_id", uuid.uuid4().hex)),
            stego=bool(data.get("stego", False)),
            text=str(data.get("text", "")),
            name=str(data.get("name", "")),
            size=int(data.get("size", 0)),
            sha256=str(data.get("sha256", "")),
        )


def make_message_id() -> str:
    return uuid.uuid4().hex


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_text_header(sender: str, text: str) -> ChatHeader:
    return ChatHeader(
        kind="chat",
        msg_type="text",
        sender=sender,
        timestamp=time.time(),
        message_id=make_message_id(),
        stego=False,
        text=text,
    )


def build_image_header(sender: str, image_path: Path, stego: bool) -> ChatHeader:
    return ChatHeader(
        kind="chat",
        msg_type="image",
        sender=sender,
        timestamp=time.time(),
        message_id=make_message_id(),
        stego=stego,
        name=image_path.name,
        size=image_path.stat().st_size,
        sha256=sha256_file(image_path),
    )


def validate_chat_header(header: dict) -> ChatHeader:
    if not isinstance(header, dict):
        raise ValueError("header must be a JSON object")

    kind = header.get("kind")
    if kind != "chat":
        raise ValueError("header.kind must be 'chat'")

    msg_type = header.get("msg_type")
    if msg_type not in {"text", "image"}:
        raise ValueError("header.msg_type must be 'text' or 'image'")

    sender = header.get("sender")
    if not isinstance(sender, str) or not sender.strip():
        raise ValueError("header.sender must be a non-empty string")

    ts = header.get("timestamp")
    if not isinstance(ts, (int, float)):
        raise ValueError("header.timestamp must be a number")

    message_id = header.get("message_id")
    if not isinstance(message_id, str) or not message_id:
        raise ValueError("header.message_id must be a non-empty string")

    if msg_type == "text":
        text = header.get("text", "")
        if not isinstance(text, str):
            raise ValueError("header.text must be a string")
    else:
        size = header.get("size")
        if not isinstance(size, int) or size < 0:
            raise ValueError("header.size must be a non-negative integer")
        name = header.get("name", "")
        if not isinstance(name, str):
            raise ValueError("header.name must be a string")
        sha256 = header.get("sha256", "")
        if sha256 and (not isinstance(sha256, str) or len(sha256) != 64):
            raise ValueError("header.sha256 must be a 64-character hex string")

    return ChatHeader.from_dict(header)


def bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def bits_to_bytes(bits):
    out = bytearray()
    cur = 0
    count = 0
    for b in bits:
        cur = (cur << 1) | b
        count += 1
        if count == 8:
            out.append(cur)
            cur = 0
            count = 0
    return bytes(out)


def build_stego_payload(message: str) -> bytes:
    body = message.encode("utf-8")
    checksum = hashlib.sha256(body).digest()[:8]
    payload = (
        STEGO_MAGIC
        + bytes([STEGO_VERSION])
        + len(body).to_bytes(4, "big")
        + checksum
        + body
    )
    return payload


def parse_stego_payload(payload: bytes) -> str:
    if len(payload) < 18:
        raise ValueError("payload too short")
    if payload[:5] != STEGO_MAGIC:
        raise ValueError("magic mismatch")
    version = payload[5]
    if version != STEGO_VERSION:
        raise ValueError(f"unsupported version: {version}")
    msg_len = int.from_bytes(payload[6:10], "big")
    checksum = payload[10:18]
    if len(payload) < 18 + msg_len:
        raise ValueError("payload incomplete")
    body = payload[18:18 + msg_len]
    if hashlib.sha256(body).digest()[:8] != checksum:
        raise ValueError("checksum mismatch")
    return body.decode("utf-8")


def embed_message_in_image(src_path: Path, dst_path: Path, message: str) -> Path:
    image = Image.open(src_path).convert("RGBA")
    payload = build_stego_payload(message)
    bits = list(bytes_to_bits(payload))

    pixels = list(image.getdata())
    capacity = len(pixels) * 3
    if len(bits) > capacity:
        raise ValueError(f"message too large for image: need {len(bits)} bits, capacity {capacity} bits")

    new_pixels = []
    bit_idx = 0
    for r, g, b, a in pixels:
        channels = [r, g, b]
        for i in range(3):
            if bit_idx < len(bits):
                channels[i] = (channels[i] & 0xFE) | bits[bit_idx]
                bit_idx += 1
        new_pixels.append((channels[0], channels[1], channels[2], a))

    image.putdata(new_pixels)

    out_path = dst_path
    if out_path.suffix.lower() not in {".png", ".bmp"}:
        out_path = out_path.with_suffix(".png")

    if out_path.suffix.lower() == ".bmp":
        image.save(out_path, format="BMP")
    else:
        image.save(out_path, format="PNG")

    return out_path


def extract_message_from_image(image_path: Path) -> str:
    image = Image.open(image_path).convert("RGBA")
    pixels = list(image.getdata())

    bits = []
    for r, g, b, a in pixels:
        bits.extend([r & 1, g & 1, b & 1])

    raw = bits_to_bytes(bits)
    pos = raw.find(STEGO_MAGIC)
    if pos < 0:
        raise ValueError("no hidden message found")

    sliced = raw[pos:]
    if len(sliced) < 18:
        raise ValueError("hidden payload incomplete")

    msg_len = int.from_bytes(sliced[6:10], "big")
    total_len = 18 + msg_len
    if len(sliced) < total_len:
        raise ValueError("hidden payload truncated")

    return parse_stego_payload(sliced[:total_len])


def format_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def safe_filename(name: str) -> str:
    name = Path(name).name
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name) or "unnamed.bin"


def unique_path(output_dir: Path, filename: str) -> Path:
    filename = safe_filename(filename)
    path = output_dir / filename
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    idx = 1
    while True:
        p = output_dir / f"{stem}_{idx}{suffix}"
        if not p.exists():
            return p
        idx += 1


def open_path(path: Path):
    path = Path(path)
    if sys.platform.startswith("win"):
        os.startfile(str(path))
    elif sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        subprocess.run(["xdg-open", str(path)], check=False)


def open_folder(path: Path):
    path = Path(path)
    folder = path if path.is_dir() else path.parent
    open_path(folder)


def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)


def save_history(history_path: Path, records: list[dict]):
    history_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")


def load_history(history_path: Path) -> list[dict]:
    if not history_path.exists():
        return []
    try:
        return json.loads(history_path.read_text(encoding="utf-8"))
    except Exception:
        return []
