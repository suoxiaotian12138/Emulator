# tools/Network_Management/tls_keylog_cache.py
import threading
import time
from typing import Optional, Dict, Tuple

_keylog_lock = threading.Lock()
_exporter_by_sslobj: Dict[int, Tuple[float, str]] = {}  # id(sslobj) -> (ts, line)

MAX_CACHE = 20000
TTL_SECONDS = 120

# 低频触发控制，避免每次 dial 都做 GC
_gc_counter = 0
_GC_EVERY = 1000  # 每 1000 次触发一次，可按并发调

def keylog_cb(sslobj, line) -> None:
    # line 可能是 str 或 bytes
    if isinstance(line, (bytes, bytearray)):
        try:
            line = line.decode("utf-8", "ignore")
        except Exception:
            return
    if not isinstance(line, str):
        return

    if not line.startswith("EXPORTER_SECRET "):
        return

    now = time.time()

    # 关键：直接写到 sslobj 上（零等待，避免 dial_tls pop 过早）
    try:
        setattr(sslobj, "_exporter_line", line)
    except Exception:
        pass

    # 兜底：同时放进全局缓存，用于某些实现不允许 setattr 的情况
    with _keylog_lock:
        _exporter_by_sslobj[id(sslobj)] = (now, line)

def get_exporter_line(sslobj) -> Optional[str]:
    """不删除，只读取兜底缓存（正常应优先读 sslobj._exporter_line）"""
    sid = id(sslobj)
    with _keylog_lock:
        item = _exporter_by_sslobj.get(sid)
    return item[1] if item else None

def pop_exporter_line(sslobj) -> Optional[str]:
    """在你真正用完 exporter 后再调用清理"""
    sid = id(sslobj)
    with _keylog_lock:
        item = _exporter_by_sslobj.pop(sid, None)
    return item[1] if item else None

def maybe_gc_exporter_cache() -> None:
    global _gc_counter
    _gc_counter += 1
    if _gc_counter % _GC_EVERY != 0:
        return
    gc_exporter_cache()

def gc_exporter_cache() -> None:
    now = time.time()
    with _keylog_lock:
        dead = [k for k, (ts, _) in _exporter_by_sslobj.items() if now - ts > TTL_SECONDS]
        for k in dead:
            _exporter_by_sslobj.pop(k, None)

        if len(_exporter_by_sslobj) > MAX_CACHE:
            items = sorted(_exporter_by_sslobj.items(), key=lambda kv: kv[1][0])
            over = len(_exporter_by_sslobj) - MAX_CACHE
            for k, _ in items[:over]:
                _exporter_by_sslobj.pop(k, None)


