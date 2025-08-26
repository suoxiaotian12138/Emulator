# twintor/logging/utils.py
from __future__ import annotations
import time, asyncio, errno
from enum import Enum

class FailReason(Enum):
    TIMEOUT = "TIMEOUT"
    RESET = "RESET"
    TLS_FAIL = "TLS_FAIL"
    NTOR_FAIL = "NTOR_FAIL"
    UNREACHABLE = "UNREACHABLE"     # 网络不可达/连接失败
    DEST_POLICY = "DEST_POLICY"     # 出口策略拒绝
    PROTO_ERR = "PROTO_ERR"         # 协议错误/解析异常
    UNKNOWN = "UNKNOWN"

def classify_exception(e: BaseException) -> FailReason:
    if isinstance(e, asyncio.TimeoutError):
        return FailReason.TIMEOUT
    if isinstance(e, ConnectionResetError):
        return FailReason.RESET
    if isinstance(e, OSError):
        # 常见网络 errno
        if getattr(e, "errno", None) in {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT}:
            return FailReason.UNREACHABLE
    # 你可以在 Tor 握手/ntor 相关异常处显式传入 NTOR_FAIL/TLS_FAIL
    return FailReason.UNKNOWN

class HopTimer:
    """简单的上下文计时器：测 EXTEND→EXTENDED RTT 等"""
    def __init__(self): self.t0 = None
    def start(self): self.t0 = time.perf_counter(); return self
    def ms(self): return (time.perf_counter() - (self.t0 or time.perf_counter())) * 1000.0
