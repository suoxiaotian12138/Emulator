import time
import json
import socket
import hashlib
import os
from tools.Crypt.serialization import decode
from urllib.parse import urlparse
from tools.Packet.packet_UDP import send_udp_async

class LocalMonitor:
    def __init__(self, sock: socket.socket):
        self.socket = sock
        self.send_time = {}  # trace_id -> send_time
        self.logs = []
        self.temporary_record = {}
        self.monitor_addr = self.get_centor_monitor_address()
        self.send = send_udp_async
        self.enabled = True

    def disable(self):
        self.enabled = False

    def enable(self):
        self.enabled = True

    async def report(self, data):
        if not self.enabled or self.monitor_addr is None:
            return
        msg = json.dumps(data).encode()
        host, port = self.monitor_addr
        await self.send(self.socket, msg, host, port)

    async def log_event(self, trace_id, event, current_addr=None, src=None, dst=None, info=None):
        if not self.enabled:
            return  # 🔒 被禁用时跳过
        data = {
            "trace_id": trace_id,
            "event": event,
            "node": current_addr,
            "src": src,
            "dst": dst,
            "time": time.time(),
            "info": info or {}
        }
        await self.report(data)

    @staticmethod
    def get_centor_monitor_address(default=None):
        addr = os.environ.get('MONITOR_ADDR', default)
        if not addr:
            return None
        if "://" not in addr:
            addr = "http://" + addr
        parsed = urlparse(addr)
        host = parsed.hostname
        port = parsed.port
        if host is None or port is None:
            raise ValueError(f"Invalid DIRECTORY_ADDR format: {addr}")
        return (host, port)

    def recv_time_record(self, packet, addr):
        if not self.enabled:
            return
        decoded_packet = decode(packet)
        if decoded_packet[0] in ('SUBSCRIBE', 'PULL', 'DUMMY'):
            return
        time_record = time.time()
        arc_addr = addr
        packet_key = self.packet_fingerprint(packet)
        self.temporary_record[packet_key] = [time_record, arc_addr]

    def recv_log(self, packet, trace_id, event, info=None):
        if not self.enabled:
            return
        packet_key = self.packet_fingerprint(packet)
        time_record, arc_addr = self.temporary_record.get(packet_key, ([], [None, None]))
        host, port = arc_addr
        src = (host, port)
        try:
            import asyncio
            asyncio.create_task(self.log_event(trace_id=trace_id, event=event, src=src, info=info))
        except RuntimeError:
            pass
        self.temporary_record.pop(packet_key, None)

    @staticmethod
    def packet_fingerprint(packet: bytes) -> str:
        digest = hashlib.sha256(packet[:512]).hexdigest()
        return digest[:16]

    def export_log(self, path):
        if not self.enabled:
            return
        with open(path, 'w') as f:
            json.dump(self.logs, f, indent=2)
