import time
import json
import socket
import hashlib


class LocalMonitor:
    """
    {
      "trace_id": "xxx",
      "event": "send" | "recv" | "forward" | "drop",
      "node": "current_node_name",
      "src": "prev_node" | null,
      "dst": "next_node" | null,
      "time": timestamp,
      "info": { "reason": "drop_by_attack" } # only for drop or extra info
    }
    """
    def __init__(self, loopixnode):
        self.name = loopixnode.name
        self.host = loopixnode.host
        self.port = loopixnode.port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.send_time = {}  # trace_id -> send_time
        self.logs = []
        self.temporary_record = {}

    def report(self, data):
        msg = json.dumps(data).encode()
        self.sock.sendto(msg, self.report_addr)


    def recv_time_record(self, packet, addr):
        time_record = time.time()
        arc_addr = addr

        packet_key = self.packet_fingerprint(packet)
        self.temporary_record[packet_key] = [time_record, arc_addr]

    def recv_log(self, packet, trace_id ,event):

        packet_key = self.packet_fingerprint(packet)
        time_record, arc_addr = self.temporary_record[packet_key]
        host,port = arc_addr
        src = f"{host}:{port}",
        self.log_event(trace_id=trace_id, event=event, src=src,time_record=time_record)
        self.temporary_record.pop(packet)

    @staticmethod
    def packet_fingerprint(packet: bytes) -> str:
        """高性能 fingerprint，防止大包计算过慢"""
        digest = hashlib.sha256(packet[:512]).hexdigest()  # 只取前512字节
        return digest[:16]


    def log_event(self, trace_id, event, src=None, dst=None, info=None, time_record=None):
        data = {
            "trace_id": trace_id,
            "event": event,
            "node": (self.host, self.port),
            "src": src,
            "dst": dst,
            "time": time.time(),
            "info": info or {}
        }

    def export_log(self, path):
        with open(path, 'w') as f:
            json.dump(self.logs, f, indent=2)
