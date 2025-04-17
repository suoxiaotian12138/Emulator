import socket
import threading
import json
import time
from collections import defaultdict

class GlobalMonitorServer:
    def __init__(self, host='0.0.0.0', port=9999, timeout=30):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)

        self.running = True
        self.trace_logs = defaultdict(list)      # trace_id -> list of logs
        self.trace_last_update = dict()          # trace_id -> last timestamp
        self.completed_traces = set()            # 已完成 trace_id
        self.timeout = timeout                   # 超时时间（秒）

        self.start_time = time.time()

        print(f"[GlobalMonitor] Listening on {host}:{port}")

    def start(self):
        threading.Thread(target=self.listen_loop, daemon=True).start()
        threading.Thread(target=self.cleanup_loop, daemon=True).start()
        threading.Thread(target=self.stat_loop, daemon=True).start()

    def stat_loop(self):
        while self.running:
            time.sleep(30)  # 每隔30秒统计一次
            self.aggregate_network_stats()

    def aggregate_network_stats(self):
        completed = list(self.completed_traces)
        if not completed:
            print("[Stats] 暂无完成 trace，跳过统计")
            return

        total = len(completed)
        dropped = 0
        delays = []

        for trace_id in completed:
            logs = self.trace_logs.get(trace_id, [])
            events = {log['event']: log for log in logs}

            if 'drop' in events:
                dropped += 1
            elif 'dest' in events and 'send' in events:
                delay = events['dest']['time'] - events['send']['time']
                delays.append(delay)
            else:
                # 其他情况（如超时），视为 drop
                dropped += 1

        loss_rate = dropped / total
        avg_delay = sum(delays) / len(delays) if delays else None

        print("\n[Network Stats]")
        print(f"  ✅ 完成 trace 数: {total}")
        print(f"  ❌ 丢失 trace 数: {dropped}")
        print(f"  📉 丢包率: {loss_rate:.2%}")
        if avg_delay is not None:
            print(f"  🕒 平均端到端延迟: {avg_delay:.3f} 秒")
        else:
            print(f"  🕒 平均端到端延迟: 无可用数据")

    def listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(8192)
                log = json.loads(data.decode())
                self.handle_log(log)
            except Exception as e:
                print(f"[Monitor-ERROR] {e}")

    def handle_log(self, log: dict):
        trace_id = log.get("trace_id")
        if not trace_id:
            print(log)
            print("asdaddsadsaasdasdsdaasd")
            return

        # 更新 log 信息
        self.trace_logs[trace_id].append(log)
        self.trace_last_update[trace_id] = time.time()

        # 检查是否是终结事件
        if log["event"] in ("drop", "dest"):
            self.mark_trace_complete(trace_id, reason=f"[{log['event'].upper()}]")

        # print(f"[Monitor-RECV] {trace_id} -> {log['event']} @ {log['node']}")

    def mark_trace_complete(self, trace_id, reason="[COMPLETE]"):
        if trace_id not in self.completed_traces:
            print(f"[Trace-FINISHED] {trace_id} {reason}")
            self.completed_traces.add(trace_id)
            self.process_trace(trace_id)

    def cleanup_loop(self):
        while self.running:
            time.sleep(10)
            now = time.time()
            for trace_id, last_time in list(self.trace_last_update.items()):
                if trace_id in self.completed_traces:
                    continue
                if now - last_time > self.timeout:
                    self.mark_trace_complete(trace_id, reason="[TIMEOUT]")

    def process_trace(self, trace_id):
        """
        对 trace 日志进行处理，例如打印完整路径等
        """
        logs = self.trace_logs.get(trace_id, [])
        print(f"\n[Trace Summary] trace_id = {trace_id}")
        for log in sorted(logs, key=lambda x: x["time"]):
            print(f"  {log['time']} | {log['event']:7} | {log['src']} <- {log.get('node')} -> {log.get('dst')}")

    def stop(self):
        self.running = False
        self.sock.close()

    def summary(self):
        print(f"Total traces received: {len(self.trace_logs)}")
        print(f"Completed traces: {len(self.completed_traces)}")
        print(f"Running time: {time.time() - self.start_time:.2f}s")



if __name__ == "__main__":
    monitor = GlobalMonitorServer(host='127.0.0.1',port=9999)
    monitor.start()

    # 可持续运行：
    try:
        while True:
            time.sleep(10)
            monitor.summary()
    except KeyboardInterrupt:
        print("Shutting down monitor...")
        monitor.stop()
