import socket
import json
import threading
import time

class GlobalMonitorServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.addr = (host, port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.addr)

        self.running = True
        self.log_buffer = []  # 可替换为数据库/持久化存储

        self.start_time = time.time()

        print(f"[GlobalMonitor] Listening on {host}:{port}")

    def start(self):
        t = threading.Thread(target=self.listen_loop, daemon=True)
        t.start()

    def listen_loop(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(8192)
                log = json.loads(data.decode())
                self.handle_log(log, addr)
            except Exception as e:
                print(f"[Monitor-ERROR] {e}")

    def handle_log(self, log: dict, addr):
        self.log_buffer.append(log)
        print(f"[Monitor-RECV] from {addr}: {log}")

    def stop(self):
        self.running = False
        self.sock.close()

    def summary(self):
        print(f"Total logs collected: {len(self.log_buffer)}")
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
