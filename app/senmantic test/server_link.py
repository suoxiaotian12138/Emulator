# server_sink.py
# A deterministic TCP sink server for Tor/TorBox semantic validation.
# It reads until the client closes, then replies once and closes.

import os
import socket
import threading
import time

HOST = os.environ.get("SINK_HOST", "192.168.66.243")
PORT = int(os.environ.get("SINK_PORT", "8000"))
BACKLOG = int(os.environ.get("SINK_BACKLOG", "1024"))
RECV_BUF = int(os.environ.get("SINK_RECV_BUF", "65536"))
PRINT_EVERY_MB = int(os.environ.get("SINK_PRINT_EVERY_MB", "10"))

def handle_conn(conn: socket.socket, addr):
    conn.settimeout(30)
    total = 0
    last_print = 0
    t0 = time.time()

    try:
        while True:
            chunk = conn.recv(RECV_BUF)
            if not chunk:
                break
            total += len(chunk)

            mb = total // (1024 * 1024)
            if mb - last_print >= PRINT_EVERY_MB:
                last_print = mb
                print(f"[SINK] {addr} received {mb} MB ...")

        # Reply once (optional). Keep it tiny.
        resp = b"OK"
        try:
            conn.sendall(resp)
        except Exception:
            pass

    except socket.timeout:
        print(f"[SINK] {addr} timeout, closing.")
    except Exception as e:
        print(f"[SINK] {addr} error: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass

        dt = time.time() - t0
        mb = total / (1024 * 1024)
        print(f"[SINK] {addr} closed. total={mb:.2f} MB, time={dt:.2f}s")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(BACKLOG)

    print(f"[SINK] Listening on {HOST}:{PORT} backlog={BACKLOG}")

    while True:
        conn, addr = server.accept()
        print(f"[SINK] Connection from {addr}")
        t = threading.Thread(target=handle_conn, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    main()
