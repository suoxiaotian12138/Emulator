import socket

HOST = "192.168.66.243"
PORT = 8000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))

# 把 backlog 从 5 提高，比如 1024（上限还会受 somaxconn 影响）
server.listen(1024)

print(f"[SERVER] Listening on {HOST}:{PORT} ...")

while True:
    conn, addr = server.accept()
    print(f"\n[SERVER] Connection from {addr}")

    data = conn.recv(4096)
    if not data:
        print("[SERVER] No data received.")
    else:
        print("[SERVER] Received:")
        print(data.decode(errors="ignore"))

        response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
        conn.sendall(response)

    conn.close()
    print("[SERVER] Connection closed.")
