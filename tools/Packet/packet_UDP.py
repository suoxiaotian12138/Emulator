import socket
import multiprocessing
import time
from tools.Crypt.serialization import encode, decode
from collections import deque
import asyncio


class PacketQueue:
    """Packet queue with address info, stores (data, addr)"""
    def __init__(self):
        self.queue = deque()

    def add(self, data: bytes, addr):
        self.queue.append((data, addr))

    def pop(self):
        return decode(self.queue.popleft()) if self.queue else None

    def __len__(self):
        return len(self.queue)


def send_udp(sock: socket.socket, message: bytes, target_ip: str, target_port: int):
    """Send a UDP packet with given message"""
    try:
        if not isinstance(message, bytes):
            message = encode(message)
        sock.sendto(encode(message), (target_ip, target_port))
    except Exception as e:
        print(f"[Send Error] {e}")


def recv_udp(sock: socket.socket, buffer_size: int = 65535):
    """Non-blocking receive, returns (data, addr) or None"""
    try:
        data, addr = sock.recvfrom(buffer_size)
        return data, addr
    except BlockingIOError:
        return None


async def send_udp_async(sock: socket.socket, message: bytes, target_ip: str, target_port: int):
    """Send a UDP packet with given message"""
    try:
        if not isinstance(message, bytes):
            message = encode(message)
        sock.sendto(encode(message), (target_ip, target_port))
    except Exception as e:
        print(f"[Send Error] {e}")


async def recv_udp_async(sock: socket.socket, buffer_size: int = 65535):
    """Proper non-blocking UDP receive using asyncio"""
    loop = asyncio.get_event_loop()
    try:
        data, addr = await loop.sock_recvfrom(sock, buffer_size)
        return data, addr
    except BlockingIOError:
        return None
    except Exception as e:
        print("recv_udp error:", e)
        return None


def handle_udp(result, buffer: PacketQueue):
    """Store received (data, addr) into packet queue"""
    if result is None:
        return
    data, addr = result
    buffer.add(data, addr)



def receiver():
    packet_queue = PacketQueue()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 9999))
    sock.setblocking(False)

    print("[Recv] Listening on 127.0.0.1:9999")
    start_time = time.time()

    while time.time() - start_time < 5:  # Run for 5 seconds
        result = recv_udp(sock)
        handle_udp(result, packet_queue)

        # Debug output

        if len(packet_queue) > 0:
            pkt = packet_queue.pop()
            print(f"[PacketQueue] From {pkt[1]}: {decode(pkt[0])}")

        time.sleep(0.1)
    sock.close()

def sender():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 8888))
    for i in range(10):
        msg = f"Message {i}"
        send_udp(sock, msg, "127.0.0.1", 9999)
        time.sleep(0.5)
    sock.close()





def test_udp_buffer_handlers():
    """Test UDP send/recv with both ByteBuffer and PacketQueue"""

    recv_proc = multiprocessing.Process(target=receiver)
    send_proc = multiprocessing.Process(target=sender)

    recv_proc.start()
    send_proc.start()

    recv_proc.join()
    send_proc.join()

    print("[Test] UDP buffer handler test completed.")


if __name__ == "__main__":
    test_udp_buffer_handlers()