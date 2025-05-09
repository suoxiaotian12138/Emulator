import socket
import multiprocessing
import time
from tools.Crypt.serialization import encode, decode
from collections import deque
import asyncio


class PacketQueue:
    """Asynchronous Packet Queue with (data, addr) support."""
    def __init__(self):
        self.queue = asyncio.Queue()

    async def add(self, data: bytes, addr):
        await self.queue.put((data, addr))

    async def pop(self):
        data, addr = await self.queue.get()
        return decode(data), addr

    def __len__(self):
        return self.queue.qsize()


def send_udp(sock: socket.socket, message, target_ip: str, target_port: int):
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


async def send_udp_async(sock: socket.socket, message, target_ip: str, target_port: int):
    """真正异步发送 UDP 消息"""
    try:
        if not isinstance(message, bytes):
            message = encode(message)
        loop = asyncio.get_running_loop()
        await loop.sock_sendto(sock, message, (target_ip, target_port))

    except Exception as e:
        print(f"[Send Error] {e}")


async def recv_udp_async(sock: socket.socket, buffer_size: int = 65535):
    """Proper non-blocking UDP receive using asyncio"""
    try:
        loop = asyncio.get_running_loop()
        data, addr = await loop.sock_recvfrom(sock, buffer_size)
        return data, addr
    except BlockingIOError:
        return None
    except Exception as e:
        print("recv_udp error:", e)
        return None


async def handle_udp(result, buffer: PacketQueue):
    """Store received (data, addr) into packet queue"""
    if result is None:
        return
    data, addr = result
    await buffer.add(data, addr)





