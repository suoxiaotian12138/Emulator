from typing import Set
import time
import ssl
import socket

from typing import Dict, Tuple, Optional, Callable


import asyncio
from typing import Optional
from tools.Crypt.serialization import decode


class ByteBuffer:
    """
    An asyncio-aware ByteBuffer that supports:
    - extract_by_head(): length-prefixed decoding
    - extract_by_size(n): fixed-length byte extraction
    """

    def __init__(self):
        self.buffer = bytearray()
        self.condition = asyncio.Condition()

    async def add(self, data: bytes):
        """Append raw data and notify waiting consumers."""
        async with self.condition:
            self.buffer.extend(data)
            self.condition.notify_all()

    async def extract_by_head(self):
        """Extract a message with 4-byte big-endian length prefix."""
        while True:
            async with self.condition:
                length = self.get_next_length()
                if length is not None and len(self.buffer) >= 4 + length:
                    raw = self.read(4 + length)
                    return decode(raw[4:])
                await self.condition.wait()

    async def extract_by_size(self, size: int = 514) -> bytes:
        """Extract exactly `size` bytes, wait if not enough data."""
        while True:
            async with self.condition:
                if len(self.buffer) >= size:
                    return self.read(size)
                await self.condition.wait()

    def get_next_length(self) -> Optional[int]:
        """Return next message's length if available."""
        if len(self.buffer) < 4:
            return None
        return int.from_bytes(self.buffer[:4], 'big')

    def read(self, size: int) -> bytes:
        """Read and remove first `size` bytes from buffer."""
        if len(self.buffer) < size:
            raise ValueError("Insufficient data")
        result = self.buffer[:size]
        del self.buffer[:size]
        return result

    def __len__(self):
        return len(self.buffer)


def recv_tcp(sock: socket.socket, buffer_size: int = 65535):
    """Non-blocking receive from TCP socket, returns data or None"""
    try:
        data = sock.recv(buffer_size)
        if not data:
            return None  # Connection closed
        return data
    except BlockingIOError:
        return None


async def handle_tcp(result, buffer):
    """Decode received TCP data and store in byte buffer"""
    if result is None:
        return
    data, _ = result
    await buffer.add(data)



def send_tcp(sock: socket.socket, message: bytes) -> bool:
    """Use an existing TCP socket to send a message (long connection)"""
    try:
        assert isinstance(message, bytes), "Expected bytes"
        sock.sendall(message)
        return True
    except Exception as e:
        print(f"[TCP Send Error] Failed to send via socket -> {e}")
        return False


async def connection_manager(
        connection_map: Dict[Tuple[str, int], socket.socket],
        lock: asyncio.Lock,
        buffer,
        buffer_size: int = 4096,
        timeout: float = 600.0,
        handler: Optional[Callable[[Tuple[bytes, Tuple[str, int]], any], None]] = None,
):
    """持续监控新连接并为它们创建监听任务"""
    # 存储所有活跃的监控任务
    active_tasks: Set[asyncio.Task] = set()

    while True:
        # 获取当前连接快照
        async with lock:
            current_connections = list(connection_map.items())

        # 通过ID跟踪已监控的连接
        monitored_ids = {t.get_name() for t in active_tasks}

        # 为新连接创建监控任务
        for addr, conn in current_connections:
            conn_id = str(id(conn))
            if conn_id not in monitored_ids:
                task = asyncio.create_task(
                    monitor_connection(conn, addr, lock, connection_map, buffer, buffer_size, timeout, handler),
                    name=conn_id
                )
                active_tasks.add(task)
                task.add_done_callback(active_tasks.discard)

        # 暂停以减少CPU使用
        await asyncio.sleep(0.1)


async def monitor_connection(
        conn: socket.socket,
        addr: Tuple[str, int],
        lock: asyncio.Lock,
        connection_map: Dict[Tuple[str, int], socket.socket],
        buffer,
        buffer_size: int = 4096,
        timeout: float = 60.0,
        handler: Optional[Callable[[Tuple[bytes, Tuple[str, int]], any], None]] = None,
):
    if handler is None:
        handler = handle_tcp

    loop = asyncio.get_running_loop()
    conn.setblocking(True)  # ✅ run_in_executor 内允许阻塞
    identifier = f"{addr[0]}:{addr[1]}"
    last_recv_time = time.time()

    try:
        while True:
            try:
                # 通过线程池执行阻塞接收，最多等待 timeout 秒
                data = await asyncio.wait_for(
                    loop.run_in_executor(None, lambda: recv_tcp(conn, buffer_size)),
                    timeout=timeout
                )

                now = time.time()

                if data is None or len(data) == 0:
                    if now - last_recv_time > timeout:
                        print(f"[Timeout] {identifier} - No data for {timeout}s, closing")
                        break
                    await asyncio.sleep(0.1)
                    continue

                # 有效数据，更新活跃时间
                last_recv_time = now
                await handler((data, addr), buffer)

            except asyncio.TimeoutError:
                print(f"[Hard Timeout] {identifier} - Socket call hung, closing")
                break
            except Exception as e:
                print(f"[Recv Error] {identifier} -> {e}")
                break

    finally:
        try:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            conn.close()
        except Exception:
            pass

        async with lock:
            connection_map.pop(conn, None)
        print(f"[Cleaned up] {identifier}")



async def accept_connections(
        listener_socket: socket.socket,
        connection_map: Dict[Tuple[str, int], socket.socket],
        lock: asyncio.Lock,
):
    """持续接受新的TCP连接"""
    listener_socket.setblocking(False)

    while True:
        try:
            # 尝试接受新连接
            conn, addr = await asyncio.get_event_loop().sock_accept(listener_socket)
            conn.setblocking(False)
            # print(f"[Accepted] {addr[0]}:{addr[1]}")

            # 添加到连接映射
            async with lock:
                connection_map[addr] = conn

        except asyncio.CancelledError:
            # 任务被取消时退出
            break
        except Exception as e:
            print(f"[Accept Error] {e}")
            # 发生错误时短暂等待
            await asyncio.sleep(0.1)


async def listen_to_tcp(
        listener_socket: socket.socket,
        connection_map: Dict[Tuple[str, int], socket.socket],
        lock: asyncio.Lock,
        buffer,
        buffer_size: int = 4096,
        timeout: float = 60.0,
        handler: Optional[Callable[[Tuple[bytes, Tuple[str, int]], any], None]] = None,
):
    """
    Start listening for new TCP connections and monitor all accepted connections.

    Args:
        listener_socket: A TCP socket already bound and listening.
        connection_map: Shared mapping of {socket: (host, port)}.
        lock: An asyncio.Lock protecting connection_map.
        buffer: Shared buffer for handling received data.
        buffer_size: Read chunk size.
        timeout: Timeout per read.
        handler: Optional data handling function.
    """
    listener_socket.setblocking(False)
    print(f"[Listening] TCP server on {listener_socket.getsockname()}")

    # 创建接受连接和管理连接的任务
    accept_task = asyncio.create_task(accept_connections(listener_socket, connection_map, lock))
    manager_task = asyncio.create_task(connection_manager(connection_map, lock, buffer, buffer_size, timeout, handler))

    try:
        # 等待这两个任务，直到被取消
        await asyncio.gather(accept_task, manager_task)
    except asyncio.CancelledError:
        # 取消所有任务
        accept_task.cancel()
        manager_task.cancel()

        # 等待任务完成取消
        await asyncio.gather(accept_task, manager_task, return_exceptions=True)



async def accept_tls_connections(
    listener_socket: socket.socket,
    connection_map: Dict[Tuple[str, int], socket.socket],
    lock: asyncio.Lock,
    ssl_context: ssl.SSLContext,
):
    """
    Accept only TLS connections, wrap using ssl_context,
    and store the TLS sockets in connection_map.
    """
    loop = asyncio.get_running_loop()
    listener_socket.setblocking(False)

    while True:
        try:
            # 等待连接
            raw_conn, addr = await loop.sock_accept(listener_socket)
            raw_conn.setblocking(True)  # 必须为 blocking 才能进行 TLS 握手
            print("pb:01")
            # 尝试进行 TLS 握手包装
            try:
                tls_conn = await loop.run_in_executor(
                    None,  # 使用默认线程池
                    lambda: ssl_context.wrap_socket(raw_conn, server_side=True)
                )

                tls_conn.setblocking(False)  # ✅ handshake 完成后恢复非阻塞
                print("pb:02")
                # 保存到映射表
                async with lock:
                    connection_map[addr] = tls_conn

                print(f"[TLS Accepted] {addr[0]}:{addr[1]}")
            except ssl.SSLError as e:
                print(f"[TLS Handshake Failed] {addr}: {e}")
                raw_conn.close()

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Accept Error] {e}")
            await asyncio.sleep(0.1)



async def listen_to_tls(
        listener_socket: socket.socket,
        connection_map: Dict[Tuple[str, int], socket.socket],
        lock: asyncio.Lock,
        buffer,
        ssl_context: ssl.SSLContext,
        buffer_size: int = 4096,
        timeout: float = 60.0,
        handler: Optional[Callable[[Tuple[bytes, Tuple[str, int]], any], None]] = None,

):
    listener_socket.setblocking(False)
    print(f"[Listening] Tls server on {listener_socket.getsockname()}")

    # 创建接受连接和管理连接的任务
    accept_task = asyncio.create_task(accept_tls_connections(listener_socket, connection_map, lock, ssl_context))
    manager_task = asyncio.create_task(connection_manager(connection_map, lock, buffer, buffer_size, timeout, handler))

    try:
        # 等待这两个任务，直到被取消
        await asyncio.gather(accept_task, manager_task)
    except asyncio.CancelledError:
        # 取消所有任务
        accept_task.cancel()
        manager_task.cancel()

        # 等待任务完成取消
        await asyncio.gather(accept_task, manager_task, return_exceptions=True)



def is_socket_alive(sock: socket.socket) -> bool:
    if sock is None:
        return False
    try:
        sock.setblocking(False)
        sock.recv(0)
        return True  # 没有异常表示还连着
    except BlockingIOError:
        return True  # 没有数据，但连接仍存在
    except ConnectionResetError:
        return False  # 对方关闭了连接
    except OSError:
        return False  # socket 出错了
    finally:
        sock.setblocking(True)