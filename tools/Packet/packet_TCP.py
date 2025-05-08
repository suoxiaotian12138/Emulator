from typing import Set
from tools.Crypt.serialization import encode, decode
import threading
import time
from queue import Empty
import asyncio
import socket

from typing import Dict, Tuple, Optional, Callable









def recv_tcp(sock: socket.socket, buffer_size: int = 65535):
    """Non-blocking receive from TCP socket, returns data or None"""
    try:
        data = sock.recv(buffer_size)
        if not data:
            return None  # Connection closed
        return data
    except BlockingIOError:
        return None


def handle_tcp(result, buffer):
    """Decode received TCP data and store in byte buffer"""
    if result is None:
        return
    data, _ = result
    # obj = decode(data)
    buffer.add(data)


def handle_tcp_with_addr(result, buffer):
    """Store received (data, addr) into packet queue"""
    if result is None:
        return
    data, addr = result
    # obj = decode(data)
    buffer.add(data, addr)

def send_tcp(sock: socket.socket, message: bytes) -> bool:
    """Use an existing TCP socket to send a message (long connection)"""
    try:
        if not isinstance(message, bytes):
            message = encode(message)
        sock.sendall(message)
        return True
    except Exception as e:
        print(f"[TCP Send Error] Failed to send via socket -> {e}")
        return False






async def connection_manager(
        connection_map: Dict[socket.socket, Tuple[str, int]],
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
        for conn, addr in current_connections:
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
        connection_map: Dict[socket.socket, Tuple[str, int]],
        buffer,
        buffer_size: int = 4096,
        timeout: float = 600.0,
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
                handler((data, addr), buffer)

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
        connection_map: Dict[socket.socket, Tuple[str, int]],
        lock: asyncio.Lock,
):
    """持续接受新的TCP连接"""
    listener_socket.setblocking(False)

    while True:
        try:
            # 尝试接受新连接
            conn, addr = await asyncio.get_event_loop().sock_accept(listener_socket)
            conn.setblocking(False)
            print(f"[Accepted] {addr[0]}:{addr[1]}")

            # 添加到连接映射
            async with lock:
                connection_map[conn] = addr

        except asyncio.CancelledError:
            # 任务被取消时退出
            break
        except Exception as e:
            print(f"[Accept Error] {e}")
            # 发生错误时短暂等待
            await asyncio.sleep(0.1)


async def listen_to_tcp(
        listener_socket: socket.socket,
        connection_map: Dict[socket.socket, Tuple[str, int]],
        lock: asyncio.Lock,
        buffer,
        buffer_size: int = 4096,
        timeout: float = 600.0,
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
























class ByteBuffer:
    """Byte-oriented buffer (like Tor's buf_t), stores raw data with length-based decoding."""

    def __init__(self):
        self.buffer = bytearray()

    def add(self, data: bytes):
        """Append raw data to the buffer."""
        self.buffer.extend(data)

    def extract_message_by_size(self, size: int) -> bytes:
        """Remove and return 'size' bytes from the buffer."""
        if len(self.buffer) < size:
            raise ValueError("Not enough data")
        result = self.buffer[:size]
        del self.buffer[:size]
        return decode(result)

    def extract_message_by_head(self):
        """
        Try to decode a complete message from the buffer.
        Returns the decoded object if a full message is available, else None.
        """
        length = self.get_next_length()

        if length is None or len(self.buffer) < 4 + length:
            return None  # Not enough data

        raw_data = self.read(4 + length)
        encoded_payload = raw_data[4:]
        print("raw_data",raw_data)
        print("encode_data",encoded_payload)
        return decode(encoded_payload)

    def read(self, size: int) -> bytes:
        """Peek at the first 'size' bytes without removing them."""
        if len(self.buffer) < size:
            raise ValueError("Not enough data to peek")
        result = self.buffer[:size]
        del self.buffer[:size]
        return result

    def get_next_length(self) -> Optional[int]:
        """Read the next message length from the buffer (4 bytes), return None if not ready."""
        if len(self.buffer) < 4:
            return None
        return int.from_bytes(self.buffer[:4], 'big')

    def __len__(self):
        return len(self.buffer)


def buffer_consumer(wrapper: ByteBuffer, stop_event, name="Consumer"):
    while not stop_event.is_set():
        try:

            while True:
                obj = wrapper.extract_message_by_head()
                if obj is None:
                    break
                print(f"[{name}] Decoded from : {obj}")
        except Empty:
            continue

def encode_with_length(obj: any) -> bytes:
    body = encode(obj)
    return len(body).to_bytes(4, 'big') + body


def start_server(port=8888, buffer=None):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(('127.0.0.1', port))
    server_sock.listen()

    conn_map = {}
    lock = asyncio.Lock()

    try:
        loop.run_until_complete(
            listen_to_tcp(
                server_sock,
                conn_map,
                lock,
                buffer,
                handler=lambda res, buf: handle_tcp(res, buf),
            )
        )
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()

def mock_client(name: str, message: str, port=8888, repeat=5, delay=0.001):
    time.sleep(1)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', port))

        for i in range(repeat):
            msg = encode_with_length(f"{name} says {message} [{i}]")
            if not send_tcp(s, msg):
                break
            time.sleep(delay)

        s.close()
    except Exception as e:
        print(f"[Client-{name}] Error: {e}")

def run_test():
    wrapper = ByteBuffer()
    stop_event = threading.Event()

    server_thread = threading.Thread(target=start_server, args=(8888, wrapper), daemon=True)
    consumer_thread = threading.Thread(target=buffer_consumer, args=(wrapper, stop_event), daemon=True)

    server_thread.start()
    consumer_thread.start()

    client_threads = []
    for i in range(5):
        t = threading.Thread(target=mock_client, args=(f"client{i}", f"hello from {i}"))
        t.start()
        client_threads.append(t)

    for t in client_threads:
        t.join()

    time.sleep(5)
    stop_event.set()
    consumer_thread.join()



if __name__ == "__main__":
    run_test()
