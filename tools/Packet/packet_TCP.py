from typing import Set
import time
import ssl, contextlib
from typing import Dict, Tuple, Callable
from typing import Optional
from tools.Crypt.serialization import decode
import asyncio
import socket
from ssl import SSLWantReadError, SSLWantWriteError

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

    async def extract_by_size(self, size: int = 514, timeout: float = 5.0) -> bytes | None:
        """Extract exactly `size` bytes, wait with timeout if not enough data."""
        start = time.time()

        while True:
            async with self.condition:
                if len(self.buffer) >= size:
                    return self.read(size)

                remaining = timeout - (time.time() - start)
                if remaining <= 0:
                    # print(f"[ByteBuffer] Timeout: needed {size}, but only {len(self.buffer)} available")
                    return None

                # print(f"[ByteBuffer] Waiting for {size} bytes, currently have {len(self.buffer)}")
                try:
                    await asyncio.wait_for(self.condition.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    # print(f"[ByteBuffer] Condition wait timeout (needed {size}, have {len(self.buffer)})")
                    return None
    async def wait_for(self, size: int):
        """阻塞直到缓存 ≥ size 字节。"""
        async with self.condition:
            while len(self.buffer) < size:
                await self.condition.wait()

    async def peek(self, size: int) -> bytes | None:
        """只查看前 size 字节，不弹出。"""
        async with self.condition:
            if len(self.buffer) >= size:
                return bytes(self.buffer[:size])
            return None

    async def pop(self, size: int) -> bytes:
        """在确保数据足够后一次性弹出 size 字节。"""
        await self.wait_for(size)
        async with self.condition:
            data = self.buffer[:size]
            del self.buffer[:size]
            return bytes(data)

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
        # print("data:", data)
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


# async def send_tcp(sock: socket.socket, message: bytes):
#     """Use an existing TCP socket to send a message (long connection)"""
#     try:
#         assert isinstance(message, bytes), "Expected bytes"
#         sock.sendall(message)
#     except Exception as e:
#         print(f"[TCP Send Error] Failed to send via socket -> {e}")

async def send_tcp(loop: asyncio.AbstractEventLoop, sock: socket.socket, data: bytes):
    """
    安全地向非阻塞 (TLS) socket 写入；自动处理 EWOULDBLOCK / WANT_WRITE。
    """
    # Python 3.11+ 自带 loop.sock_sendall；低版本手动实现
    try:
        await loop.sock_sendall(sock, data)
    except AttributeError:                            # <3.11 fallback
        view = memoryview(data)
        while view:
            try:
                n = sock.send(view)
                view = view[n:]
            except (BlockingIOError, ssl.SSLWantWriteError):
                await asyncio.sleep(0)

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
                await handler((data, addr), buffer)

            except asyncio.TimeoutError:
                break
            except Exception as e:
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





# async def accept_tls_connections(listener_sock, ssl_ctx):
#     loop = asyncio.get_running_loop()
#     listener_sock.setblocking(False)
#     while True:
#         raw_sock, addr = await loop.sock_accept(listener_sock)
#         print(f"[+] Accepted raw {addr}")
#
#         def _wrap():
#             raw_sock.setblocking(True)   # 握手期间必须阻塞
#             tls_sock = ssl_ctx.wrap_socket(raw_sock, server_side=True)
#             tls_sock.setblocking(True)   # 后续所有阻塞I/O（如果你在线程池里用 recv）
#             return tls_sock
#
#         try:
#             tls_sock = await loop.run_in_executor(None, _wrap)
#             yield tls_sock, addr
#         except ssl.SSLError as e:
#             print("[!] TLS fail:", e)

async def accept_tls_connections(listener_sock: socket.socket, ssl_ctx: ssl.SSLContext):
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[tuple[socket.socket, tuple[str,int]]] = asyncio.Queue()

    # 内部：处理一次 TLS 握手并把结果放队列
    async def do_handshake(raw_sock: socket.socket, addr):
        def wrap():
            raw_sock.setblocking(True)  # 握手前必须阻塞
            tls_sock = ssl_ctx.wrap_socket(raw_sock, server_side=True, do_handshake_on_connect=True)
            tls_sock.setblocking(False)  # ★ 握手后立刻切成非阻塞 ★
            return tls_sock

        try:
            tls = await loop.run_in_executor(None, wrap)
            await queue.put((tls, addr))
        except ssl.SSLError as e:
            print(f"[!] TLS 握手失败 {addr}: {e}")
            raw_sock.close()

    # 背景：不停 accept raw socket，并发起 handshake 任务
    async def accept_loop():
        while True:
            raw_sock, addr = await loop.sock_accept(listener_sock)
            print(f"[+] Accepted raw {addr}")
            # 丢给后台去握手
            asyncio.create_task(do_handshake(raw_sock, addr))

    # 启动背景 accept
    asyncio.create_task(accept_loop())

    # 主循环：不断从 queue 拿到已完成握手的 tls_sock
    while True:
        tls_sock, addr = await queue.get()
        yield tls_sock, addr


async def monitor_connection_tls(
    conn: socket.socket,
    addr: Tuple[str, int],
    buffer,
    buffer_size: int = 4094,
    timeout: float = 600.0,
    handler: Optional[Callable[[Tuple[bytes, Tuple[str, int]], any], None]] = None,
):
    """
    - 不再 run_in_executor；靠 loop.sock_recv 做真正的异步 I/O
    - 仍然用 queue 把 I/O 与解析解耦，避免一个慢 handler 阻塞 recv
    """
    if handler is None:
        handler = handle_tcp

    loop = asyncio.get_running_loop()
    conn.setblocking(False)                      # ****** 关键：非阻塞 ******
    identifier = f"{addr[0]}:{addr[1]}"
    queue: asyncio.Queue[bytes] = asyncio.Queue(maxsize=256)
    alive = True

    # ------------ Task‑1: 纯异步 recv ----------------
    async def recv_loop():
        nonlocal alive
        last = time.monotonic()
        try:
            while alive:
                try:
                    data = await asyncio.wait_for(
                        recv_any(loop, conn, buffer_size),
                        timeout=timeout
                    )

                    if not data:  # ← 对端已优雅关闭 (FIN)
                        print(f"[PeerClose] {identifier} FIN received")
                        break  # ★ 立即退出循环，走 finally

                    await queue.put(data)
                    last = time.monotonic()

                except ssl.SSLError as e:
                    # WANT_READ / WANT_WRITE → 轻微等待后重试
                    if isinstance(e, (SSLWantReadError, SSLWantWriteError)) or \
                            e.errno in (ssl.SSL_ERROR_WANT_READ, ssl.SSL_ERROR_WANT_WRITE):
                        await asyncio.sleep(0.01)
                        continue
                    print(f"[RecvErr] {identifier} {e}")
                    break

                except asyncio.TimeoutError:
                    print(f"[Timeout] {identifier} >{timeout}s no data")
                    break

        finally:
            alive = False

    # ------------ Task‑2: 解析 / 业务处理 -------------
    async def process_loop():
        nonlocal alive
        try:
            while alive:
                try:
                    data = await queue.get()
                    await handler((data, addr), buffer)
                except Exception as e:
                    print(f"[HandlerErr] {identifier} {e}")
        finally:
            alive = False

    # ------------- 调度与清理 -------------------------
    recv_task = asyncio.create_task(recv_loop(),  name=f"recv-{identifier}")
    process_task = asyncio.create_task(process_loop(), name=f"proc-{identifier}")

    try:
        await asyncio.wait(
            [recv_task, process_task],
            return_when=asyncio.FIRST_COMPLETED
        )
    finally:
        alive = False
        recv_task.cancel()
        process_task.cancel()
        with contextlib.suppress(Exception):
            conn.shutdown(socket.SHUT_RDWR)
        conn.close()




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

async def send_any(loop: asyncio.BaseEventLoop, sock: socket.socket, data: bytes):
    """异步发送：TCP 走 sock_sendall；SSLSocket 在线程池 + 阻塞模式发送"""
    try:
        return await loop.sock_sendall(sock, data)       # 普通 TCP → 真异步
    except (TypeError, NotImplementedError):
        def _blocking_sendall():
            try:
                sock.setblocking(True)
                sock.sendall(data)  # 若触发 TLS alert，会 raise ssl.SSLError
            except Exception as e:
                print(f"[SendErr] {sock.getpeername()} {e}")
                raise
            finally:
                sock.setblocking(False)
        return await loop.run_in_executor(None, _blocking_sendall)


async def recv_any(loop: asyncio.BaseEventLoop, sock: socket.socket, nbytes: int) -> bytes:
    """异步接收：TCP 走 sock_recv；SSLSocket 在线程池 + 阻塞模式接收"""
    try:
        return await loop.sock_recv(sock, nbytes)        # 普通 TCP
    except (TypeError, NotImplementedError):
        def _blocking_recv():
            blocking = sock.getblocking()
            try:
                sock.setblocking(True)
                return sock.recv(nbytes)
            finally:
                sock.setblocking(blocking)
        return await loop.run_in_executor(None, _blocking_recv)