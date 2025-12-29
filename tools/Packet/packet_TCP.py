from typing import Set
import time
import sys, contextlib
from typing import Dict, Tuple, Callable
from typing import Optional
from tools.Crypt.serialization import decode

import errno, ssl
import asyncio, ssl, socket, time
from typing import Callable, Tuple, Optional

from tools.Network_Management.tls_registry import (
    get_server_ctx, get_client_ctx,
    get_global_sem, get_node_sem,
)


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
            # print(f"[BufferAdd] {len(data)} bytes added, total={len(self.buffer)}")
            self.condition.notify_all()

    async def extract_by_head(self):
        """Extract a message with 4-byte big-endian length prefix."""
        while True:
            async with self.condition:
                length = self.get_next_length()
                if length is not None and len(self.buffer) >= 4 + length:
                    raw = self.read(4 + length)
                    print(f"[BufferExtract] {length} bytes extracted, remaining={len(self.buffer)}")
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

# async def monitor_connection_tls(
#     conn: socket.socket,
#     addr: Tuple[str, int],
#     buffer,
#     buffer_size: int = 4094,
#     timeout: float = 600.0,
# ):
#     """
#     TLS socket 数据接收与缓存：
#     - 纯异步 recv + await 写入 buffer
#     - 不使用 queue，不再拆分成两协程
#     - handler 默认为 buffer.add，仅做轻量缓冲
#     """
#     loop = asyncio.get_running_loop()
#     conn.setblocking(False)  # 必须设置为非阻塞
#     identifier = f"{addr[0]}:{addr[1]}"
#
#     try:
#         while True:
#             try:
#                 data = await asyncio.wait_for(
#                     recv_any(loop, conn, buffer_size),
#                     timeout=timeout
#                 )
#
#                 if not data:  # FIN 或连接关闭
#                     print(f"[PeerClose] {identifier} FIN received")
#                     break
#
#                 await buffer.add(data)
#
#             except asyncio.TimeoutError:
#                 print(f"[Timeout] {identifier} >{timeout}s no data")
#                 break
#
#             except Exception as e:
#                 print(f"[RecvErr] {identifier} {e}")
#                 break
#
#     finally:
#         with contextlib.suppress(Exception):
#             conn.shutdown(socket.SHUT_RDWR)
#         conn.close()


# async def accept_tls_connections(listener_sock: socket.socket,
#                                  tls_connector: TLSConnector,
#                                  on_accept: Callable[[socket.socket, tuple[str,int]], None]):
#     """
#     接收 TCP -> 升级 TLS -> 立即交给 on_accept
#     无内部 queue，不存在 '握手完成但没人收' 的窗口
#     """
#     loop = asyncio.get_running_loop()
#
#     async def handle(raw_sock, addr):
#         try:
#             tls_sock = await tls_connector.wrap_tls(raw_sock)
#             # 👇 握手成功后立刻调用回调（on_accept 里会启动 monitor）
#             on_accept(tls_sock, addr)
#         except Exception as e:
#             print(f"[!] TLS handshake failed for {addr}: {e}")
#             raw_sock.close()
#
#     while True:
#         raw_sock, addr = await loop.sock_accept(listener_sock)
#         asyncio.create_task(handle(raw_sock, addr))

class _DummyProto(asyncio.Protocol):
    """在 start_tls() 前**暂停**读取，防止吞包。"""
    def connection_made(self, transport):
        self.transport = transport
        transport.pause_reading()          # ⬅ 关键：先暂停
    def data_received(self, data):
        # 不应收到任何数据；如果真收到说明 pause_reading 太晚
        pass



class TLSConnector:
    """保留作配置容器（兼容旧调用）；上下文/并发控制交给 tls_registry。"""
    def __init__(self,
                 certfile: str = "cert.pem",
                 keyfile: str = "key.pem",
                 max_concurrent_tls: int = 2000,   # 仅作信息参考；不在此处限流
                 handshake_timeout: float = 15.0):
        self.certfile = certfile
        self.keyfile = keyfile
        self.handshake_timeout = handshake_timeout


async def accept_tls_connections(
    listener_sock: socket.socket,
    tls_connector: TLSConnector,
    on_accept: Callable[[asyncio.StreamReader, asyncio.StreamWriter, tuple[str,int]], None],
    *,
    node_id: str,
    on_server_ready=None
) -> None:
    loop = asyncio.get_running_loop()
    handshake_timeout = getattr(tls_connector, "handshake_timeout", 15.0)

    if sys.platform.startswith("win"):
        # Windows: 不要 start_tls，直接交给 asyncio TLS
        server = await asyncio.start_server(
            on_accept,
            sock=listener_sock,
            ssl=get_server_ctx(node_id),
            ssl_handshake_timeout=handshake_timeout,
            backlog=2048
        )
    else:
        # Linux/macOS: 先明文 accept，再 start_tls 升级
        async def plain_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            transport = writer.transport
            transport.pause_reading()
            try:
                async with get_global_sem(), get_node_sem(node_id):
                    tls_transport = await loop.start_tls(
                        transport, writer._protocol,
                        sslcontext=get_server_ctx(node_id),
                        server_side=True,
                        ssl_handshake_timeout=handshake_timeout,
                    )
            except Exception as e:
                transport.close()
                return

            reader2 = asyncio.StreamReader(limit=64*1024)  # ★ buffer 提大
            proto2  = asyncio.StreamReaderProtocol(reader2)
            tls_transport.set_protocol(proto2)
            tls_transport.resume_reading()
            writer2 = asyncio.StreamWriter(tls_transport, proto2, reader2, loop)

            peer = tls_transport.get_extra_info("peername")
            on_accept(reader2, writer2, peer)

        server = await asyncio.start_server(plain_handler, sock=listener_sock, backlog=2048)
    if on_server_ready:
        on_server_ready()
    async with server:
        await server.serve_forever()

# —— 出站：统一拨号 + 受限握手
async def dial_tls(
    remote_addr: tuple[str, int],
    *,
    source_ip: str | None = None,
    node_id: str | None = None,
    timeout: float = 15.0,
    ssl_ctx: Optional[ssl.SSLContext] = None,
    keylog_path: str | None = None,
):
    ctx = ssl_ctx or get_client_ctx()
    if keylog_path:
        ctx.keylog_filename = keylog_path
    nid = node_id or source_ip or "default"

    async with get_global_sem(), get_node_sem(nid):
        reader, writer = await asyncio.open_connection(
            remote_addr[0], remote_addr[1],
            ssl=ctx,
            server_hostname=None,
            ssl_handshake_timeout=timeout,
            local_addr=(source_ip, 0) if source_ip else None
        )
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj:
        if keylog_path:
            with contextlib.suppress(Exception):
                setattr(ssl_obj, "_keylog_path", keylog_path)
        print(f"[dial_tls] {remote_addr} -> TLS {ssl_obj.version()} {ssl_obj.cipher()}")
    return reader, writer

async def monitor_connection_tls(
    conn: socket.socket,
    addr: Tuple[str, int],
    buffer,
    buffer_size: int = 4094,
    timeout: float = 600.0,
):
    loop = asyncio.get_running_loop()
    conn.setblocking(False)
    identifier = f"{addr[0]}:{addr[1]}"

    try:
        while True:
            try:
                data = await asyncio.wait_for(
                    recv_any(loop, conn, buffer_size),
                    timeout=timeout
                )
                if not data:                 # FIN
                    print(f"[PeerClose] {identifier} FIN received")
                    break
                await buffer.add(data)

            except ssl.SSLWantReadError:
                # ↻ 非阻塞场景下很常见：继续下一轮
                continue

            except OSError as e:
                # Windows 下 SSLWantRead 会包装成 OSError 10035
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK, 10035):
                    continue
                print(f"[RecvErr] {identifier} {e}")
                break            # 其它 OSError 才视为致命

            except asyncio.TimeoutError:
                print(f"[Timeout] {identifier} >{timeout}s no data")
                break

    finally:
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
                sock.sendall(data)
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


