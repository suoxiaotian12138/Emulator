import asyncio, contextlib
import logging
from typing import Optional
import struct
from enum import unique, Enum, auto
from examples.Tor_simplified.Tor_Cell import *
from examples.Tor_simplified.Tor_Window import TorWindow
import socket

logger = logging.getLogger(__name__)


@unique
class StreamState(Enum):
    Connecting = auto()
    Connected = auto()
    Disconnected = auto()
    Closed = auto()

class StreamsList:
    LOCK = asyncio.Lock()
    GLOBAL_STREAM_ID = 0

    def __init__(self, circuit):
        self._stream_map = {}
        self._circuit = circuit

    @staticmethod
    def get_next_stream_id():
        StreamsList.GLOBAL_STREAM_ID += 1
        return StreamsList.GLOBAL_STREAM_ID

    def create_new(self):
        stream = Tor_Stream(self.get_next_stream_id(), self._circuit)
        self._stream_map[stream.id] = stream
        return stream

    def set_stream(self, stream_id, target_addr):
        stream = Tor_Stream(stream_id, self._circuit, target_addr)
        self._stream_map[stream_id] = stream
        return stream

    def values(self):
        return self._stream_map.values()

    def remove(self, tor_stream):
        stream = self._stream_map.pop(tor_stream.id, None)
        if not stream:
            logger.debug('Stream #%i: not found in stream map', tor_stream.id)

    def get_by_id(self, stream_id):
        return self._stream_map.get(stream_id, None)


class Tor_Stream:
    def __init__(self, id, circuit, target_addr=None):
        self._id = id
        self._circuit = circuit
        self.target_addr = target_addr

        # --- 公共状态 ---
        self._state = StreamState.Closed
        self._closed = False
        self.connect_event = asyncio.Event()
        self.window = TorWindow(start=500, increment=50)
        self._close_lock = asyncio.Lock()

        # --- Client 专用: Buffer 模式 ---
        self._buffer = bytearray()
        self.data_event = asyncio.Event()

        # --- Server 专用: Exit Node 转发模式 ---
        # Node 收到 CellRelayData -> put 到此队列 -> pump_to_remote 读取写入 TCP
        self._to_remote = asyncio.Queue(maxsize=4096)
        self._remote_reader: Optional[asyncio.StreamReader] = None
        self._remote_writer: Optional[asyncio.StreamWriter] = None
        self._tasks = []

        self._closing = asyncio.Event()

        self.end_event = asyncio.Event()
        self._ended = False

    @property
    def id(self):
        return self._id

    # ================= Client 模式核心方法 =================

    def append(self, data):
        """Client端使用：收到 RelayData 后存入缓冲区"""
        self._buffer.extend(data)
        self.data_event.set()

    async def recv(self, bufsize):
        """Client端使用：从缓冲区读取数据"""
        await self.data_event.wait()
        if bufsize == -1:
            to_read = len(self._buffer)
        else:
            to_read = min(len(self._buffer), bufsize)

        result = self._buffer[:to_read]
        self._buffer = self._buffer[to_read:]

        if not self._buffer:
            self.data_event.clear()
        return result

    def set_end(self, cell_end):
        """Client端使用：收到 RelayEnd"""
        self._ended = True
        self.end_event.set()
        # wake recv() if it is waiting
        self.data_event.set()

    # ================= Server 模式核心方法 =================

    async def open_remote_raw(self, timeout=5.0):
        if not self.target_addr:
            raise ValueError("Target address not set")
        host, port = self.target_addr
        try:
            self._remote_reader, self._remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
        except asyncio.CancelledError:
            # ensure partial resources are closed
            with contextlib.suppress(Exception):
                if self._remote_writer:
                    self._remote_writer.close()
                    await self._remote_writer.wait_closed()
            raise

        with contextlib.suppress(Exception):
            sock = self._remote_writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def start_duplex_tasks(self, circuit, sock, cw_picker, spawner):
        """Server Exit 模式：启动双向转发"""
        if self._tasks:
            return

        # Task 1: Tor -> TCP (读取 _to_remote 队列)
        async def pump_to_remote():
            try:
                while not self._closing.is_set():
                    data = await self._to_remote.get()
                    if data is None:
                        break
                    if not self._remote_writer:
                        break
                    self._remote_writer.write(data)
                    await self._remote_writer.drain()
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            finally:
                # try half close
                with contextlib.suppress(Exception):
                    if self._remote_writer:
                        if hasattr(self._remote_writer, "write_eof"):
                            self._remote_writer.write_eof()
                            await self._remote_writer.drain()

        # Task 2: TCP -> Tor (读取 socket)
        async def pump_to_client():
            # cw = cw_picker(circuit, out_sock=sock)
            upstream_sock = circuit.circuit_nodes[0].sock
            cw = cw_picker(circuit, out_sock=upstream_sock)
            try:
                while not self._closing.is_set():
                    chunk = await self._remote_reader.read(16384)
                    if not chunk:
                        # remote EOF
                        end = CellRelayEnd(StreamReason.DONE, circuit.id)
                        await sock.send_cell(circuit.make_relay(end, stream_id=self.id))
                        break

                    for rc in self.make_relays_server(chunk):
                        if isinstance(rc, CellRelayData):
                            await self.window.acquire_send(1)
                            await cw.acquire_send(1)
                        await sock.send_cell(rc)
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
            finally:
                # 不要在这里 await self.aclose()，避免自取消链条
                return

        coro1 = pump_to_remote()
        coro2 = pump_to_client()
        try:
            t1 = spawner(coro1, name=f"stream_pump_remote:{circuit.id}:{self.id}")
            t2 = spawner(coro2, name=f"stream_pump_client:{circuit.id}:{self.id}")
        except Exception:
            # spawner 失败时，必须手动 close 掉 coroutine，避免 “was never awaited”
            coro1.close()
            coro2.close()
            raise

        self._tasks = [t1, t2]

    async def recv_all_until_end(self, max_bytes: int = -1, timeout: float = 10.0) -> bytes:
        """
        Client端使用：持续读取缓冲区，直到收到 END，返回拼接后的数据。
        max_bytes = -1 表示不限制；否则读满就提前返回。
        timeout 用于防止 END 永远不到导致挂死。
        """
        out = bytearray()
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout if timeout is not None else None

        while True:
            # drain what we already have
            if self._buffer:
                if max_bytes != -1:
                    need = max_bytes - len(out)
                    if need <= 0:
                        return bytes(out)
                    take = min(len(self._buffer), need)
                else:
                    take = len(self._buffer)

                out.extend(self._buffer[:take])
                del self._buffer[:take]

                if not self._buffer:
                    self.data_event.clear()

                if max_bytes != -1 and len(out) >= max_bytes:
                    return bytes(out)

                # continue loop to see whether END already arrived
                continue

            # no buffered data now
            if self._ended:
                return bytes(out)

            # wait for either data or END (with timeout)
            if deadline is not None:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    return bytes(out)

                t_data = asyncio.create_task(self.data_event.wait())
                t_end = asyncio.create_task(self.end_event.wait())
                done, pending = await asyncio.wait({t_data, t_end}, timeout=remaining,
                                                   return_when=asyncio.FIRST_COMPLETED)
                for p in pending:
                    p.cancel()
                # loop continues, will drain buffer or exit on _ended
            else:
                t_data = asyncio.create_task(self.data_event.wait())
                t_end = asyncio.create_task(self.end_event.wait())
                done, pending = await asyncio.wait({t_data, t_end}, return_when=asyncio.FIRST_COMPLETED)
                for p in pending:
                    p.cancel()

    # ================= 公共生命周期 =================

    def close(self):
        asyncio.create_task(self.aclose())

    async def aclose(self):
        async with self._close_lock:
            if self._closed:
                return
            self._closed = True
            self._closing.set()

            # 1) wake pump_to_remote if blocked on queue.get()
            # 1) 先用 sentinel 唤醒 pump_to_remote，避免卡在 get()
            with contextlib.suppress(Exception):
                if not self._to_remote.empty():
                    pass
                await self._to_remote.put(None)

            # 2) cancel 并 await 两个 pump task 真正退出
            tasks = list(self._tasks)
            for t in tasks:
                if t and not t.done():
                    t.cancel()
            if tasks:
                with contextlib.suppress(Exception):
                    await asyncio.gather(*tasks, return_exceptions=True)
            self._tasks = []

            # 3) 关闭 remote_writer，唤醒 pump_to_client 的 read
            if self._remote_writer:
                with contextlib.suppress(Exception):
                    self._remote_writer.close()
                with contextlib.suppress(Exception):
                    await self._remote_writer.wait_closed()
                self._remote_writer = None
            self._remote_reader = None

    # ================= 辅助构建方法 (Client/Server 通用) =================

    @staticmethod
    def chunks(lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    def make_connect(self, address: list):
        return self.make_relay(CellRelayBegin(address[0], address[1]))

    def make_end(self):
        return self.make_relay(CellRelayEnd(StreamReason.DONE, self._circuit.id))

    def make_sendme(self):
        return self.make_relay(CellRelaySendMe(circuit_id=self._circuit.id))

    def make_relay(self, inner_cell):
        return self._circuit.make_relay(inner_cell, stream_id=self.id)

    def make_relays_server(self, data):
        cell_list = []
        for chunk in self.chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            cell_list.append(self.make_relay_server(CellRelayData(chunk, self._circuit.id)))
        return cell_list

    def make_relay_server(self, inner_cell):
        return self._circuit.make_relay(inner_cell, stream_id=self.id)

    async def wait_connect_ack(self):
        # Client 等待连接成功
        await self.connect_event.wait()
