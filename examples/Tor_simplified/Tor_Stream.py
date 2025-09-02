import asyncio, contextlib
import logging
from typing import Optional
import struct

from torpy.stream import StreamState, TorWindow
from examples.Tor_simplified.Tor_Cell import *

logger = logging.getLogger(__name__)


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
    """This tor stream object implements socket-like interface."""

    def __init__(self, id, circuit, target_addr=None):
        logger.info('Stream #%i: creating attached to #%x circuit...', id, circuit.id)
        self._id = id
        self._circuit = circuit
        self.target_addr = target_addr

        self._buffer = bytearray()
        self._data_lock = asyncio.Lock()
        self.data_event = asyncio.Event()
        self._received_callbacks = []

        self._conn_timeout = 60
        self._recv_timeout = 60

        self._state = StreamState.Closed
        self._close_lock = asyncio.Lock()

        self.window = TorWindow(start=500, increment=50)

        self.connect_event = asyncio.Event()

        self._buffer = bytearray()
        self._mode = None  # None | 'http-tunnel' | 'tls-tunnel' | 'connect-tunnel'
        self._remote_reader = None  # asyncio.StreamReader
        self._remote_writer = None  # asyncio.StreamWriter
        self._recvq = asyncio.Queue(maxsize=64)
        self._remote_closed = False
        self._reader_task = None  # 后台读取远端数据 -> recvq
        self._close_lock = asyncio.Lock()


    def __enter__(self):
        """Start using the stream."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the stream."""
        self.close()

    @property
    def id(self):
        return self._id

    @staticmethod
    def _make_new_event():
        return asyncio.Event()

    def append(self, data):
        self._buffer.extend(data)
        self.data_event.set()

    async def aclose(self):
        """Async-safe close; used by client when actively closing a stream."""
        async with self._close_lock:
            if self._state == StreamState.Closed:
                return
            self._circuit.remove_stream(self)
            self._state = StreamState.Closed

    def close(self):
        """Backward-compat: schedule async close."""
        asyncio.create_task(self.aclose())

    async def wait_connect_ack(self):
        try:
            # 已经 set 过就立刻返回；否则等到 _conn_timeout
            if self.connect_event.is_set():
                return
            await asyncio.wait_for(self.connect_event.wait(), self._conn_timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for CONNECT ACK")


    @staticmethod
    def chunks(lst, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    def make_connect(self, address: list):
        return self.make_relay(CellRelayBegin(address[0], address[1]))

    def make_end(self):
        return self.make_relay(CellRelayEnd(StreamReason.DONE, self._circuit.id))

    def make_sendme(self):
        return self.make_relay(CellRelaySendMe(circuit_id=self._circuit.id))

    def make_relays(self, data):
        cell_list = []
        for chunk in self.chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            self._circuit.last_node.window.package_dec()
            cell_list.append(self.make_relay(CellRelayData(chunk, self._circuit.id)))
        return cell_list

    def make_relay(self, inner_cell):
        return self._circuit.make_relay(inner_cell, stream_id=self.id)

    def make_relays_server(self, data):
        cell_list = []
        for chunk in self.chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            self._circuit.last_node.window.package_dec()
            cell_list.append(self.make_relay_server(CellRelayData(chunk, self._circuit.id)))
        return cell_list

    def make_relay_server(self, inner_cell):
        return self._circuit.make_relay(inner_cell, stream_id=self.id)


    def set_end(self, cell_end):
        logger.info('Stream #%i: remote disconnected (reason = %s)', self.id, cell_end.reason.name)
        self.data_event.set()

    async def recv(self, bufsize):

        await self.data_event.wait()
        if bufsize == -1:
            to_read = len(self._buffer)
        else:
            to_read = min(len(self._buffer), bufsize)
        result = self._buffer[:to_read]
        self._buffer = self._buffer[to_read:]
        self.data_event = self._make_new_event()

        return result

    async def extract_guessed_message_from_buffer(self, timeout_ms: int = 20, coalesce_bytes: int = 64 * 1024) -> \
    Optional[bytes]:
        """
        单入口：检测协议 -> 建立隧道 -> 双向转发
        返回：
          - bytes：要发回客户端的数据块
          - b''   ：远端 EOF（你应该发 RelayEnd(DONE)）
          - None  ：当前无数据可回写
        """
        self._ensure_stream_state()

        # ---------- 小工具（仅本函数内使用） ----------
        def _http_header_end(buf: bytearray) -> int:
            return buf.find(b"\r\n\r\n")

        def _parse_http_request_head(head: bytes):
            # 返回 (method, path, version, headers_dict_lower)
            line_end = head.find(b"\r\n")
            if line_end == -1:
                return None, None, None, {}
            req_line = head[:line_end].decode("latin-1", "ignore")
            parts = req_line.split()
            method = parts[0] if len(parts) > 0 else ""
            path = parts[1] if len(parts) > 1 else ""
            ver = parts[2] if len(parts) > 2 else ""
            hdrs = {}
            for h in head[line_end + 2:].split(b"\r\n"):
                if not h: continue
                k, sep, v = h.partition(b":")
                if not sep: continue
                hdrs[k.strip().lower()] = v.strip()
            return method, path, ver, hdrs

        def _http_content_length(hdrs: dict) -> int:
            v = hdrs.get(b"content-length")
            if not v:
                return 0
            try:
                return int(v.decode("latin-1").strip())
            except Exception:
                return 0

        def _is_tls_record(buf: bytearray) -> bool:
            return len(buf) >= 5 and buf[0] == 0x16 and buf[1] == 0x03

        def _tls_record_total_len(buf: bytearray) -> int:
            if len(buf) < 5: return -1
            rec_len = (buf[3] << 8) | buf[4]
            total = 5 + rec_len
            return total if len(buf) >= total else -1

        def _extract_sni_hostname(data: bytes) -> Optional[str]:
            try:
                pos = 43
                if len(data) <= pos:
                    return None
                session_id_len = data[pos]
                pos += 1 + session_id_len
                if len(data) < pos + 2:
                    return None
                cs_len = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2 + cs_len
                if len(data) <= pos:
                    return None
                comp_len = data[pos]
                pos += 1 + comp_len
                if len(data) < pos + 2:
                    return None
                ext_total = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                end = pos + ext_total
                while pos + 4 <= end:
                    et = struct.unpack(">H", data[pos:pos + 2])[0]
                    el = struct.unpack(">H", data[pos + 2:pos + 4])[0]
                    pos += 4
                    if et == 0:  # SNI
                        if el < 5:
                            return None
                        sni = data[pos:pos + el]
                        if len(sni) < 5 or sni[2] != 0:
                            return None
                        name_len = struct.unpack(">H", sni[3:5])[0]
                        return sni[5:5 + name_len].decode("idna", "ignore")
                    pos += el
            except Exception:
                return None
            return None

        # ---------- 已处于隧道：持续转发 ----------
        if self._mode is not None:
            await self._flush_client_to_remote()
            return await self._recv_from_remote(wait_ms=timeout_ms, coalesce_bytes=coalesce_bytes)

        # ---------- 初次探测 ----------
        buf = self._buffer
        if not buf:
            return None

        # 1) HTTP/1.x（含 CONNECT）
        h_end = _http_header_end(buf)
        if h_end != -1:
            head = bytes(buf[:h_end + 4])
            method, path, ver, hdrs = _parse_http_request_head(head)
            method_up = (method or "").upper()

            # (a) CONNECT host:port
            if method_up == "CONNECT":
                # 消费头部
                del buf[:h_end + 4]
                host_port = (path or "")
                host, port = host_port.split(":")[0], int(host_port.split(":")[1]) if ":" in host_port else 443

                await self._open_remote(host, port)
                self._mode = "connect-tunnel"

                # 返回 200，随后走隧道
                return b"HTTP/1.1 200 Connection Established\r\n\r\n"

            # (b) 普通 HTTP：头部一完整就建连并流式转发 body
            host_hdr = hdrs.get(b"host")
            if not host_hdr:
                return b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nMissing Host header."
            target_host = host_hdr.decode("latin-1").strip()
            target_port = 80

            cl = _http_content_length(hdrs)
            # 已到达的 body（可能为 0）
            body_avail = len(buf) - (h_end + 4)
            # 取出头 + 已到的 body 一并首发（不再等待完整 Content-Length）
            first_send_len = h_end + 4 + max(0, body_avail)
            first_req = bytes(buf[:first_send_len])
            del buf[:first_send_len]

            await self._open_remote(target_host, target_port)
            self._mode = "http-tunnel"

            # 可选：记录剩余 body（当 Content-Length 存在时）
            if cl > 0:
                self._http_body_rem = max(0, cl - body_avail)
            else:
                self._http_body_rem = None

            # 首发并尽快取回响应首包
            self._remote_writer.write(first_req)
            await self._remote_writer.drain()
            return await self._recv_from_remote(wait_ms=timeout_ms, coalesce_bytes=coalesce_bytes)

        # 2) 直连 TLS（ClientHello 开头）
        if _is_tls_record(buf):
            total = _tls_record_total_len(buf)
            if total == -1:
                return None
            first_rec = bytes(buf[:total])
            sni = _extract_sni_hostname(first_rec)
            if not sni:
                return None  # 继续等待更多握手数据
            del buf[:total]

            await self._open_remote(sni, 443)
            self._mode = "tls-tunnel"

            self._remote_writer.write(first_rec)
            await self._remote_writer.drain()
            return await self._recv_from_remote(wait_ms=timeout_ms, coalesce_bytes=coalesce_bytes)

        # 3) 自定义：2 字节大端长度前缀（一次性消息）
        if len(buf) >= 2:
            msg_len = (buf[0] << 8) | buf[1]
            need = 2 + msg_len
            if len(buf) >= need:
                msg = bytes(buf[:need])
                del buf[:need]
                return msg

        return None

    def _ensure_stream_state(self):
        if not hasattr(self, "_buffer"): self._buffer = bytearray()
        if not hasattr(self, "_mode"): self._mode = None  # None|'http-tunnel'|'tls-tunnel'|'connect-tunnel'
        if not hasattr(self, "_remote_reader"): self._remote_reader = None
        if not hasattr(self, "_remote_writer"): self._remote_writer = None
        if not hasattr(self, "_reader_task"): self._reader_task = None
        if not hasattr(self, "_recvq"): self._recvq = asyncio.Queue(maxsize=64)
        if not hasattr(self, "_remote_closed"): self._remote_closed = False
        if not hasattr(self, "_http_body_rem"): self._http_body_rem = None  # 可选：记录 HTTP Content-Length 剩余

    async def _ensure_remote_reader_task(self):
        if self._reader_task is not None:
            return

        async def _pump():
            try:
                while True:
                    chunk = await self._remote_reader.read(65536)
                    if not chunk:
                        break
                    await self._recvq.put(chunk)
            finally:
                self._remote_closed = True

        self._reader_task = asyncio.create_task(_pump())

    async def _open_remote(self, host: str, port: int):
        self._remote_reader, self._remote_writer = await asyncio.open_connection(host, port)
        # TCP 优化
        with contextlib.suppress(Exception):
            sock = self._remote_writer.get_extra_info("socket")
            if sock:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._remote_closed = False
        await self._ensure_remote_reader_task()

    async def _flush_client_to_remote(self):
        """把 self._buffer 中的客户端数据批量写给远端；一次 drain。"""
        if not self._remote_writer or not self._buffer:
            return
        mv = memoryview(self._buffer)
        self._remote_writer.write(mv)
        self._buffer.clear()
        await self._remote_writer.drain()

    async def _recv_from_remote(self, wait_ms: int = 20, coalesce_bytes: int = 64 * 1024):
        """
        从远端读取返回给客户端的数据：
          - 先无阻塞抽干队列并聚合（最多 coalesce_bytes）
          - 没有则等待 wait_ms 毫秒拿首包
          - 若远端已关闭且队列空，返回 b'' 作为 EOF 哨兵
          - 若当前没有数据可回写，返回 None
        """
        total = bytearray()
        # 先尽量无阻塞聚合
        try:
            while True:
                total += self._recvq.get_nowait()
                if len(total) >= coalesce_bytes:
                    break
        except asyncio.QueueEmpty:
            pass
        if total:
            return bytes(total)

        # 队列空：远端已关闭 => EOF 哨兵
        if self._remote_closed:
            return b''

        # 等待首包
        if wait_ms > 0:
            try:
                first = await asyncio.wait_for(self._recvq.get(), timeout=wait_ms / 1000.0)
                total = bytearray(first)
                # 再无阻塞聚合剩余
                try:
                    while True:
                        total += self._recvq.get_nowait()
                        if len(total) >= coalesce_bytes:
                            break
                except asyncio.QueueEmpty:
                    pass
                return bytes(total)
            except asyncio.TimeoutError:
                # 仍无数据；若远端刚好关闭，返回 EOF；否则 None
                return b'' if self._remote_closed else None
        return None

#     async def handle_guessed_protocol(self, proto, request_bytes: bytes) -> bytes:
#         """
#         Detect protocol type from buffer and call corresponding handler.
#
#         Supported:
#             - HTTP
#             - HTTPS (TLS)
#             - Custom
#             - JSON (echo)
#
#         Returns:
#             raw response bytes
#         """
#         if proto == "http":
#             return await self.handle_http_request(request_bytes)
#         elif proto == "https":
#             return await self.handle_https_request(request_bytes)
#         elif proto == "json":
#             return b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + request_bytes
#         elif proto == "custom":
#             return b"Custom protocol received.\n" + request_bytes
#         else:
#             return b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nUnknown or incomplete request."
#
#     async def handle_http_request(self, request_bytes: bytes) -> bytes:
#         """
#         Parse and forward an HTTP request, return the raw response.
#
#         Args:
#             request_bytes: The raw HTTP request received via Tor.
#
#         Returns:
#             response_bytes: The raw HTTP response to send back.
#         """
#
#         try:
#             # Step 1: decode and parse Host
#             request_text = request_bytes.decode('iso-8859-1')  # safe for binary headers
#             headers = request_text.split("\r\n")
#
#             host = None
#             for line in headers:
#                 if line.lower().startswith("host:"):
#                     host = line.split(":", 1)[1].strip()
#                     break
#
#             if not host:
#                 raise ValueError("Missing Host header in request")
#
#             # Step 2: open TCP connection to host:80
#             reader, writer = await asyncio.open_connection(host, 80)
#
#             # Step 3: forward the original request
#             writer.write(request_bytes)
#             await writer.drain()
#
#             # Step 4: read response (until EOF)
#             response = bytearray()
#             while True:
#                 chunk = await reader.read(4096)
#                 if not chunk:
#                     break
#                 response.extend(chunk)
#
#             writer.close()
#             await writer.wait_closed()
#
#             return bytes(response)
#
#         except Exception as e:
#             return f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nError: {e}".encode()
#
#     async def handle_https_request(self, request_bytes: bytes) -> bytes:
#         """
#         Forward an HTTPS/TLS request by creating a raw TCP tunnel.
#
#         Args:
#             request_bytes: TLS ClientHello and later handshake content
#
#         Returns:
#             response_bytes: The raw response from the target HTTPS server
#         """
#         try:
#             # Step 1: extract SNI host from ClientHello (basic heuristic)
#             host = self._extract_sni_hostname(request_bytes)
#             if not host:
#                 raise ValueError("Unable to extract SNI from TLS ClientHello")
#
#             # Step 2: open TLS destination port
#             reader, writer = await asyncio.open_connection(host, 443)
#
#             # Step 3: send initial ClientHello
#             writer.write(request_bytes)
#             await writer.drain()
#
#             # Step 4: relay response (at least handshake)
#             response = bytearray()
#             while True:
#                 chunk = await reader.read(4096)
#                 if not chunk:
#                     break
#                 response.extend(chunk)
#
#             writer.close()
#             await writer.wait_closed()
#
#             return bytes(response)
#
#         except Exception as e:
#             return f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nHTTPS Error: {e}".encode()
#
#     @staticmethod
#     def _extract_sni_hostname(data: bytes) -> Optional[str]:
#         """
#         Extract the SNI hostname from a TLS ClientHello message.
#
#         Reference: https://tools.ietf.org/html/rfc6066#section-3
#
#         Returns:
#             - host (str) if found
#             - None otherwise
#         """
#         try:
#             # Skip TLS record header (5 bytes)
#             # + handshake header (1 + 3 bytes)
#             # + version (2 bytes)
#             # + random (32 bytes)
#             # + session ID len + session ID
#             pos = 43
#             session_id_len = data[pos]
#             pos += 1 + session_id_len
#
#             # Cipher Suites
#             cipher_suites_len = struct.unpack(">H", data[pos:pos + 2])[0]
#             pos += 2 + cipher_suites_len
#
#             # Compression methods
#             compression_len = data[pos]
#             pos += 1 + compression_len
#
#             # Extensions
#             ext_total_len = struct.unpack(">H", data[pos:pos + 2])[0]
#             pos += 2
#             end = pos + ext_total_len
#
#             while pos + 4 <= end:
#                 ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
#                 ext_len = struct.unpack(">H", data[pos + 2:pos + 4])[0]
#                 pos += 4
#                 if ext_type == 0:  # SNI
#                     sni_data = data[pos + 2:pos + ext_len]  # skip list length (2 bytes)
#                     if sni_data[0] == 0:  # host_name type
#                         name_len = struct.unpack(">H", sni_data[1:3])[0]
#                         hostname = sni_data[3:3 + name_len].decode()
#                         return hostname
#                 pos += ext_len
#
#         except Exception:
#             pass
#         return None
#
#
# def guess_protocol_and_check_complete(data: bytes) -> tuple[Optional[str], Optional[int]]:
#     """
#     Heuristically guess protocol based on buffer content and check if a complete message is received.
#
#     Returns:
#         (protocol_name, message_length)
#         or (None, None) if unknown or incomplete.
#     """
#     # 1. HTTP check
#     if data.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ")):
#         header_end = data.find(b"\r\n\r\n")
#         if header_end != -1:
#             return "http", header_end + 4
#
#     # 2. HTTPS / TLS ClientHello
#     # TLS handshake usually starts with 0x16 0x03 0x01 or 0x16 0x03 0x03
#     if len(data) >= 5 and data[0] == 0x16 and data[1] == 0x03:
#         length = struct.unpack(">H", data[3:5])[0]
#         total_len = 5 + length
#         if len(data) >= total_len:
#             return "https", total_len
#
#     # 3. Custom: 2-byte big endian length prefix
#     if len(data) >= 2:
#         msg_len = int.from_bytes(data[:2], "big")
#         if len(data) >= 2 + msg_len:
#             return "custom", 2 + msg_len
#
#     # 4. JSON? (starts with { or [ and ends with } or ])
#     if data.startswith(b"{") or data.startswith(b"["):
#         try:
#             import json
#             obj = json.loads(data.decode(errors="ignore"))
#             return "json", len(data)
#         except Exception:
#             pass
#
#     # Not complete or unknown
#     return None, None

