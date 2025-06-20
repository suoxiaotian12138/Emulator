import asyncio
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
        stream = TorStream(self.get_next_stream_id(), self._circuit)
        self._stream_map[stream.id] = stream
        return stream

    def set_stream(self, stream_id, target_addr):
        stream = TorStream(stream_id, self._circuit, target_addr)
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


class TorStream:
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

        self._conn_timeout = 30
        self._recv_timeout = 60

        self._state = StreamState.Closed
        self._close_lock = asyncio.Lock()

        self.window = TorWindow(start=500, increment=50)

        self.connect_event = self._make_new_event()


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

    def close(self):
        logger.info('Stream #%i: closing (state = %s)...', self.id, self._state.name)

        with self._close_lock:
            if self._state == StreamState.Closed:
                logger.warning('Stream #%i: closed already', self.id)
                return

            self._circuit.remove_stream(self)

            self._state = StreamState.Closed
            logger.debug('Stream #%i: closed', self.id)

    async def wait_connect_ack(self):
        try:
            await asyncio.wait_for(self.connect_event.wait(), self._conn_timeout)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for CONNECT ACK")


    @staticmethod
    def chunks(lst, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]

    def make_connect(self, address: list):
        return self.make_cell(CellRelayBegin(address[0], address[1]))

    def make_end(self):
        return self.make_cell(CellRelayEnd(StreamReason.DONE, self._circuit.id))

    def make_sendme(self):
        return self.make_cell(CellRelaySendMe(circuit_id=self._circuit.id))

    def make_relays(self, data):
        cell_list = []
        for chunk in self.chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            self._circuit.last_node.window.package_dec()
            cell_list.append(self.make_cell(CellRelayData(chunk, self._circuit.id)))
        return cell_list

    def make_cell(self, inner_cell):
        return self._circuit.make_relay(inner_cell, stream_id=self.id)

    def make_relays_server(self, data):
        cell_list = []
        for chunk in self.chunks(data, RelayedTorCell.MAX_PAYLOD_SIZE):
            self._circuit.last_node.window.package_dec()
            cell_list.append(self.make_cell_server(CellRelayData(chunk, self._circuit.id)))
        return cell_list

    def make_cell_server(self, inner_cell):
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
    def extract_guessed_message_from_buffer(self):
        """
        Try to detect the protocol from buffer content and extract a full message.

        Returns:
            - message (bytes) if full message is found
            - None otherwise
        """
        if not self._buffer:
            return None

        data = bytes(self._buffer)
        proto, msg_len = guess_protocol_and_check_complete(data)

        if msg_len is not None:
            message = data[:msg_len]
            del self._buffer[:msg_len]
            return message

        return None

    async def handle_http_request(self, request_bytes: bytes) -> bytes:
        """
        Parse and forward an HTTP request, return the raw response.

        Args:
            request_bytes: The raw HTTP request received via Tor.

        Returns:
            response_bytes: The raw HTTP response to send back.
        """

        try:
            # Step 1: decode and parse Host
            request_text = request_bytes.decode('iso-8859-1')  # safe for binary headers
            headers = request_text.split("\r\n")

            host = None
            for line in headers:
                if line.lower().startswith("host:"):
                    host = line.split(":", 1)[1].strip()
                    break

            if not host:
                raise ValueError("Missing Host header in request")

            # Step 2: open TCP connection to host:80
            reader, writer = await asyncio.open_connection(host, 80)

            # Step 3: forward the original request
            writer.write(request_bytes)
            await writer.drain()

            # Step 4: read response (until EOF)
            response = bytearray()
            while True:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                response.extend(chunk)

            writer.close()
            await writer.wait_closed()

            return bytes(response)

        except Exception as e:
            return f"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nError: {e}".encode()


def guess_protocol_and_check_complete(data: bytes) -> tuple[Optional[str], Optional[int]]:
    """
    Heuristically guess protocol based on buffer content and check if a complete message is received.

    Returns:
        (protocol_name, message_length)
        or (None, None) if unknown or incomplete.
    """
    # 1. HTTP check
    if data.startswith((b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ")):
        header_end = data.find(b"\r\n\r\n")
        if header_end != -1:
            return "http", header_end + 4

    # 2. HTTPS / TLS ClientHello
    # TLS handshake usually starts with 0x16 0x03 0x01 or 0x16 0x03 0x03
    if len(data) >= 5 and data[0] == 0x16 and data[1] == 0x03:
        length = struct.unpack(">H", data[3:5])[0]
        total_len = 5 + length
        if len(data) >= total_len:
            return "https", total_len

    # 3. Custom: 2-byte big endian length prefix
    if len(data) >= 2:
        msg_len = int.from_bytes(data[:2], "big")
        if len(data) >= 2 + msg_len:
            return "custom", 2 + msg_len

    # 4. JSON? (starts with { or [ and ends with } or ])
    if data.startswith(b"{") or data.startswith(b"["):
        try:
            import json
            obj = json.loads(data.decode(errors="ignore"))
            return "json", len(data)
        except Exception:
            pass

    # Not complete or unknown
    return None, None

