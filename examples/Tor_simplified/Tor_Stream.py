import asyncio
import logging


from torpy.stream import StreamState, TorWindow
from torpy.cells import (
    CellRelayEnd,
    StreamReason,
    CellRelayData,
    CellRelayBegin,
    RelayedTorCell,
    CellRelaySendMe,
)

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