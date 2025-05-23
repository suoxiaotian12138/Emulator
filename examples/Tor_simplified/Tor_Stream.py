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
        with StreamsList.LOCK:
            StreamsList.GLOBAL_STREAM_ID += 1
            return StreamsList.GLOBAL_STREAM_ID

    def create_new(self):
        stream = TorStream(self.get_next_stream_id(), self._circuit)
        self._stream_map[stream.id] = stream
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

    def __init__(self, id, circuit):
        logger.info('Stream #%i: creating attached to #%x circuit...', id, circuit.id)
        self._id = id
        self._circuit = circuit

        self._buffer = bytearray()
        self._data_lock = asyncio.Lock()
        self._has_data = asyncio.Event()
        self._received_callbacks = []

        self._conn_timeout = 30
        self._recv_timeout = 60

        self._state = StreamState.Closed
        self._close_lock = asyncio.Lock()

        self._window = TorWindow(start=500, increment=50)

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

    @property
    def state(self):
        return self._state

    @staticmethod
    def _make_new_event():
        return asyncio.Event()

    def register(self, callback):
        self._received_callbacks.append(callback)

    def unregister(self, callback):
        self._received_callbacks.remove(callback)

    def _append(self, data):
        with self._close_lock, self._data_lock:
            if self._state == StreamState.Closed:
                logger.warning('Stream #%i: closed (but received %r)', self.id, data)
                return

            logger.debug('Stream #%i: append %i (to buffer)', self.id, len(data))
            self._buffer.extend(data)
            self._has_data.set()

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
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for CONNECT ACK")

    def on_connect_ack(self):
        self.connect_event.set()


    def recv(self, bufsize):
        if self._state == StreamState.Closed:
            raise Exception("You can't recv closed stream")

        signaled = self._has_data.wait(self._recv_timeout)
        if not signaled:
            raise Exception('recv timeout')

        # If remote side already send 'end cell' but we still
        # has some data - we keep receiving
        if self._state == StreamState.Disconnected and not self._buffer:
            return b''

        with self._data_lock:
            if bufsize == -1:
                to_read = len(self._buffer)
            else:
                to_read = min(len(self._buffer), bufsize)
            result = self._buffer[:to_read]
            self._buffer = self._buffer[to_read:]
            logger.debug('Stream #%i: read %i (left %i)', self.id, to_read, len(self._buffer))

            # Clear 'has_data' flag only if we don't have more data and not disconnected
            if not self._buffer and self._state != StreamState.Disconnected:
                self._has_data.clear()

        return result


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

