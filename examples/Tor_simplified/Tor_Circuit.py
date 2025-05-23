import logging
import asyncio
from queue import Queue

from examples.Tor_simplified.Tor_Stream import StreamsList

from torpy.keyagreement import KeyAgreement, TapKeyAgreement, NtorKeyAgreement, FastKeyAgreement
from functools import partial
from torpy.crypto_state import CryptoState
from torpy.http.client import HttpStreamClient
from torpy.circuit import TorCircuitState, check_connected, CircuitNode, CircuitExtendError
from torpy.cells import (
    CellRelay,
    CellCreateFast,
    CellCreate2,
    CellDestroy,
    CellCreatedFast,
    CellCreated2,
    CellRelayEnd,
    CellRelayData,
    CircuitReason,
    CellRelayEarly,
    RelayedTorCell,
    CellRelaySendMe,
    CellRelayExtend2,
    CellRelayConnected,
    CellRelayExtended2,
    CellRelayTruncated,
)

logger = logging.getLogger(__name__)


class CircuitsList:
    LOCK = asyncio.Lock()
    GLOBAL_CIRCUIT_ID = 0

    def __init__(self, guard, is_client=True):
        self._guard = guard
        self.msb = is_client
        self._circuits_map = {}

    def values(self):
        return self._circuits_map.values()

    def _get_next_circuit_id(self):
        with CircuitsList.LOCK:
            CircuitsList.GLOBAL_CIRCUIT_ID += 1
            circuit_id = CircuitsList.GLOBAL_CIRCUIT_ID
        if self.msb:
            circuit_id |= 0x80000000
        return circuit_id

    def create_new(self):
        circuit_id = self._get_next_circuit_id()
        circuit = TorCircuit(circuit_id, self._guard)
        self._circuits_map[circuit.id] = circuit
        return circuit

    def get_by_id(self, circuit_id):
        return self._circuits_map.get(circuit_id, None)

    def remove(self, circuit_id):
        return self._circuits_map.pop(circuit_id, None)


class TorCircuit:
    def __init__(self, id, guard):
        self._id = id
        self._guard = guard
        self.streams = StreamsList(self)
        self.buffer = Queue()

        self._relay_send_lock = asyncio.Lock()
        self.circuit_nodes = []
        self._state = TorCircuitState.Unknown
        self._state_lock = asyncio.Lock()
        self._extend_lock = asyncio.Lock()
        self.connect_event = self._make_new_event()

    def __enter__(self):
        """Start using the circuit."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Close the circuit."""
        self.close()

    def close(self):
        logger.debug('Close circuit #%x', self.id)
        if self._guard is not None:
            self._guard.destroy_circuit(self)



    def initialize(self, router):
        logger.debug('Circuit created')
        key_agreement_cls = NtorKeyAgreement
        create_cls = partial(CellCreate2, key_agreement_cls.TYPE)
        circuit_node = CircuitNode(router, key_agreement_cls=key_agreement_cls)
        onion_skin = circuit_node.create_onion_skin()
        self.circuit_nodes.append(circuit_node)
        cell_create = create_cls(onion_skin, self.id)

        return cell_create

    async def guard_handsake(self, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            logger.debug('Verifying response...')
            circuit_node = self.circuit_nodes[0]
            cell_created = self.buffer.get()
            circuit_node.complete_handshake(cell_created.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for guard handshake")

    def extend(self, next_onion_router, key_agreement_cls=NtorKeyAgreement):
        logger.info('Extending the circuit #%x with %s...', self.id, next_onion_router)

        logger.debug('Sending Extend2...')
        extend_node = CircuitNode(next_onion_router, key_agreement_cls=key_agreement_cls)
        skin = extend_node.create_onion_skin()

        inner_cell = CellRelayExtend2(
            next_onion_router.ip, next_onion_router.or_port, next_onion_router.fingerprint, skin
        )
        extend_cell = self.make_relay(inner_cell)
        self.circuit_nodes.append(extend_node)
        return extend_cell

    async def extend_handshake(self, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            recv_cell = self.buffer.get()
            if isinstance(recv_cell, CellRelayTruncated):
                raise CircuitExtendError('Extend error {}'.format(recv_cell.reason.name))
            extend_node = self.last_node
            logger.debug('Verifying response...')
            extend_node.complete_handshake(recv_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for extend handshake")


    def create_dir_client(self):
        stream = self.create_stream()
        stream.connect_dir()
        return HttpStreamClient(stream, host=self.last_node.router.ip)

    def destroy(self, send_destroy=True):
        with self._state_lock:
            logger.debug('#%x circuit: destroying (state: %s)...', self.id, self._state.name)

            if self._state == TorCircuitState.Unknown:
                raise Exception('#{:x} circuit is not yet connected'.format(self.id))

            if self._state == TorCircuitState.Destroyed:
                logger.warning('#%x circuit: has been destroyed already', self.id)
                return

            if self._state == TorCircuitState.Connected:
                # Destroy all streams belonging to the current circuit
                self.close_all_streams()
                if send_destroy:
                    # Destroy the circuit itself
                    self._send(CellDestroy(CircuitReason.FINISHED, self.id))

            self._state = TorCircuitState.Destroyed

    def close_all_streams(self):
        for stream in list(self.streams.values()):
            stream.close()

    def _encrypt(self, relay_cell):
        assert isinstance(relay_cell, RelayedTorCell)
        assert not relay_cell.is_encrypted

        for circuit_node in self.circuit_nodes[::-1]:
            circuit_node.encrypt_forward(relay_cell)

    def _decrypt(self, relay_cell):
        # tor ref: relay_decrypt_cell
        assert relay_cell.is_encrypted

        from_node = None
        for i, circuit_node in enumerate(self.circuit_nodes):
            logger.debug('Decrypting by [%i] %s...', i, circuit_node.router)
            if not relay_cell.is_encrypted:
                logger.warning('Decrypted earlier')
                break

            # Continue decrypting...
            circuit_node.decrypt_backward(relay_cell)
            from_node = circuit_node

        return from_node, relay_cell.get_decrypted()


    def make_relay(self, inner_cell, relay_type=None, stream_id=0):
        relay_type = relay_type or CellRelay
        assert issubclass(relay_type, RelayedTorCell)

        relay_cell = relay_type(inner_cell, stream_id=stream_id, circuit_id=self.id)
        with self._relay_send_lock:
            self._encrypt(relay_cell)
            return relay_cell

    @check_connected
    def create_stream(self):
        tor_stream = self.streams.create_new()
        return tor_stream

    def remove_stream(self, tor_stream):
        self.streams.remove(tor_stream)

    @property
    def id(self):
        return self._id

    @property
    def nodes_count(self):
        return len(self.circuit_nodes)

    @property
    def last_node(self):
        return self.circuit_nodes[-1]

    @property
    def state(self):
        return self._state

    @property
    def connected(self):
        return self._state == TorCircuitState.Connected

    @staticmethod
    def _make_new_event():
        return asyncio.Event()
