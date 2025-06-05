import logging
import asyncio
from queue import Queue

from examples.Tor_simplified.Tor_Stream import StreamsList
from examples.Tor_simplified.Tor_Router import Tor_Router

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


class Tor_CircuitsList:
    LOCK = asyncio.Lock()
    GLOBAL_CIRCUIT_ID = 0

    def __init__(self, is_client=True):
        self.msb = is_client
        self._circuits_map = {}

    def values(self):
        return self._circuits_map.values()

    async def _get_next_circuit_id(self):
        async with Tor_CircuitsList.LOCK:
            Tor_CircuitsList.GLOBAL_CIRCUIT_ID += 1
            circuit_id = Tor_CircuitsList.GLOBAL_CIRCUIT_ID
        if self.msb:
            circuit_id |= 0x80000000
        return circuit_id

    async def create_new(self):
        circuit_id = await self._get_next_circuit_id()
        circuit = TorCircuit(circuit_id)
        self._circuits_map[circuit.id] = circuit
        return circuit

    def get_by_id(self, circuit_id):
        return self._circuits_map.get(circuit_id, None)

    def remove(self, circuit_id):
        return self._circuits_map.pop(circuit_id, None)


class TorCircuit:
    def __init__(self, id):
        self._id = id
        self.streams = StreamsList(self)
        self.buffer = Queue()

        self._relay_send_lock = asyncio.Lock()
        self.circuit_nodes = []
        self._state = TorCircuitState.Unknown
        self._state_lock = asyncio.Lock()
        self._extend_lock = asyncio.Lock()

        self.connect_event = self._make_new_event()




    def initialize(self, guard):
        logger.debug('Circuit created')

        key_agreement_cls = NtorKeyAgreement
        create_cls = partial(CellCreate2, key_agreement_cls.TYPE)
        circuit_node = guard
        onion_skin = circuit_node.create_onion_skin()

        self.circuit_nodes.append(circuit_node)
        cell_create = create_cls(onion_skin, self.id)
        self.created_cell = None  #便于后续传入cell
        return cell_create

    async def guard_handsake(self, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            logger.debug('Verifying response...')
            circuit_node = self.circuit_nodes[0]

            print("self.created_cell : ", self.created_cell)
            print("self.created_cell.handshake_data len: ", len(self.created_cell.handshake_data))
            print("self.created_cell.handshake_data: ", self.created_cell.handshake_data)
            print("Hex:", self.created_cell.handshake_data.hex())

            circuit_node.complete_handshake(self.created_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for guard handshake")

    def extend(self, extend_node):
        logger.info('Extending the circuit #%x with %s...', self.id)

        logger.debug('Sending Extend2...')
        skin = extend_node.create_onion_skin()
        inner_cell = CellRelayExtend2(
            extend_node.ip, extend_node.or_port, extend_node.fingerprint, skin
        )
        extend_cell = self.make_relay(inner_cell, relay_type=CellRelayEarly)
        self.circuit_nodes.append(extend_node)
        self.extend_cell = None
        return extend_cell

    async def extend_handshake(self, descriptor_str, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            recv_cell = self.extend_cell
            if isinstance(recv_cell, CellRelayTruncated):
                raise CircuitExtendError('Extend error {}'.format(recv_cell.reason.name))
            extend_node = self.last_node
            logger.debug('Verifying response...')
            extend_node.set_descriptor(descriptor_str)
            extend_node.complete_handshake(recv_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for extend handshake")

    def handle_relay(self, cell):
        # tor ref: circuit_receive_relay_cell
        # tor ref: connection_edge_process_relay_cell
        circuit_node, inner_cell = self._decrypt(cell)
        logger.debug('Decrypted relay cell received from %s: %r', circuit_node.nickname, inner_cell)
        return inner_cell



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
            logger.debug('Decrypting by [%i] %s...', i, circuit_node)
            if not relay_cell.is_encrypted:
                break

            # Continue decrypting...
            circuit_node.decrypt_backward(relay_cell)
            from_node = circuit_node

        return from_node, relay_cell.get_decrypted()


    def make_relay(self, inner_cell, relay_type=None, stream_id=0):
        relay_type = relay_type or CellRelay
        assert issubclass(relay_type, RelayedTorCell)
        print("relay_type", relay_type)
        relay_cell = relay_type(inner_cell, stream_id=stream_id, circuit_id=self.id)

        self._encrypt(relay_cell)
        return relay_cell

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
