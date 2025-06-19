import logging
import asyncio
from queue import Queue

from examples.Tor_simplified.Tor_Stream import StreamsList
from examples.Tor_simplified.Tor_Router import Tor_Router_simple

from torpy.keyagreement import NtorKeyAgreement
from torpy.circuit import TorCircuitState, CircuitExtendError
from examples.Tor_simplified.Tor_Cell import *

logger = logging.getLogger(__name__)


class Tor_CircuitsList:
    LOCK = asyncio.Lock()
    GLOBAL_CIRCUIT_ID = 0

    def __init__(self, is_client=True):
        self.msb = is_client
        self._circuits_map = {}

    def values(self):
        return self._circuits_map.items()

    async def _get_next_circuit_id(self):
        async with Tor_CircuitsList.LOCK:
            Tor_CircuitsList.GLOBAL_CIRCUIT_ID += 1
            circuit_id = Tor_CircuitsList.GLOBAL_CIRCUIT_ID
        if self.msb:
            circuit_id |= 0x80000000
        return circuit_id

    async def create_new_client(self):
        circuit_id = await self._get_next_circuit_id()
        circuit = TorCircuit(circuit_id, role="client")
        self._circuits_map[circuit.id] = circuit
        return circuit

    def create_circuit_server(self, circuit_id):
        circuit = TorCircuit(circuit_id, role="server")
        self._circuits_map[circuit.id] = circuit
        return circuit

    def get_by_id(self, circuit_id):
        return self._circuits_map.get(circuit_id, None)

    def remove(self, circuit_id):
        return self._circuits_map.pop(circuit_id, None)


class TorCircuit:
    def __init__(self, id, role: str = "client"):
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
        circuit_node = guard
        onion_skin = circuit_node.create_onion_skin()
        print("create onion:", onion_skin)
        self.circuit_nodes.append(circuit_node)

        cell_create = Cell_Create2(key_agreement_cls.TYPE, onion_skin, self.id)
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
        print("extend onion:", skin)

        inner_cell = CellRelayExtend2(
            extend_node.ip, extend_node.or_port, extend_node.fingerprint, skin
        )
        extend_cell = self.make_relay(inner_cell, relay_type=Cell_RelayEarly)
        self.circuit_nodes.append(extend_node)
        self.extended_cell = None
        return extend_cell

    async def extend_handshake(self, descriptor_str, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            recv_cell = self.extended_cell
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
        inner_cell = self._decrypt_client(cell)
        print("succeful")
        logger.debug('Decrypted relay cell received from %s: %r', inner_cell)
        return inner_cell

    def handle_relay_server(self, cell):
        relay_cell = self._decrypt_server(cell)
        logger.debug('Decrypted relay cell received from %s: %r', relay_cell)
        return relay_cell

    def circuit_build_server(self, protocol, create_cell, sock):
        payload, share_key = protocol.handle_create2(create_cell.serialize_payload())
        created_cell = CellCreated2(payload, create_cell.circuit_id)
        simple_node = Tor_Router_simple(sock, share_key)
        self.circuit_nodes.append(simple_node)
        return created_cell

    def destroy(self, send_destroy=True):
        pass

    def close_all_streams(self):
        for stream in list(self.streams.values()):
            stream.close()

    def _encrypt(self, relay_cell):
        assert isinstance(relay_cell, RelayedTorCell)
        assert not relay_cell.is_encrypted

        for circuit_node in self.circuit_nodes[::-1]:
            circuit_node.encrypt_forward(relay_cell)

    def _encrypt_server(self, relay_cell):
        assert isinstance(relay_cell, RelayedTorCell)
        assert not relay_cell.is_encrypted
        circuit_node = self.circuit_nodes[0]
        circuit_node.encrypt_forward(relay_cell)


    def _decrypt_client(self, relay_cell):
        # tor ref: relay_decrypt_cell
        assert relay_cell.is_encrypted
        print("circuit_nodes", self.circuit_nodes)

        for i, circuit_node in enumerate(self.circuit_nodes):
            print("i:", i)
            print("circuit_node", circuit_node)
            logger.debug('Decrypting by [%i] %s...', i, circuit_node)
            if not relay_cell.is_encrypted:
                break

            # Continue decrypting...
            circuit_node.decrypt_backward(relay_cell)

        return relay_cell.get_decrypted()

    def _decrypt_server(self, relay_cell):
        # tor ref: relay_decrypt_cell
        assert relay_cell.is_encrypted
        circuit_node = self.circuit_nodes[0]
        circuit_node.decrypt_backward(relay_cell)
        if relay_cell.is_encrypted:
            forwarded_cell = type(relay_cell)(
                inner_cell=None,
                circuit_id=relay_cell.circuit_id,
                encrypted=relay_cell.get_encrypted()
            )
        else:
            forwarded_cell = relay_cell.get_decrypted()

        return forwarded_cell

    def make_relay(self, inner_cell, relay_type=None, stream_id=0):
        relay_type = relay_type or CellRelay
        assert issubclass(relay_type, RelayedTorCell)
        relay_cell = relay_type(inner_cell, stream_id=stream_id, circuit_id=self.id)
        self._encrypt(relay_cell)
        return relay_cell

    def make_relay_server(self, inner_cell, relay_type=None, stream_id=0):
        relay_type = relay_type or CellRelay
        assert issubclass(relay_type, RelayedTorCell)
        relay_cell = relay_type(inner_cell, stream_id=stream_id, circuit_id=self.id)
        self._encrypt_server(relay_cell)
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
