import asyncio
from queue import Queue

from examples.Tor_simplified.Tor_Stream import StreamsList
from examples.Tor_simplified.Tor_Router import Tor_Router_simple
from examples.Tor_simplified.Tor_Crypt import NtorKeyAgreement

# from torpy.keyagreement import NtorKeyAgreement
from examples.Tor_simplified.Tor_Cell import *
import logging

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

    async def create_circuit_server(self, circuit_id):
        circuit = TorCircuit(circuit_id, role="server")
        self._circuits_map[circuit.id] = circuit
        return circuit

    def get_by_id(self, circuit_id):
        return self._circuits_map.get(circuit_id, None)

    def remove(self, circuit_id):
        return self._circuits_map.pop(circuit_id, None)


class CircuitRoleOps:
    def __init__(self, circuit):
        self.circuit = circuit

    def encrypt(self, relay_cell):
        raise NotImplementedError

    def decrypt(self, relay_cell):
        raise NotImplementedError

    def handle_relay(self, cell):
        raise NotImplementedError


class ClientCircuitOps(CircuitRoleOps):
    def encrypt(self, relay_cell):
        for node in reversed(self.circuit.circuit_nodes):
            node.encrypt_forward(relay_cell)

    def decrypt(self, relay_cell):
        for node in self.circuit.circuit_nodes:
            if not relay_cell.is_encrypted:
                break
            node.decrypt_backward(relay_cell)
        return relay_cell.get_decrypted()

    def handle_relay(self, cell):
        return self.decrypt(cell)


class ServerCircuitOps(CircuitRoleOps):
    def encrypt(self, relay_cell):
        self.circuit.circuit_nodes[0].encrypt_forward(relay_cell)

    def decrypt(self, relay_cell):
        node = self.circuit.circuit_nodes[0]
        node.decrypt_backward(relay_cell)
        if relay_cell.is_encrypted:
            return type(relay_cell)(
                inner_cell=None,
                circuit_id=relay_cell.circuit_id,
                encrypted=relay_cell.get_encrypted()
            )
        else:
            return relay_cell.get_decrypted()

    def handle_relay(self, cell):
        return self.decrypt(cell)


class TorCircuit:
    def __init__(self, circuit_id, role: str):
        self._id = circuit_id
        self.streams = StreamsList(self)
        self.buffer = Queue()
        self._relay_send_lock = asyncio.Lock()
        self.circuit_nodes = []
        self._extend_lock = asyncio.Lock()
        self.connect_event = self._make_new_event()
        self.role_ops = ClientCircuitOps(self) if role == "client" else ServerCircuitOps(self)

    def connect_to_guard(self, guard):
        key_agreement_cls = NtorKeyAgreement
        circuit_node = guard
        onion_skin = circuit_node.create_onion_skin()
        self.circuit_nodes.append(circuit_node)
        cell_create = Cell_Create2(key_agreement_cls.TYPE, onion_skin, self.id)
        self.created_cell = None
        return cell_create

    async def guard_handsake(self, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            circuit_node = self.circuit_nodes[0]
            circuit_node.complete_handshake(self.created_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for guard handshake")

    def connect_to_extend(self, extend_node):
        skin = extend_node.create_onion_skin()
        inner_cell = CellRelayExtend2(extend_node.ip, extend_node.or_port, extend_node.fingerprint, skin)
        extend_cell = self.make_relay(inner_cell, relay_type=Cell_RelayEarly)
        self.circuit_nodes.append(extend_node)
        self.extended_cell = None
        return extend_cell

    async def extend_handshake(self, descriptor_str, wait_time=60):
        try:
            await asyncio.wait_for(self.connect_event.wait(), wait_time)
            recv_cell = self.extended_cell
            if isinstance(recv_cell, CellRelayTruncated):
                raise Exception(f'Extend error {recv_cell.reason.name}')
            extend_node = self.last_node
            extend_node.set_descriptor(descriptor_str)
            extend_node.complete_handshake(recv_cell.handshake_data)
            self.connect_event = self._make_new_event()
        except asyncio.TimeoutError:
            raise TimeoutError("Timed out waiting for extend handshake")

    def server_connected(self, protocol, create_cell, sock):
        payload, share_key = protocol.handle_create2(create_cell.serialize_payload())
        created_cell = CellCreated2(payload, create_cell.circuit_id)
        simple_node = Tor_Router_simple(sock, share_key)
        self.circuit_nodes.append(simple_node)
        return created_cell

    def handle_relay(self, cell):
        return self.role_ops.handle_relay(cell)

    def make_relay(self, inner_cell, relay_type=None, stream_id=0):
        relay_type = relay_type or CellRelay
        relay_cell = relay_type(inner_cell, stream_id=stream_id, circuit_id=self.id)
        self.role_ops.encrypt(relay_cell)
        return relay_cell

    def create_stream(self):
        return self.streams.create_new()

    def remove_stream(self, tor_stream):
        self.streams.remove(tor_stream)

    def close_all_streams(self):
        for stream in list(self.streams.values()):
            stream.close()

    def destroy(self, send_destroy=True):
        pass

    @property
    def id(self):
        return self._id

    @property
    def nodes_count(self):
        return len(self.circuit_nodes)

    @property
    def last_node(self):
        return self.circuit_nodes[-1]

    @staticmethod
    def _make_new_event():
        return asyncio.Event()
