import struct
import os
import logging
import socket

from struct import pack, unpack
from torpy.utils import to_hex, fp_to_str
logger = logging.getLogger(__name__)

from torpy.cells import (
    CellVersions,
    CellNetInfo,
    CellCreateFast,
    CellDestroy,
    CellCreatedFast,
    CellCreated2,
    CellRelayEnd,
    CellRelayData,
    CellRelaySendMe,
    CellRelayConnected,
    CellRelayExtended2,
    CellRelayTruncated,
    StreamReason

)

class TorCell:
    NUM = -1
    MAX_PAYLOAD_SIZE = 509

    def __init__(self, circuit_id=0):
        self.circuit_id = circuit_id

    @classmethod
    def is_var_len(cls):
        """
        If current cell variable-length.
        On a version 2 connection, variable-length cells are indicated by a command byte equal to 7 ("VERSIONS").
        On a version 3 or higher connection, variable-length cells are indicated by a command byte equal to 7 ("VERSIONS"),
        or greater than or equal to 128.
        See tor-spec.txt 3. "Cell Packet format"
        """
        # 假设CellVersions.NUM = 7，如果没有定义则需要导入或定义
        VERSIONS_COMMAND = 7
        if cls.NUM == VERSIONS_COMMAND or cls.NUM >= 128:
            return True
        else:
            return False

    def _serialize_payload(self):
        raise NotImplementedError('Must be implemented in a subclass')

    def serialize(self, proto_version, negotiating=False):
        payload = self._serialize_payload()

        # 特殊处理：VERSIONS cell在协议协商期间必须使用旧格式
        # 即使目标是协议4，VERSIONS cell本身也要用协议3的格式发送
        effective_version = proto_version
        if self.NUM == 7 and negotiating:  # VERSIONS command during negotiation
            effective_version = 3  # 强制使用协议3格式进行协商
            # VERSIONS cell的circuit_id必须为0
            if self.circuit_id != 0:
                raise ValueError("VERSIONS cell must have circuit_id=0")

        # Link protocol 4 increases circuit ID width to 4 bytes.
        if effective_version < 4:
            # Protocol version < 4: 2-byte circuit ID + 1-byte command
            header = struct.pack('!HB', self.circuit_id, self.NUM)
            cell_header_size = 3  # 2 + 1
        else:
            # Protocol version >= 4: 4-byte circuit ID + 1-byte command
            header = struct.pack('!IB', self.circuit_id, self.NUM)
            cell_header_size = 5  # 4 + 1

        if self.is_var_len():
            # 可变长度cell：header + 2字节长度 + payload
            buffer = header + struct.pack('!H', len(payload)) + payload
        else:
            # 固定长度cell：需要确保总长度正确
            if effective_version < 4:
                # 协议版本 < 4：总长度 = 512字节 (2+1+509)
                total_cell_size = 512
            else:
                # 协议版本 >= 4：总长度 = 514字节 (4+1+509)
                total_cell_size = 514

            # 计算需要的payload大小
            payload_size = total_cell_size - cell_header_size

            # 如果payload太长，截断；如果太短，用零填充
            if len(payload) > payload_size:
                payload = payload[:payload_size]
            else:
                payload = payload.ljust(payload_size, b'\x00')

            buffer = header + payload

        return buffer

    @staticmethod
    def deserialize(cell_type, circuit_id, payload, proto_version):
        kwargs = cell_type._deserialize_payload(payload, proto_version)
        return cell_type(**kwargs, circuit_id=circuit_id)

    def _args_str(self):
        return ''

    def __repr__(self):
        """Represent TorCell string."""
        args = self._args_str()
        circ_str = 'circuit_id = {:x}'.format(self.circuit_id) if self.circuit_id else ''
        return '{}({}{})'.format(
            type(self).__name__,
            args,
            ', ' + circ_str if args and circ_str else circ_str
        )

class RelayedTorCell(TorCell):
    NUM = -1
    MAX_PAYLOD_SIZE = 509 - 11

    def __init__(self, inner_cell, stream_id, circuit_id, padding=None, encrypted=None):
        super().__init__(circuit_id)
        self._set_inits(inner_cell, padding, stream_id, None)
        self._encrypted = encrypted
        self._checked = False

    def _set_inits(self, inner_cell, padding, stream_id, digest, **kwargs):
        self._inner_cell = inner_cell
        self._padding = padding or b''
        # if self._padding:
        #    logger.warn('Has some padding!!!')
        self._stream_id = stream_id
        self._digest = digest

    @property
    def digest(self):
        return self._digest

    @property
    def stream_id(self):
        return self._stream_id

    @property
    def is_encrypted(self):
        return self._encrypted is not None

    def get_decrypted(self):
        assert self._checked
        return self._inner_cell

    def prepare(self, digesting_func):
        assert not self.digest, 'already prepared'

        payload = self._serialize_payload()
        self._digest = digesting_func(payload)
        assert len(self.digest) == 4

    def encrypt(self, encrypting_func):
        assert self._digest, 'must be prepared already'

        payload = self._serialize_payload()
        # verbose: logger.debug('relay full cell: %s', to_hex(payload))
        self._encrypted = encrypting_func(payload)

    def _serialize_payload(self):
        if self.is_encrypted:
            return self._encrypted
        else:
            relay_payload = self._inner_cell._serialize_payload()
            # logger.debug('relay_payload: %s', to_hex(relay_payload))

            payload_bytes = struct.pack('!B', self._inner_cell.NUM)
            payload_bytes += struct.pack('!H', 0)  # 'recognized'
            payload_bytes += struct.pack('!H', self._stream_id)
            payload_bytes += struct.pack('!4s', self._digest if self._digest else b'\x00' * 4)  # Digest placeholder
            if len(relay_payload) > RelayedTorCell.MAX_PAYLOD_SIZE:
                raise Exception(
                    'relay payload length cannot be more than {} ({} got)'.format(
                        RelayedTorCell.MAX_PAYLOD_SIZE, len(relay_payload)
                    )
                )
            assert len(relay_payload) + len(self._padding) <= RelayedTorCell.MAX_PAYLOD_SIZE, 'wrong relay payload size'
            payload_bytes += struct.pack('!H', len(relay_payload))
            payload_bytes += struct.pack('!{}s'.format(RelayedTorCell.MAX_PAYLOD_SIZE), relay_payload + self._padding)
            return payload_bytes

    def get_encrypted(self):
        assert self._inner_cell is None
        assert self._encrypted
        return self._encrypted

    def set_encrypted(self, new_encrypted):
        assert new_encrypted
        self._encrypted = new_encrypted

    @staticmethod
    def parse_header(payload):
        try:
            header = struct.unpack('!BHH4sH498s', payload)
            fields = ['cell_num', 'is_recognized', 'stream_id', 'digest', 'relay_payload_len', 'relay_payload_raw']
            return dict(zip(fields, header))
        except struct.error:
            logger.error("Can't unpack: %r", to_hex(payload))
            raise

    @staticmethod
    def set_header_digest(payload, new_digest):
        assert len(new_digest) == 4, 'digest must be 4 bytes'
        return payload[:5] + new_digest + payload[5 + 4:]

    def set_decrypted(self, cell_num, stream_id, digest, relay_payload_len, relay_payload_raw, **kwargs):
        relay_payload = relay_payload_raw[:relay_payload_len]
        padding = relay_payload_raw[relay_payload_len:]
        if all([b == 0 for b in padding]):
            padding = b''

        try:
            cell_type = TorCommands.get_relay_by_num(cell_num)
            logger.debug('Deserialize %s relay cell', cell_type.__name__)
            inner_cell = TorCell.deserialize(cell_type, 0, relay_payload, 0)
        except BaseException:
            logger.error("Can't deserialize %i cell: %r", cell_num, to_hex(relay_payload))
            raise "is error"

        self._set_inits(inner_cell, padding, stream_id, digest)
        self._encrypted = None
        self._checked = True

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        raise NotImplementedError("RelayedTorCell couldn't be deserialized")

    def _args_str(self):
        inner_str = '<encrypted>' if self.is_encrypted and not self._inner_cell else self._inner_cell
        stream_str = ', stream_id = {}'.format(self._stream_id or 0) if self._stream_id else ''
        digest_str = ', digest = {!r}'.format(self._digest) if self._digest else ''
        return 'inner_cell = {!r}{}{}'.format(inner_str, stream_str, digest_str)

class CellAuthChallenge(TorCell):
    NUM = 130

    def __init__(self, challenge: bytes = None, methods: list[int] = None, circuit_id=0):
        super().__init__(circuit_id)
        self.challenge = challenge or os.urandom(32)  # 生成 32 字节随机 challenge
        self.methods = methods or [2]  # 默认支持 TLSCert 方法
        self.reserved = b'\x00\x00\x00\x00'

    def _serialize_payload(self) -> bytes:
        n_methods = len(self.methods)
        payload = (
                self.challenge +
                pack("B", n_methods) +
                bytes(self.methods) +
                self.reserved
        )
        return payload

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        challenge = payload[:32]
        n_methods = payload[32]
        methods = list(payload[33:33 + n_methods])
        reserved = payload[33 + n_methods:33 + n_methods + 4]
        return {
            'challenge': challenge,
            'methods': methods,
            'reserved': reserved,
        }

class CellCerts(TorCell):
    NUM = 129  # 注意是 129，不是 128（CERTS cell 是 129）
    # type 1:RSA  2:LINK  3:ED25519 4:ED-RSA CROSS CERT
    def __init__(self, certs: list[tuple[int, bytes]], circuit_id=0):
        """
        :param certs: list of (cert_type, cert_bytes)
        """
        super().__init__(circuit_id)
        self.certs = certs

    def _serialize_payload(self) -> bytes:
        parts = [pack("B", len(self.certs))]  # number of certs
        for cert_type, cert_body in self.certs:
            parts.append(pack("!BH", cert_type, len(cert_body)))
            parts.append(cert_body)
        return b''.join(parts)

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        certs = []
        idx = 0
        n = payload[0]
        idx += 1
        for _ in range(n):
            cert_type = payload[idx]
            cert_len = unpack("!H", payload[idx+1:idx+3])[0]
            cert_body = payload[idx+3:idx+3+cert_len]
            certs.append((cert_type, cert_body))
            idx += 3 + cert_len
        return {'certs': certs}

class Cell_Create2(TorCell):
    NUM = 10

    def __init__(self, handshake_type, onion_skin, circuit_id):
        super().__init__(circuit_id)
        self.handshake_type = handshake_type
        self.onion_skin = onion_skin

    def _serialize_payload(self):
        return struct.pack('!HH', self.handshake_type, len(self.onion_skin)) + self.onion_skin

    def serialize_payload(self):
        return struct.pack('!HH', self.handshake_type, len(self.onion_skin)) + self.onion_skin

    def _args_str(self):
        return "type = {!r}, onion_skin = b'...'".format(self.handshake_type)

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        if len(payload) < 4:
            raise ValueError("CREATE2 payload too short")

        handshake_type, length = struct.unpack("!HH", payload[:4])
        onion_skin = payload[4:4 + length]

        if len(onion_skin) != length:
            raise ValueError(f"CREATE2 onion_skin length mismatch: expected {length}, got {len(onion_skin)}")

        return {
            "handshake_type": handshake_type,
            "onion_skin": onion_skin
        }

class Cell_RelayEarly(RelayedTorCell):
    NUM = 9
    def __init__(self, inner_cell, stream_id=0, circuit_id=0, padding=None, encrypted=None):
        super().__init__(inner_cell, stream_id, circuit_id, padding=padding, encrypted=encrypted)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'inner_cell': None, 'encrypted': payload}

class CellRelay(RelayedTorCell):
    NUM = 3

    def __init__(self, inner_cell, stream_id=0, circuit_id=0, padding=None, encrypted=None):
        super().__init__(inner_cell, stream_id, circuit_id, padding=padding, encrypted=encrypted)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        return {'inner_cell': None, 'encrypted': payload}

class CellRelayExtend2(TorCell):
    """
    CellRelayExtend2 representation.

    To extend an existing circuit, the client sends an EXTEND2
    relay cell to the last node in the circuit.

    An EXTEND2 cell's relay payload contains:
        NSPEC      (Number of link specifiers)     [1 byte]
          NSPEC times:
            LSTYPE (Link specifier type)           [1 byte]
            LSLEN  (Link specifier length)         [1 byte]
            LSPEC  (Link specifier)                [LSLEN bytes]
        HTYPE      (Client Handshake Type)         [2 bytes]
        HLEN       (Client Handshake Data Len)     [2 bytes]
        HDATA      (Client Handshake Data)         [HLEN bytes]
    """

    NUM = 14

    def __init__(self, ip, port, fingerprint, skin, circuit_id=0):
        super().__init__(circuit_id)
        self.nspec = 2  # 2x NSPEC
        self.link_type = 0  # link_specifier_type::ipv4
        self.finger_type = 2  # link_specifier_type::legacy_id
        self.ip = ip
        self.port = port
        self.fingerprint = fingerprint
        self.skin = skin


    def _serialize_payload(self):
        payload_bytes = struct.pack('!B', self.nspec)
        ip_port_len = 6
        payload_bytes += struct.pack('!BB4sH', self.link_type, ip_port_len, socket.inet_aton(self.ip), self.port)

        assert len(self.fingerprint) == 20
        payload_bytes += struct.pack('!BB20s', self.finger_type, len(self.fingerprint), self.fingerprint)

        assert len(self.skin) == 84
        payload_bytes += struct.pack('!HH', 2, len(self.skin)) + self.skin
        return payload_bytes

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        try:
            offset = 0
            # 1. NSPEC
            nspec = payload[offset]
            offset += 1
            if nspec != 2:
                raise ValueError(f"Expected 2 link specifiers, got {nspec}")

            # 2. 1st Link Specifier: IP + port
            link_type_1 = payload[offset]
            l1_len = payload[offset + 1]
            if link_type_1 != 0 or l1_len != 6:
                raise ValueError("Expected link_type=0 (IPv4), len=6")
            ip_bytes = payload[offset + 2:offset + 6]
            port_bytes = payload[offset + 6:offset + 8]
            ip = socket.inet_ntoa(ip_bytes)
            port = struct.unpack('!H', port_bytes)[0]
            offset += 2 + l1_len  # move past this link specifier

            # 3. 2nd Link Specifier: Fingerprint
            link_type_2 = payload[offset]
            l2_len = payload[offset + 1]
            if link_type_2 != 2 or l2_len != 20:
                raise ValueError("Expected link_type=2 (fingerprint), len=20")
            fingerprint = payload[offset + 2:offset + 2 + l2_len]
            offset += 2 + l2_len

            # 4. Handshake type + length + data
            htype, hlen = struct.unpack('!HH', payload[offset:offset + 4])
            offset += 4
            skin = payload[offset:offset + hlen]
            if len(skin) != hlen:
                raise ValueError("Mismatch in handshake data length")

            return {
                'ip': ip,
                'port': port,
                'fingerprint': fingerprint,
                'skin': skin
            }

        except Exception as e:
            logger.error(f"Failed to deserialize CellRelayExtend2: {e}")
            raise

    def deserialize_payload(self, payload, proto_version):
        return self._deserialize_payload(payload, proto_version)
    def _args_str(self):
        return 'ip = {}, port = {}, fingerprint = {}'.format(self.ip, self.port, fp_to_str(self.fingerprint))

class CellRelayBegin(TorCell):
    NUM = 1
    def __init__(self, address, port, circuit_id=0):
        super().__init__(circuit_id=circuit_id)
        self.address = address
        self.flags = None
        self.port = port

    def _serialize_payload(self):
        addr_port = '{}:{}'.format(self.address, self.port).encode()
        return addr_port + struct.pack('!BI', 0, 0)

    @staticmethod
    def _deserialize_payload(payload, proto_version):
        try:
            # Find the null terminator
            null_index = payload.index(b'\x00')
        except ValueError:
            raise ValueError("Missing null terminator in ADDRPORT")
        addr_port_raw = payload[:null_index].decode()
        rest = payload[null_index + 1:]
        # Extract address and port
        if ':' not in addr_port_raw:
            raise ValueError("ADDRPORT field missing ':' separator")
        address, port_str = addr_port_raw.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError("Invalid port number in ADDRPORT")
        if len(rest) < 4:
            raise ValueError("Not enough bytes for FLAGS")

        return {
            "address": address,
            "port": port
        }

    def _args_str(self):
        return 'address = {!r}, port = {!r}, flags = {!r}'.format(self.address, self.port, self.flags)

class TorCommands:
    """
    Enum class which contains all available command types.

    tor-spec.txt 3. "Cell Packet format"
    """

    _map = {
        # fmt: off
        # Fixed-length command values.
        # CellCreated.NUM: CellCreated,               # 2
        CellRelay.NUM: CellRelay,                   # 3
        CellDestroy.NUM: CellDestroy,               # 4
        CellCreateFast.NUM: CellCreateFast,         # 5
        CellCreatedFast.NUM: CellCreatedFast,       # 6
        CellNetInfo.NUM: CellNetInfo,               # 8
        Cell_RelayEarly.NUM: Cell_RelayEarly,         # 9
        Cell_Create2.NUM: Cell_Create2,               # 10
        CellCreated2.NUM: CellCreated2,             # 11

        # Variable-length command values.
        CellVersions.NUM: CellVersions,             # 7
        # CellVPadding.NUM: CellVPadding,            # 128
        CellCerts.NUM: CellCerts,                   # 129
        CellAuthChallenge.NUM: CellAuthChallenge,   # 130
        # CellAuthenticate.NUM: CellAuthenticate,    # 131
        # fmt: on
    }

    @classmethod
    def get_by_num(cls, num):
        cell_type = cls._map.get(num, None)
        if not cell_type:
            raise Exception('Cell type ({}) not found'.format(num))
        return cell_type

    # The relay commands.
    #
    # Within a circuit, the OP and the exit node use the contents of
    # RELAY packets to tunnel end-to-end commands and TCP connections
    # ("Streams") across circuits. End-to-end commands can be initiated
    # by either edge; streams are initiated by the OP.
    #
    _map2 = {
        # fmt: off
        CellRelayBegin.NUM: CellRelayBegin,            # 1
        CellRelayData.NUM: CellRelayData,              # 2
        CellRelayEnd.NUM: CellRelayEnd,                # 3
        CellRelayConnected.NUM: CellRelayConnected,    # 4
        CellRelaySendMe.NUM: CellRelaySendMe,          # 5
        # CellRelayExtend2.NUM: CellRelayExtend2,        # 6
        # CellRelayExtended2.NUM: CellRelayExtended2,    # 7
        # CellRelayTruncate.NUM: CellRelayTruncate,      # 8
        CellRelayTruncated.NUM: CellRelayTruncated,    # 9
        # CellRelayDrop.NUM: CellRelayDrop,             # 10
        # CellRelayResolve.NUM: CellRelayResolve,       # 11
        # CellRelayResolved.NUM: CellRelayResolved,     # 12
        CellRelayExtend2.NUM: CellRelayExtend2,       # 14
        CellRelayExtended2.NUM: CellRelayExtended2,    # 15
        # ...

    }

    @classmethod
    def get_relay_by_num(cls, num):
        cell_type = cls._map2.get(num, None)
        if not cell_type:
            raise Exception('Cell type ({}) not found'.format(num))
        return cell_type
