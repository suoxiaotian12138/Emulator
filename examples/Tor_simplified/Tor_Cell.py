import struct
import os
import logging
import socket

from struct import pack, unpack
from torpy.utils import to_hex, fp_to_str
logger = logging.getLogger(__name__)

from torpy.cells import (
    CellVersions,
    CellCreateFast,
    CellDestroy,
    CellCreatedFast,
    CellRelayEnd,
    CellRelayData,
    CellRelayConnected,
    CellRelayExtended2,
    CellRelayTruncated,
    StreamReason
)

AUTH_METHOD_RSA_SHA256_TLSSECRET = 1
AUTH_METHOD_RSA_SHA256_RFC5705 = 2
AUTH_METHOD_ED25519_SHA256 = 3
AUTH_TYPE_STR = b'AUTH0003'  # 8 bytes

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
        return cls.NUM in (7, 12, 13) or cls.NUM >= 128

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
            # print(f"[DEBUG] relay_payload type: {type(relay_payload)}, value: {relay_payload}")
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



class Cell_Create2(TorCell):
    NUM = 10

    def __init__(self, handshake_type, onion_skin, circuit_id):
        super().__init__(circuit_id)
        self.handshake_type = handshake_type
        self.onion_skin = onion_skin
        if len(onion_skin) > 507:
            raise ValueError(f"onion_skin too long: {len(onion_skin)} > 507")
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


class CellCreated2(TorCell):
    """
    CellCreated2 representation.

    A CREATED2 cell contains:
        DATA_LEN      (Server Handshake Data Len) [2 bytes]
        DATA          (Server Handshake Data)     [DATA_LEN bytes]
    """

    NUM = 11  # Created2

    def __init__(self, handshake_data: bytes, circuit_id: int):
        super().__init__(circuit_id)
        self.handshake_data = handshake_data

    def _serialize_payload(self) -> bytes:
        return struct.pack('!H', len(self.handshake_data)) + self.handshake_data

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int) -> dict:
        if len(payload) < 2:
            raise ValueError("CREATED2 payload too short")

        length = struct.unpack('!H', payload[:2])[0]
        if len(payload) < 2 + length:
            raise ValueError(f"CREATED2 length mismatch: expected {length}, got {len(payload) - 2}")

        handshake_data = payload[2:2 + length]
        return {'handshake_data': handshake_data}

    def _args_str(self):
        return f'handshake_data = {self.handshake_data[:10]}... ({len(self.handshake_data)} bytes)'


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

class CellRelaySendMe(TorCell):
    NUM = 5

    def __init__(self, circuit_id=0, *, version: int = 0, digest: bytes | None = None):
        super().__init__(circuit_id)
        self.version = int(version)
        self.digest = digest or b""

    def _serialize_payload(self):
        if self.version <= 0:
            return b""
        if self.version != 1:
            return b""
        if len(self.digest) != 20:
            raise ValueError("SENDME v1 digest must be 20 bytes")
        data_len = len(self.digest)
        return bytes([self.version, data_len]) + self.digest

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        if not payload:
            return {"version": 0, "digest": b""}
        if len(payload) < 2:
            return {"version": 0, "digest": b""}
        version = payload[0]
        data_len = payload[1]
        digest = payload[2:2 + data_len]
        return {"version": version, "digest": digest}

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

class CellAuthChallenge(TorCell):
    NUM = 130

    def __init__(self, challenge: bytes = None, methods: list[int] = None, circuit_id: int = 0):
        super().__init__(circuit_id)
        # Challenge: 32 随机字节
        self.challenge = challenge or os.urandom(32)
        # Methods: 每个方法用 2 字节表示
        self.methods = methods or [AUTH_METHOD_ED25519_SHA256]

    def _serialize_payload(self) -> bytes:
        n_methods = len(self.methods)
        # 32B challenge | 2B n_methods | 2B * n_methods (methods)
        return b"".join([
            self.challenge,
            struct.pack("!H", n_methods),
            struct.pack("!" + "H"*n_methods, *self.methods),
        ])

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        # 最少需要 32B challenge + 2B n_methods
        if len(payload) < 32 + 2:
            raise ValueError("AUTH_CHALLENGE too short")

        off = 0
        # ① Challenge
        challenge = payload[off:off+32]
        off += 32

        # ② N_Methods（2 字节大端）
        n_methods = struct.unpack("!H", payload[off:off+2])[0]
        off += 2

        # ③ Methods，每个方法 2 字节
        expected_len = n_methods * 2
        if len(payload) < off + expected_len:
            raise ValueError("AUTH_CHALLENGE malformed (methods length mismatch)")

        methods = []
        for _ in range(n_methods):
            method = struct.unpack("!H", payload[off:off+2])[0]
            methods.append(method)
            off += 2

        # 按规范，多余的字节主动忽略
        return {
            "challenge": challenge,
            "methods": methods
        }

class CellAuthenticate(TorCell):
    NUM = 131  # AUTHENTICATE

    def __init__(self, auth_type: int, auth_data: bytes, circuit_id=0):
        super().__init__(circuit_id)
        self.auth_type = auth_type
        self.auth_data = auth_data

    @classmethod
    def is_var_len(cls):
        return True

    def _serialize_payload(self) -> bytes:
        # payload = 2B auth_type | 2B auth_len | auth_data
        if len(self.auth_data) > 0xFFFF:
            raise ValueError(f"AUTHENTICATE auth_data too long: {len(self.auth_data)}")
        return struct.pack("!HH", self.auth_type, len(self.auth_data)) + self.auth_data

    def serialize(self, proto_version, negotiating=False):
        # varcell header: circid | cmd | len(2B) | body
        if proto_version < 4:
            hdr = struct.pack("!HB", self.circuit_id, self.NUM)  # 2B circid
        else:
            hdr = struct.pack("!IB", self.circuit_id, self.NUM)  # 4B circid

        body = self._serialize_payload()
        if len(body) > 0xFFFF:
            raise ValueError(f"AUTHENTICATE body too long: {len(body)}")

        raw = hdr + struct.pack("!H", len(body)) + body
        return raw

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        # 注意：这里的 payload 应该是“body”（已经按 varcell length 截出来了）
        if len(payload) < 4:
            raise ValueError("AUTHENTICATE too short")
        auth_type, auth_len = struct.unpack_from("!HH", payload, 0)
        if len(payload) < 4 + auth_len:
            raise ValueError(f"AUTHENTICATE truncated: body_len={len(payload)} need={4+auth_len}")
        auth = payload[4:4+auth_len]
        return {"auth_type": auth_type, "auth_data": auth}


class CellNetInfo(TorCell):
    """
    CellNetInfo representation.

    The cell's payload is:

    - Timestamp              [4 bytes]
    - Other OR's address     [variable]
    - Number of addresses    [1 byte]
    - This OR's addresses    [variable]

    Address format:

    - Type   (1 octet)
    - Length (1 octet)
    - Value  (variable-width)
    "Length" is the length of the Value field.
    "Type" is one of:
    - 0x00 -- Hostname
    - 0x04 -- IPv4 address
    - 0x06 -- IPv6 address
    - 0xF0 -- Error, transient
    - 0xF1 -- Error, nontransient
    """

    NUM = 8

    def __init__(self, timestamp, other_or, this_or, circuit_id=0):
        super().__init__(circuit_id)
        self.timestamp = timestamp
        self.other_or = other_or
        self.this_or = this_or

    def _serialize_payload(self):
        # timestamp
        payload = struct.pack('!I', self.timestamp)

        # other_or address
        other_ip = socket.inet_aton(self.other_or)
        payload += struct.pack('!BB', 0x04, 4) + other_ip

        # this OR's address list
        this_ip = socket.inet_aton(self.this_or)
        payload += struct.pack('!B', 1)  # number of addresses
        payload += struct.pack('!BB', 0x04, 4) + this_ip  # IPv4

        return payload

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        # payload is the fixed 509-byte body (for fixed-length cells)
        if len(payload) < 4:
            raise ValueError("NETINFO too short (no timestamp)")

        off = 0

        # 1) timestamp (uint32)
        (ts,) = struct.unpack_from("!I", payload, off)
        off += 4

        def parse_addr(buf: bytes, pos: int):
            # Tor ADDR: type(1) + len(1) + value(len)
            if pos + 2 > len(buf):
                raise ValueError("NETINFO addr header truncated")
            atype = buf[pos]
            alen = buf[pos + 1]
            pos += 2
            if pos + alen > len(buf):
                raise ValueError("NETINFO addr value truncated")

            aval = buf[pos:pos + alen]
            pos += alen

            # Only decode IPv4/IPv6 here; others return empty string
            if atype == 0x04 and alen == 4:
                ip = socket.inet_ntoa(aval)
            elif atype == 0x06 and alen == 16:
                ip = socket.inet_ntop(socket.AF_INET6, aval)
            else:
                ip = ""

            return ip, pos

        # 2) other_or address (one ADDR)
        other_or, off = parse_addr(payload, off)

        # 3) number of this_or addresses
        if off >= len(payload):
            n = 0
        else:
            n = payload[off]
            off += 1

        # 4) this_or addresses (N ADDR)
        this_or = ""
        for _ in range(n):
            ip, off = parse_addr(payload, off)
            if not this_or and ip:
                this_or = ip

        return {"timestamp": ts, "other_or": other_or, "this_or": this_or}

    def _args_str(self):
        return 'timestamp = {!r}, other_or = {!r}, this_or = {!r}'.format(self.timestamp, self.other_or, self.this_or)
# padding_cells.py  (或直接放在原文件任意位置)

class CellPadding(TorCell):                # Cmd = 0，固定 509 B
    NUM = 0

    def _serialize_payload(self):
        # Tor 规范：全部 0 亦可
        return b'\x00' * self.MAX_PAYLOAD_SIZE

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        # 收到后无需处理，直接忽略
        return {}

class CellPaddingNegotiate(TorCell):       # Cmd = 12，可变长
    NUM = 12

    def _serialize_payload(self):
        return b''                          # 暂不协商，自身留空

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        return {}

class CellVPadding(TorCell):               # Cmd = 13，可变长
    NUM = 13

    def _serialize_payload(self):
        # Tor 会随机长度; 这里用空串即可
        return b''

    @staticmethod
    def _deserialize_payload(payload: bytes, proto_version: int):
        return {}

class TorCommands:
    """
    Enum class which contains all available command types.

    tor-spec.txt 3. "Cell Packet format"
    """

    _map = {
        # fmt: off
        # Fixed-length command values.
        # CellCreated.NUM: CellCreated,               # 2
        CellPadding.NUM:          CellPadding,
        CellPaddingNegotiate.NUM: CellPaddingNegotiate,
        CellVPadding.NUM:         CellVPadding,
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
        CellAuthenticate.NUM: CellAuthenticate,    # 131
        # fmt: on
    }

    @classmethod
    def get_by_num(cls, num):
        return cls._map.get(num)

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
