import struct
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

class Tor_Cell:
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