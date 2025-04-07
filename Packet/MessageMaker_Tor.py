import struct
import os
from tools.json_reader import JSONReader


class MessageMakerTor:
    def __init__(self):
        # 初始化一些基本参数，后续可以扩展
        self.max_relay_early_cells = 8  # 默认最大RELAY_EARLY单元数
        self.jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'D:\project\Oniverse\config.json'))
        self.cell_params = self.jsonReader.get_tor_config_params("cellSetting")
        self.relay_params = self.jsonReader.get_tor_config_params("relayCommand")

    def relaycellGenerator(self, stream_id, circuit, relay_command, payload, cpath_layer=None):
        """
        生成一个relay cell。

        参数:
            stream_id (int): 数据流ID
            circuit (dict): 电路对象
            relay_command (int): 中继命令类型（如RELAY_COMMAND_DATA）
            payload (bytes): 有效负载数据
            cpath_layer (dict, optional): 加密路径层

        返回:
            bytes: 封装好的relay cell数据
        """
        payload_len = len(payload)
        if payload_len > self.relay_params.RELAY_PAYLOAD_SIZE:
            raise ValueError(f"Payload length {payload_len} exceeds max size {self.relay_params.RELAY_PAYLOAD_SIZE}")

        cell = bytearray(self.cell_params.CELL_TOTAL_SIZE)
        cell_command = self.cell_params.CELL_RELAY
        cell_direction = None

        if circuit.get("is_origin", False):
            if cpath_layer is None:
                raise ValueError("cpath_layer is required for origin circuit")
            circ_id = circuit.get("n_circ_id")
            cell_direction = self.cell_params.CELL_DIRECTION_OUT
        else:
            if cpath_layer is not None:
                raise ValueError("cpath_layer should be None for non-origin circuit")
            circ_id = circuit.get("p_circ_id")
            cell_direction = self.cell_params.CELL_DIRECTION_IN

        if circ_id is None:
            raise ValueError("circ_id is missing in circuit")

        circ = self._select_circuit(circuit, relay_command)
        if circ != circuit:
            cpath_layer = self._get_destination_hop(circ)

        struct.pack_into(">I B", cell, 0, circ_id, cell_command)

        rh = bytearray(self.relay_params.RELAY_HEADER_SIZE)
        struct.pack_into(">B H H", rh, 0, relay_command, stream_id, payload_len)
        cell[5:5 + self.relay_params.RELAY_HEADER_SIZE] = rh

        if payload_len > 0:
            cell[5 + self.relay_params.RELAY_HEADER_SIZE:5 + self.relay_params.RELAY_HEADER_SIZE + payload_len] = payload

        self._pad_cell_payload(cell, payload_len)

        #查看是否需要进行扩展电路，在之后会放到processor里
        if cell_direction == self.cell_params.CELL_DIRECTION_OUT:
            remaining_relay_early = circuit.get("remaining_relay_early_cells", self.max_relay_early_cells)
            cpath = circuit.get("cpath", None)
            if (remaining_relay_early > 0 and
                    (relay_command in (self.relay_params.RELAY_COMMAND_EXTEND, self.relay_params.RELAY_COMMAND_EXTEND2) or
                     cpath_layer != cpath)):
                cell_command = self.cell_params.CELL_RELAY_EARLY
                struct.pack_into(">B", cell, 4, cell_command)
                circuit["remaining_relay_early_cells"] = remaining_relay_early - 1
                relay_early_commands = circuit.get("relay_early_commands", [])
                relay_early_commands.append(relay_command)
                circuit["relay_early_commands"] = relay_early_commands

        return bytes(cell)

    def _select_circuit(self, circuit, relay_command):
        """
        选择电路（预留Conflux支持）。

        参数:
            circuit (dict): 原始电路
            relay_command (int): 中继命令

        返回:
            dict: 选择的电路
        """
        # 如果支持Conflux，这里可以调用conflux相关逻辑
        # 目前直接返回原始电路
        return circuit

    def _get_destination_hop(self, circuit):
        """
        获取目标跳（预留Conflux支持）。

        参数:
            circuit (dict): 电路对象

        返回:
            dict: 目标跳信息
        """
        # 目前返回None，后续可实现
        return None

    def _pad_cell_payload(self, cell, payload_len):
        """
        为单元添加随机填充。

        参数:
            cell (bytearray): 单元数据
            payload_len (int): 有效负载长度
        """
        payload_start = 5
        total_used = payload_start + self.relay_params.RELAY_HEADER_SIZE + payload_len
        if total_used < len(cell):
            padding = os.urandom(len(cell) - total_used)
            cell[total_used:] = padding

    def _format_cell_info(self, cell):
        circ_id, command = struct.unpack(">I B", cell[:5])
        command_name = "CELL_RELAY" if command == self.cell_params.CELL_RELAY else "CELL_RELAY_EARLY"\
            if command == self.cell_params.CELL_RELAY_EARLY else f"Unknown({command})"
        relay_command, stream_id, length = struct.unpack(">B H H", cell[5:10])

        # 映射relay_command到可读名称
        relay_command_names = {
            self.relay_params.RELAY_COMMAND_BEGIN: "RELAY_COMMAND_BEGIN",
            self.relay_params.RELAY_COMMAND_DATA: "RELAY_COMMAND_DATA",
            self.relay_params.RELAY_COMMAND_END: "RELAY_COMMAND_END",
            self.relay_params.RELAY_COMMAND_EXTEND: "RELAY_COMMAND_EXTEND",
            self.relay_params.RELAY_COMMAND_EXTENDED: "RELAY_COMMAND_EXTENDED",
            self.relay_params.RELAY_COMMAND_EXTEND2: "RELAY_COMMAND_EXTEND2",
            self.relay_params.RELAY_COMMAND_EXTENDED2: "RELAY_COMMAND_EXTENDED2",
            self.relay_params.RELAY_COMMAND_SENDME: "RELAY_COMMAND_SENDME"
        }
        relay_command_name = relay_command_names.get(relay_command, f"Unknown({relay_command})")

        return (f"Circuit ID: {circ_id} (hex: {cell[0:4].hex()})\n"
                f"Command: {command_name} (hex: {cell[4:5].hex()})\n"
                f"Relay Command: {relay_command_name} ({relay_command}), "
                f"Stream ID: {stream_id}, Payload Length: {length}")

# 使用示例
if __name__ == "__main__":
    maker = MessageMakerTor()

    # 模拟电路对象
    circuit = {
        "is_origin": True,
        "n_circ_id": 12345,
        "remaining_relay_early_cells": 0,
        "cpath": {"hop": 1}
    }
    cpath_layer = {"hop": 2}

    # 生成relay cell
    payload = b"Hello, Tor!"
    cell = maker.relaycellGenerator(
        stream_id=1,
        circuit=circuit,
        relay_command=3,  # 假设3是RELAY_COMMAND_DATA
        payload=payload,
        cpath_layer=cpath_layer
    )

    print(f"Generated relay cell length: {len(cell)}")
    print(f"First 20 bytes: {cell[:20].hex()}")
