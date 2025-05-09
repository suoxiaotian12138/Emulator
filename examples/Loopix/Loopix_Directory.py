import asyncio
import json
from tools.Packet.packet_UDP import send_udp, recv_udp
from tools.Packet.make_packet import RoutingInfo
from examples.Loopix.Loopix_base import Loopix_Base
from tools.Crypt.serialization import decode


class Loopix_Directory(Loopix_Base):
    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.routing_buffer = asyncio.Queue()
        self.registered_nodes = {}  # node_id -> dict
        self.routing_table = {}     # type -> list of dict

    async def start_protocol(self):
        # Start receive loop
        receive_task = asyncio.create_task(self.receive_loop())
        # Start routing buffer processing
        dispatcher_task = asyncio.create_task(self.routing_dispatcher())

        await asyncio.gather(receive_task, dispatcher_task)

    async def receive_loop(self):
        while True:
            result = await self.recv(self.socket)
            if result:
                data, addr = result
                try:
                    message = decode(data)
                    if isinstance(message, list) and len(message) == 2:
                        msg_type, content = message
                        if msg_type == "REGISTER":
                            print("receive a register message")
                            await self.handle_register(content, addr)
                        elif msg_type == "ROUTING":
                            await self.routing_buffer.put((content, addr))
                        else:
                            print(f"[WARN] Unsupported message type: {msg_type}")
                    else:
                        print("[WARN] Unexpected message format:", message)
                except Exception as e:
                    print(f"[ERROR] Failed to parse or handle message: {e}")

    async def handle_register(self, content, addr):
        node_name = content.get("name")
        node_type = content.get("node_type")
        if node_name and node_type:
            node_info = content.copy()
            node_info["host"] = node_info.get("host", addr[0])
            node_info["port"] = node_info.get("port", addr[1])

            # 分类存储
            self.registered_nodes.setdefault(node_type, [])
            # 替换已有节点（去重）
            self.registered_nodes[node_type] = [
                n for n in self.registered_nodes[node_type] if n.get("name") != node_name
            ]
            self.registered_nodes[node_type].append(node_info)

    async def routing_dispatcher(self):
        while True:
            _, addr = await self.routing_buffer.get()
            payload = ["ROUTING_RESPONSE", {"routes": self.registered_nodes}]
            await self.send(self.socket, payload, addr[0], addr[1])
            print(f"[INFO] Sent full routing table to {addr}")


