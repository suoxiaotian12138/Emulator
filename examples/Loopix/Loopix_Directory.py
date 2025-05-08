import asyncio
import json
from tools.Packet.packet_UDP import send_udp, recv_udp
from tools.Packet.make_packet import RoutingInfo
from examples.Loopix.Loopix_base import Loopix_Base
from tools.Crypt.serialization import decode
class LoopixNodeHandler(Loopix_Base):
    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.routing_buffer = asyncio.Queue()
        self.registered_nodes = {}  # node_id -> dict
        self.routing_table = {}     # type -> list of dict

    async def start(self):
        # Start receive loop
        asyncio.create_task(self.receive_loop())
        # Start routing buffer processing
        asyncio.create_task(self.routing_dispatcher())

    async def receive_loop(self):
        loop = asyncio.get_running_loop()

        while True:
            result = await loop.run_in_executor(None, self.recv, self.socket)
            if result:
                data, addr = result
                try:
                    message = decode(data)
                    if isinstance(message, list) and len(message) == 2:
                        msg_type, content = message
                        if msg_type == "REGISTER":
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
            # Copy entire content, fallback for host/port if missing
            node_info = content.copy()
            self.registered_nodes[node_name] = node_info
            # print(f"[INFO] Registered node {node_name} as {node_type} from {addr}")

    async def routing_dispatcher(self):
        while True:
            _, addr = await self.routing_buffer.get()
            response = {}
            for info in self.registered_nodes.values():
                node_type = info.get("extra", {}).get("type", "unknown")
                response.setdefault(node_type, []).append(info)
            payload = ["ROUTING_RESPONSE", {"routes": response}]
            send_udp(self.socket, payload, addr[0], addr[1])
            print(f"[INFO] Sent full routing table to {addr}")


