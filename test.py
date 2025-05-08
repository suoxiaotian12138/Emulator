import asyncio
import json
import socket
from tools.Packet.packet_UDP import *
from examples.Loopix.Loopix_Directory import LoopixNodeHandler
# Create a simple UDP sender/receiver for test
class UDPTestClient:
    def __init__(self, local_port=0):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', local_port))
        self.sock.setblocking(False)

    async def send_json(self, data, host, port):
        self.sock.sendto(json.dumps(data).encode(), (host, port))

    async def recv_json(self, timeout=2.0):
        loop = asyncio.get_running_loop()
        try:
            data, _ = await asyncio.wait_for(
                loop.run_in_executor(None, recv_udp, self.sock),
                timeout=timeout
            )
            return json.loads(data.decode())
        except Exception as e:
            print(f"[Client] recv_json timeout or error: {e}")
            return None


# Main test routine
async def run_test_client(server_port):
    client = UDPTestClient(9001)

    # Register node
    await client.send_json({
        "type": "register",
        "id": "testnode1",
        "node_type": "mix",
        "public_key": "KEY",
        "group": 1,
        "tags": ["test", "eu"]
    }, '127.0.0.1', server_port)

    await asyncio.sleep(0.2)

    # Send heartbeat
    await client.send_json({
        "type": "heartbeat",
        "id": "testnode1"
    }, '127.0.0.1', server_port)

    await asyncio.sleep(0.2)

    # Send route request
    await client.send_json({
        "type": "route",
        "types": ["mix"],
        "group": 1,
        "tags": ["eu"]
    }, '127.0.0.1', server_port)

    await asyncio.sleep(0.5)

    response = await client.recv_json()
    print("[Client] Received response:", json.dumps(response, indent=2))

async def main():
    # Start Loopix base node
    handler = LoopixNodeHandler(name="registry", host="127.0.0.1", port=9002)
    await handler.start()

    # Run client after short delay
    await asyncio.sleep(0.5)
    await run_test_client(server_port=9002)


# Run the test
if __name__ == '__main__':
    asyncio.run(main())
