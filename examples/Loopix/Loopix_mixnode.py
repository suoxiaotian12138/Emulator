import numpy as np
import random

import asyncio
from tools.Packet.decrypt_packet import decrypt_sphinx_packet, handle_forward_sphinx

from baselib.sphinxmix.SphinxClient import Relay_flag, Dest_flag
from examples.Loopix.Loopix_base import Loopix_Base


class Loopix_Mixnode(Loopix_Base):

    def __init__(self, name: str, host: str, port: int, group: int):
        super().__init__(name, host, port)
        self.group = group

        self.config = self.config_set()
        self.routing_ready = asyncio.Event()


    async def start_protocol(self):
        self.tasks['register_task'] = asyncio.create_task(self.register())
        self.tasks['routing_task'] = asyncio.create_task(self.routing_request())
        self.tasks['listener_task'] = asyncio.create_task(self.listener(self.socket))
        self.tasks['process_task'] = asyncio.create_task(self.process())
        # self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(*self.tasks.values())


    async def register(self):
        message = ['REGISTER', {
            "node_type": "mixnode",
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "pubk": self.pubk,
            "group": self.group,
        }]
        addr, port = self.directory_address
        await self.send(self.socket, message, addr, port)


    async def routing_table_update(self, content):
        try:
            temp_routing_table = content.get("routes", {})
            self.routing_table['client'] =temp_routing_table.get('client', [])
            self.routing_table['provider'] =temp_routing_table.get('provider', [])
            self.routing_table['mixnode'] = self.group_layered_topology(temp_routing_table.get('mixnode', []))
            if len(self.routing_table['mixnode']) >= 3 and all(len(v) > 0 for v in self.routing_table.values()):
                self.routing_ready.set()
        except Exception as e:
            self.print(f"[ERROR] Failed to initialize routing table: {e}")

    async def process(self):
        while True:
            data, addr = await self.buffer.pop()
            try:
                if data[0] == 'ROUTING_RESPONSE':
                    await self.routing_table_update(data[1])
                else:
                    flag, decrypted_packet, traceid = self.decrypt_packet(data)
                    if flag == "ROUT":
                        delay, new_header, new_body, next_addr, _ = decrypted_packet
                        host, port = next_addr
                        packet = (new_header, new_body)
                        asyncio.create_task(self.delayed_send(packet, host, port, delay))
                        self.print("relay a packet: ", self.group)
                    elif flag == "LOOP":
                        pass
                    else:
                        self.print("Unknown packet type")
                    await self.extra_process(flag, decrypted_packet, traceid, addr)

            except Exception as exp:
                self.print("ERROR:", str(exp))

    async def periodic_make_stream(self, interval):
        await self.routing_ready.wait()
        while True:
            self.print("send a loop message")
            await asyncio.sleep(interval)
            await self.make_stream_loop()

    async def make_stream_loop(self):
        loop_message = b'HT' + np.random.bytes(self.config.NOISE_LENGTH)
        path = self.construct_full_path(receiver=self.build_client_info(self))
        packet = await self.make_packet(message=loop_message, path=path)
        host = path[0]["host"]
        port = path[0]["port"]
        await self.send(self.socket, packet, host, port)


    def construct_full_path(self, receiver=None):
        """构造完整路径"""
        # 后续可能会修改loop message的路径生成逻辑
        path = []
        num_all_layers = len(self.routing_table['mixnode'])
        layer = self.group + 1
        while layer != self.group:
            mix = random.choice(self.routing_table['mixnode'][layer % num_all_layers])
            path.append(mix)
            layer = (layer + 1) % num_all_layers
        path.insert(num_all_layers - 1 - self.group, random.choice(self.routing_table['provider']))
        return path



    def decrypt_packet(self, packet):
        try:
            tag, routing, new_header, new_body, mac = decrypt_sphinx_packet(self.params, packet, self.privk)
            routing_flag, meta_info = routing[0], routing[1:]

            if routing_flag == Relay_flag:
                next_addr, next_name, extra = meta_info[0]
                trace_id, drop_flag, delay = extra
                return "ROUT", [delay, new_header, new_body, next_addr, next_name], trace_id

            elif routing_flag == Dest_flag:
                dest, decoded_packet = handle_forward_sphinx(self.params, new_body, mac)
                if dest == [self.host, self.port, self.name]:
                    message, trace_id = decoded_packet['message']
                    if message.startswith(b'HT'):
                        self.print("receive a loop message")
                        return "LOOP", decoded_packet, trace_id
                    else:
                        return "ERROR", [], None
        except Exception as exp:
            self.print("ERROR:", str(exp))
