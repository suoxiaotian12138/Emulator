import numpy as np
import random

import asyncio
from tools.Packet.packet_UDP import PacketQueue
from tools.Packet.make_packet import make_sphinx_packet
from tools.Packet.decrypt_packet import decrypt_sphinx_packet, handle_forward_sphinx

from baselib.sphinxmix.SphinxClient import Relay_flag, Dest_flag
from examples.Loopix.Loopix_base import Loopix_Base


class Loopix_Provider(Loopix_Base):

    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)

        self.buffer = PacketQueue()
        self.subscribed_clients = {}
        self.client_messages = {}
        self.config = self.config_set("parametersProviders")
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
        "node_type": "provider",
        "name": self.name,
        "host": self.host,
        "port": self.port,
        "pubk": self.pubk,
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
                if data[0] == 'SUBSCRIBE':
                    subscribe_name, subscribe_host, subscribe_port = data[1:]
                    self.subscribed_clients[subscribe_name] = (subscribe_host, subscribe_port)
                elif data[0] == 'PULL':
                    pulled_messages = self.pull_messages(client_id=data[1])
                    for packet in pulled_messages:
                        addr = self.subscribed_clients[data[1]]
                        host, port = addr
                        await self.send(self.socket, packet, host, port)
                elif data[0] == 'ROUTING_RESPONSE':
                    await self.routing_table_update(data[1])
                else:
                    flag, decrypted_packet, traceid = self.decrypt_packet(data)
                    if flag == "ROUT":
                        delay, new_header, new_body, next_addr, next_name = decrypted_packet
                        if next_name in self.subscribed_clients.keys():
                            self.client_messages.setdefault(next_name, []).append((new_header, new_body))
                        else:
                            host, port = next_addr
                            packet = (new_header, new_body)
                            asyncio.create_task(self.delayed_send(packet, host, port, delay))
                    elif flag == "LOOP" or flag == "DROP":
                        self.print("send a loop message")
                        pass

                    self.extra_process(flag, decrypted_packet, traceid)

            except Exception as exp:
                self.print("ERROR:", str(exp))

    def decrypt_packet(self, packet):
        try:
            tag, routing, new_header, new_body, mac = decrypt_sphinx_packet(self.params, packet, self.privk)
            routing_flag, meta_info = routing[0], routing[1:]

            if routing_flag == Relay_flag:
                next_addr, next_name, extra = meta_info[0]
                trace_id, drop_flag, delay = extra
                if drop_flag:
                    return "DROP", []
                else:
                    return "ROUT", [delay, new_header, new_body, next_addr, next_name], trace_id

            elif routing_flag == Dest_flag:
                dest, decoded_packet = handle_forward_sphinx(self.params, new_body, mac)
                if dest[:-1] == [self.host, self.port, self.name]:
                    message = decoded_packet['message']
                    trace_id = dest[-1]
                    if message.startswith(b'HT'):
                        return "LOOP", message, trace_id
                    else:
                        raise "Wrong destination"
                else:
                    raise "Destination has been tampered with"
            else:
                raise "Wrong flag"
        except Exception as exp:
            self.print("ERROR:", str(exp))

    async def periodic_make_stream(self, interval):
        await self.routing_ready.wait()
        while True:
            await asyncio.sleep(interval)
            await self.make_stream_loop()

    async def make_stream_loop(self):
        loop_message = b'HT' + np.random.bytes(self.config.NOISE_LENGTH)

        trace_id = self.generate_trace_id()
        path = self.construct_full_path_loop()
        keys = self.take_nodes_keys(path)
        routing_info = self.build_routing_info(path=path,trace_id=trace_id)
        header, body = make_sphinx_packet(params=self.params, message=loop_message, keys=keys, routing_info=routing_info)
        packet = (header, body)

        host = path[0]["host"]
        port = path[0]["port"]
        await self.send(self.socket, packet, host, port)



    def construct_full_path_loop(self, receiver=None):
        """构造完整路径"""
        # 后续可能会修改loop message的路径生成逻辑
        path = []
        num_all_layers = len(self.routing_table['mixnode'])
        for i in range(num_all_layers):
            mix = random.choice(self.routing_table['mixnode'][i])
            path.append(mix)
        return path


    def extra_process(self, flag, decrypted_packet, traceid):
        pass

    def pull_messages(self, client_id):
        dummy_messages = []
        popped_messages = self.get_clients_messages(client_id)
        if len(popped_messages) < self.config.MAX_RETRIEVE:
            dummy_messages = self.generate_dummy_messages(
                self.config.MAX_RETRIEVE - len(popped_messages))
        return popped_messages + dummy_messages

    def get_clients_messages(self, client_id):
        if client_id in self.client_messages.keys():
            messages = self.client_messages[client_id]
            popped, rest = messages[:self.config.MAX_RETRIEVE], messages[self.config.MAX_RETRIEVE:]
            self.client_messages[client_id] = rest
            return popped
        return []

