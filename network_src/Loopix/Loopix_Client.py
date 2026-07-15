import numpy as np
import asyncio
from queue import Queue
import random

from tools.Packet.decrypt_packet import decrypt_sphinx_packet, handle_forward_sphinx, handle_receive_surb
from tools.Packet.make_packet import reply_with_surb
from tools.Crypt.serialization import decode
from src.sphinxmix.SphinxClient import Dest_flag, Surb_flag

from network_src.Loopix.Loopix_base import Loopix_Base


class Loopix_Client(Loopix_Base):

    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.provider = None

        self.output_buffer = Queue()
        self.provider_ready = asyncio.Event()
        self.routing_ready = asyncio.Event()
        self.config = self.config_set("parametersClients")
        self.surbkeys_storage = {}


    async def start_protocol(self):
        self.tasks['register_task'] = asyncio.create_task(self.register())
        self.tasks['routing_task'] = asyncio.create_task(self.routing_request())
        self.tasks['subscribe_task'] = asyncio.create_task(self.subscribe_to_provider(self.config.TIME_PULL))
        self.tasks['pull_task'] = asyncio.create_task(self.pull_message(self.config.TIME_PULL))
        self.tasks['listener_task'] = asyncio.create_task(self.listener(self.socket))
        self.tasks['process_task'] = asyncio.create_task(self.process())
        self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(*self.tasks.values())

    async def register(self):
        await self.provider_ready.wait()
        message = ['REGISTER', {
            "node_type": "client",
            "name": self.name,
            "host": self.host,
            "port": self.port,
            "pubk": self.pubk,
            "provider": self.provider
        }]
        addr, port = self.directory_address
        await self.send(self.socket, message, addr, port)

    async def routing_table_update(self, content):
        try:
            temp_routing_table = content.get("routes", {})
            self.routing_table['client'] = temp_routing_table.get('client', [])
            self.routing_table['provider'] = temp_routing_table.get('provider', [])
            self.routing_table['mixnode'] = self.group_layered_topology(temp_routing_table.get('mixnode', []))

            if not self.provider and self.routing_table.get('provider', []):
                self.provider = random.choice(self.routing_table['provider'])
                self.provider_ready.set()
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
                elif not data[0] == 'DUMMY':
                    flag, decrypted_packet, traceid = self.decrypt_packet(data)
                    surb = decrypted_packet.get("surb")
                    if surb:
                        await self.make_reply(surb)
                        self.print("send a reply message")
                    await self.extra_process(flag, decrypted_packet, traceid, addr)

            except Exception as exp:

                self.print("ERROR:", str(exp))

    def decrypt_packet(self, packet):
        try:
            tag, routing, new_header, new_body, mac = decrypt_sphinx_packet(self.params, packet, self.privk)
            routing_flag, meta_info = routing[0], routing[1:]

            if routing_flag == Dest_flag:
                dest, decoded_packet = handle_forward_sphinx(self.params, new_body, mac)
                if dest == [self.host, self.port, self.name]:
                    message, trace_id = decoded_packet['message']
                    if message.startswith(b'HT'):
                        self.print("receive a loop message")
                        return "LOOP", decoded_packet, trace_id
                    else:
                        self.print("receive a new message")
                        return "NEW", decoded_packet, trace_id
                else:
                    raise ValueError("Destination has been tampered with")

            elif routing_flag == Surb_flag:
                self.print("receive a surb message")
                surb_id = routing[-1]
                trace_id = 0
                message = handle_receive_surb(self.params, new_body, surb_id, self.surbkeys_storage)

                return "SURB", {"message": message}, trace_id

            else:
                raise ValueError("Unknown packet type")

        except Exception as exp:
            self.print("ERROR:", str(exp))


    async def periodic_make_stream(self, interval=0.1):
        await self.routing_ready.wait()
        while True:
            # self.print("send a loop message")
            # await self.make_stream_loop()
            self.print("send a real message")
            await self.make_stream_real()
            await asyncio.sleep(interval)


    async def make_stream_loop(self):
        loop_message = b'HT' + np.random.bytes(self.config.NOISE_LENGTH)
        path = self.construct_full_path(receiver=self.build_client_info(self))
        packet = await self.make_packet(message=loop_message, path=path)
        host = path[0]["host"]
        port = path[0]["port"]
        await self.send(self.socket, packet, host, port)


    async def make_stream_real(self, need_surb=False):
        if not self.output_buffer.empty():
            message, receiver = self.output_buffer.get()
        else:
            message = self.generate_random_string(self.config.NOISE_LENGTH)
            receiver = random.choice(self.routing_table["client"])

        path = self.construct_full_path(receiver)
        host = path[0]["host"]
        port = path[0]["port"]

        if need_surb:
            surb_receiver = self.build_client_info(self)
            mix_chain = self.random_routing_strategy()
            surb_path = [receiver.get('provider', '')] + mix_chain + [surb_receiver.get('provider', '')] + [surb_receiver]
            packet = await self.make_packet_with_surb(message, path, surb_path, self.surbkeys_storage)
        else:
            packet = await self.make_packet(message=message, path=path)
        await self.send(self.socket, packet, host, port)


    async def make_reply(self, surb, message=None):
        if not message:
            message = self.generate_random_string(self.config.NOISE_LENGTH)
        surb_id = surb.get('id', None)
        surb_header = surb.get('header', None)
        if not surb_id or not surb_header:
            raise ValueError("Invaild surb block")
        raw_data = surb_header[0]
        routing_flag, meta_info = decode(raw_data)
        next_addr, next_name, extra = meta_info
        trace_id, drop_flag, delay = extra
        host, port = next_addr
        reply_header, reply_body = reply_with_surb(self.params, surb_header, message)
        packet = (reply_header, reply_body)
        await self.send(self.socket, packet, host, port)

    def construct_full_path(self, receiver=None):
        """构造完整路径"""
        # 后续可能会修改loop message的路径生成逻辑
        if not receiver:
            receiver = random.choice(self.routing_table['client'])
        mix_chain = self.random_routing_strategy()
        return [self.provider] + mix_chain + [receiver.get('provider', '')] + [receiver]

    def random_routing_strategy(self):
        mix_chain = []
        num_all_layers = len(self.routing_table['mixnode'])
        for i in range(num_all_layers):
            mix = random.choice(self.routing_table['mixnode'][i])
            mix_chain.append(mix)
        return mix_chain


    async def subscribe_to_provider(self, interval=10):
        await self.provider_ready.wait()
        while True:
            message = ['SUBSCRIBE', self.name, self.host, self.port]
            await self.send(self.socket, message, self.provider['host'], self.provider['port'])
            await asyncio.sleep(interval)

    async def pull_message(self, interval=10):
        await self.provider_ready.wait()
        while True:
            message = ['PULL', self.name]
            await self.send(self.socket, message, self.provider['host'], self.provider['port'])
            await asyncio.sleep(interval)
