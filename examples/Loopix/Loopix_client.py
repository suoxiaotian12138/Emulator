import numpy as np
import asyncio
from queue import Queue
import random

from tools.Packet.decrypt_packet import decrypt_sphinx_packet, handle_forward_sphinx, handle_receive_surb
from tools.Packet.make_packet import make_sphinx_packet

from baselib.sphinxmix.SphinxClient import Dest_flag, Surb_flag

from examples.Loopix.Loopix_base import Loopix_Base


class Loopix_client(Loopix_Base):

    def __init__(self, name: str, host: str, port: int):
        super().__init__(name, host, port)
        self.provider = None

        self.output_buffer = Queue()
        self.provider_ready = asyncio.Event()

        self.surbkeys = {}


    async def start_protocol(self):
        self.tasks['register_task'] = asyncio.create_task(self.register())
        self.tasks['routing_task'] = asyncio.create_task(self.routing_request())
        self.tasks['listener_task'] = asyncio.create_task(self.listener(self.socket))
        self.tasks['process_task'] = asyncio.create_task(self.process())
        self.tasks['periodic_send_task'] = asyncio.create_task(self.periodic_make_stream(interval=self.config.EXP_PARAMS_LOOPS))

        await asyncio.gather(
            self.tasks['register_task'], self.tasks['routing_task'], self.tasks['listener_task'],
            self.tasks['process_task'], self.tasks['periodic_send_task']
        )

    async def register(self):
        await self.provider_ready.wait()
        message = ['register', {
        "node_type": "client",
        "name": self.name,
        "host": self.host,
        "port": self.port,
        "public_key": self.pubk,
        "provider": self.provider
        }]
        await self.send(self.socket, message, self.directory_address)


    async def routing_table_update(self, content):
        try:
            self.routing_table = content.get("routes", {})
            mixs = self.group_layered_topology(self.group_layered_topology(self.routing_table['mixnode']))
            self.routing_table['mixnode'] = mixs
            self.provider = random.choice(self.routing_table['provider'])
            self.provider_ready.set()
        except Exception as e:
            print(f"[ERROR] Failed to initialize routing table: {e}")

    async def process(self):
        while True:
            if self.buffer:
                data, addr = self.buffer.pop()
                try:
                    if data[0] == 'ROUTING_RESPONSE':
                        await self.routing_table_update(data[1])
                    else:
                        flag, decrypted_packet, traceid = self.decrypt_packet(data)
                        self.extra_process(flag, decrypted_packet, traceid)

                except Exception as exp:
                    print("ERROR:", str(exp))

    def decrypt_packet(self, packet):
        try:
            tag, routing, new_header, new_body, mac = decrypt_sphinx_packet(self.params, packet, self.privk)
            routing_flag, meta_info = routing[0], routing[1:]

            if routing_flag == Dest_flag:
                dest, decoded_packet = handle_forward_sphinx(self.params, new_body, mac)
                if dest[:-1] == [self.host, self.port, self.name]:
                    message = decoded_packet['message']
                    trace_id = dest[-1]
                    if message.startswith('HT'):
                        return "LOOP", decoded_packet, trace_id
                    else:
                        return "NEW", decoded_packet, trace_id
                else:
                    raise "Destination has been tampered with"

            elif routing_flag == Surb_flag:
                surb_id = routing[-1]
                trace_id = routing[1][-1]
                message = handle_receive_surb(self.params, new_body, surb_id, self.surbkeys)
                return "SURB", message, trace_id

            else:
                raise "Unknown packet type"

        except Exception as exp:
            print("ERROR:", str(exp))


    async def periodic_make_stream(self, interval):
        while True:
            await asyncio.sleep(interval)
            await self.make_stream_loop()

    async def make_stream_loop(self):
        loop_message = 'HT' + np.random.bytes(self.config.NOISE_LENGTH)

        trace_id = self.generate_trace_id()
        path = self.construct_full_path(receiver=self)
        keys = self.take_nodes_keys(path)
        routing_info = self.build_routing_info(path=path, trace_id=trace_id)
        header, body = make_sphinx_packet(params=self.params, message=loop_message, keys=keys,
                                          routing_info=routing_info)
        packet = (header, body)

        host = path[0].host
        port = path[0].port
        await self.send(self.socket, packet, host, port)

    async def make_stream_real(self):
        if not self.output_buffer.empty():
            message, receiver = self.output_buffer.get()
        else:
            message = self.generate_random_string(self.config.NOISE_LENGTH)
            receiver = random.choice(self.routingtable["clients"])

        trace_id = self.generate_trace_id()
        path = self.construct_full_path(receiver)
        keys = self.take_nodes_keys(path)
        routing_info = self.build_routing_info(path=path, trace_id=trace_id)
        header, body = make_sphinx_packet(params=self.params, message=message, keys=keys,
                                          routing_info=routing_info)
        packet = (header, body)

        host = path[0].host
        port = path[0].port
        await self.send(self.socket, packet, host, port)

    def construct_full_path(self, receiver=None):
        """构造完整路径"""
        # 后续可能会修改loop message的路径生成逻辑
        if not receiver:
            receiver = random.choice(self.routing_table['client'])

        mix_chain = []
        num_all_layers = len(self.routing_table['mixnode'])
        for i in range(num_all_layers):
            mix = random.choice(self.routing_table['mixnode'][i])
            mix_chain.append(mix)

        return [self.provider] + mix_chain + [receiver.provider] + [receiver]

    def extra_process(self, flag, decrypted_packet, traceid):
        pass

