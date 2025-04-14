import json
import pickle

from support_formats import Origin
import os
import numpy as np
from tools.Serialization import encode
from tools.sphinxmix import SphinxException
from tools.sphinxmix.SphinxNode import sphinx_process
from tools.sphinxmix.SphinxClient import PFdecode, Nenc, create_forward_message, receive_forward, create_surb, receive_surb
from cryptography.hazmat.primitives.asymmetric import ec
import weakref
from tools.json_reader import JSONReader
import sys

class LoopixCrypto(object):
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None
        self.sec_params = loopixnode.sec_params
        self.jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json'))
        self.config = self.jsonReader.get_loopix_config_params("parametersMixnodes")
        self.surb_key_list = {}

    @staticmethod
    def Loopix_setup():
        ''' setup the parameters of the mix Crypto-system '''
        curve = ec.SECP256R1()
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        generator = public_key.public_numbers().x, public_key.public_numbers().y
        return curve, private_key, public_key, generator

    def make_sphinx_packet(self, receiver, path, message, need_surb = False, drop_flag=False, type_flag=None):
        keys_nodes = self.take_nodes_keys(path)
        routing_info = self.take_nodes_routing(path, drop_flag, type_flag)
        dest = (receiver.host, receiver.port, receiver.name)
        if need_surb:
            surb_id, surb_key, surb_header = self.make_sphinx_surb_block(path)
            payload = {
                'message': message,
                'surb': {
                    'header': surb_header,
                    'id': surb_id
                }
            }
            self.surb_key_list[surb_id] = surb_key

        else:
            payload = {
                'message': message,
            }

        header, body = create_forward_message(self.sec_params,
                                              routing_info, keys_nodes, dest, payload)
        return header, body

    def make_sphinx_surb_block(self, path):
        loopix_node = self._node_ref()
        Zero_hop = Origin(loopix_node.name, loopix_node.port, loopix_node.host, loopix_node.pubk)
        backward_path = list(reversed(path[:-1]))
        backward_path.append(Zero_hop)
        keys_nodes = self.take_nodes_keys(backward_path)
        routing_info = self.take_nodes_routing(backward_path, drop_flag=False, type_flag=None)
        dest = (backward_path[-1].host, backward_path[-1].port, backward_path[-1].name)

        return create_surb(self.sec_params, routing_info, keys_nodes, dest)

    def take_nodes_keys(self, nodes):
        return [n.pubk for n in nodes]

    def take_nodes_routing(self, nodes, drop_flag, type_flag):
        last_index = len(nodes) - 1
        return [
            Nenc([(node.host, node.port), (i == last_index) and drop_flag, type_flag,
                  self.generate_random_delay(), node.name])
            for i, node in enumerate(nodes)
        ]

    @staticmethod
    def sample_from_exponential(lambda_param):
        return np.random.exponential(lambda_param)

    def generate_random_delay(self):
        delay_param = self.config.EXP_PARAMS_DELAY
        return 0.0 if np.isclose(delay_param, 0.0) else self.sample_from_exponential(delay_param)

    def decrypt_sphinx_packet(self, packet, key):
        header, body = packet
        tag, info, (new_header, new_body), final_body = sphinx_process(self.sec_params, key, header, body)
        routing = PFdecode(self.sec_params, info)
        return tag, routing, new_header, new_body, final_body

    def handle_received_forward(self, packet, mac):
        return receive_forward(self.sec_params, mac, packet)

    def handle_receive_surb(self, packet, surb_id):
        if surb_id in self.surb_key_list:
            surb_key = self.surb_key_list[surb_id]
            return receive_surb(self.sec_params, surb_key ,packet)
        else:
            raise SphinxException("Unknown surb_id: {}".format(surb_id))