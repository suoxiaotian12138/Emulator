from operator import attrgetter
import itertools
import os
import numpy as np
from tools.sphinxmix.SphinxNode import sphinx_process
from tools.sphinxmix.SphinxClient import PFdecode, Nenc, create_forward_message, receive_forward
from cryptography.hazmat.primitives.asymmetric import ec
import math
from tools.json_reader import JSONReader


class LoopixCrypto(object):
    def __init__(self, params):
        self.sec_params = params
        self.jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json'))
        self.config = self.jsonReader.get_loopix_config_params("parametersMixnodes")
    def Loopix_setup(self):
        ''' setup the parameters of the mix Crypto-system '''
        curve = ec.SECP256R1()  # 选择 P-256（等效于 petlib 的默认曲线）
        private_key = ec.generate_private_key(curve)
        public_key = private_key.public_key()
        generator = public_key.public_numbers().x, public_key.public_numbers().y
        return curve, private_key, public_key, generator

    def make_sphinx_packet(self, receiver, path, message, drop_flag=False, type_flag=None):
        keys_nodes = self.take_nodes_keys(path)
        routing_info = self.take_nodes_routing(path, drop_flag, type_flag)
        print(routing_info)
        dest = (receiver.host, receiver.port, receiver.name)
        header, body = create_forward_message(self.sec_params,
                                              routing_info, keys_nodes, dest, message)
        return header, body

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