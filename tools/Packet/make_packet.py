from typing import List

from baselib.sphinxmix.SphinxClient import Nenc, create_forward_message, create_surb
from baselib.sphinxmix.SphinxParams import SphinxParams
from dataclasses import dataclass


@dataclass
class RoutingInfo:
    host: str
    port: int
    name: str
    extra: list


def make_sphinx_packet(params: SphinxParams, keys: list, message: bytes, routing_info: List[RoutingInfo]):
    receiver = routing_info[-1]
    routing_info_encoded = encode_routing(routing_info)
    dest = (receiver.host, receiver.port, receiver.name, receiver.extra)
    payload = {'message': message}

    header, body = create_forward_message(params, routing_info_encoded, keys, dest, payload)
    return header, body

def make_sphinx_packet_with_surb(
        params: SphinxParams,
        keys: list,
        message: bytes,
        routing_info: List[RoutingInfo],
        keys_surb: list,
        surb_routing_info: List[RoutingInfo],
        surbkeys_storage: dict
):
    receiver = routing_info[-1]
    routing_info_encoded = encode_routing(routing_info)
    dest = (receiver.host, receiver.port, receiver.name, receiver.extra)
    surb_id, surb_key, surb_header = make_sphinx_surb_block(params, keys_surb, surb_routing_info)
    payload = {
        'message': message,
        'surb': {
            'header': surb_header,
            'id': surb_id
        }
    }
    surbkeys_storage[surb_id] = surb_key

    header, body = create_forward_message(params, routing_info_encoded, keys, dest, payload)
    return header, body


def make_sphinx_surb_block(params: SphinxParams, keys: list, routing_info: List[RoutingInfo]):
    receiver = routing_info[-1]
    routing_info = encode_routing(routing_info)
    dest = (receiver.host, receiver.port, receiver.name, receiver.extra)

    return create_surb(params, routing_info, keys, dest)


def encode_routing(routing_info: List[RoutingInfo]):
    routing_info_encoded = []
    for i, node in enumerate(routing_info):
        routing_info_encoded.append(Nenc([(node.host, node.port), node.name, node.extra]))
    return routing_info_encoded

