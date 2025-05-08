from baselib.sphinxmix import SphinxException
from baselib.sphinxmix.SphinxNode import sphinx_process
from baselib.sphinxmix.SphinxClient import PFdecode, receive_forward, receive_surb


def decrypt_sphinx_packet(params, packet, key):
    header, body = packet
    tag, info, (new_header, new_body), final_body = sphinx_process(params, key, header, body)
    routing = PFdecode(params, info)
    return tag, routing, new_header, new_body, final_body


def handle_forward_sphinx(params, packet, mac):
    return receive_forward(params, mac, packet)


def handle_receive_surb(params, packet_body, surb_id, surbKeys):
    if surbKeys is not None:
        if surb_id in surbKeys:
            surb_key = surbKeys[surb_id]
            return receive_surb(params, surb_key, packet_body)
    else:
        raise SphinxException("Unknown surb_id: {}".format(surb_id))