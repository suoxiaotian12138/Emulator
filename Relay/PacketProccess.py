from twisted.conch.ssh.connection import messages
from twisted.logger import eventAsText

from tools.Serialization import decode
from tools.sphinxmix.SphinxClient import Relay_flag, Dest_flag, Surb_flag
import weakref
import itertools


class LoopixProcess():
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None

    def read_packet(self, packet, mode="client"):
        loopix_node = self._node_ref()
        event = 'recv'
        info = None

        mode_map = {
            "client": self.read_packet_client,
            "mixnode": self.read_packet_mixnode,
            "provider": self.read_packet_provider,
        }
        handler = mode_map.get(mode)
        if handler:
            if mode == "client":
                flag, trace_id, _ = handler(packet)
            else:
                flag, trace_id = handler(packet)

            if flag == 'NEW' or flag == 'LOOP':
                event = 'dest'
            elif flag == 'ROUT':
                event = 'recv'
            elif flag == 'DROP':
                event = 'drop'
                info = {"reason": "drop_message"}
            else:
                return None
        else:
            print(f"[ERROR] Unknown mode: {mode}")
            return None

        loopix_node.monitor.recv_log(packet=packet, trace_id=trace_id, event=event, info=info)

    def read_packet_client(self, packet, replySURB=True, surbKeys=None):
        decoded_packet = decode(packet)
        loopix_node = self._node_ref()
        message = ''
        if not decoded_packet[0] == 'DUMMY':
            flag, decrypted_packet, traceid = self.process_packet(decoded_packet, surbKeys)
            if flag == "NEW":
                message = decrypted_packet['message']
                if replySURB:
                    loopix_node.receiver.put_real_message(message)
                if 'surb' in decrypted_packet:
                    surb = decrypted_packet['surb']
                    if replySURB:
                        loopix_node.message_maker.make_stream("REPLY", surb=surb, message=message)
            if flag == "SURB":
                message = decrypted_packet
            return flag, traceid, (message, decrypted_packet)
        else:
            return None, None, None

    def read_packet_mixnode(self, packet):
        """ 解码和处理收到的数据包 """
        loopix_node = self._node_ref()
        try:
            decoded_packet = decode(packet)
            flag, decrypted_packet, traceid = self.process_packet(decoded_packet)
            if flag == "ROUT":
                delay, new_header, new_body, next_addr, _ = decrypted_packet
                packet = (new_header, new_body)
                loopix_node.message_maker.make_stream("FORWARD", delay=delay, addr=next_addr, packet=packet,
                                                      traceid=traceid)
            elif flag == "LOOP":
                pass
            else:
                return None, None
            return flag, traceid

        except Exception as exp:
            print("ERROR:", str(exp))

    def read_packet_provider(self, packet):
        loopix_node = self._node_ref()
        try:
            decoded_packet = decode(packet)
            if decoded_packet[0] == 'SUBSCRIBE':
                self._subscribe_client(decoded_packet[1:])
                return None, None
            # elif decoded_packet[0] == 'PULL':
            #     pulled_messages = loopix_node.receiver.pull_messages(client_id=decoded_packet[1])
            #     client_id = decoded_packet[1]
            #     if client_id not in loopix_node.receiver.clients:
            #         print(f"[ERROR] client_id '{client_id}' not registered in receiver.clients.")
            #         return None,None
            #     client_addr = loopix_node.receiver.clients[client_id]
            #     list(map(
            #         lambda pair: loopix_node.sender.send(pair[0], *pair[1]),
            #         zip(pulled_messages, itertools.repeat(client_addr))
            #     ))
            #     return None,None
            else:
                flag, decrypted_packet, traceid = self.process_packet(decoded_packet)
                if flag == "ROUT":
                    delay, new_header, new_body, next_addr, next_name = decrypted_packet
                    if loopix_node.is_assigned_client(next_name):
                        loopix_node.receiver.put_into_storage(next_name, (new_header, new_body))
                    else:
                        packet = (new_header, new_body)
                        loopix_node.message_maker.make_stream("FORWARD", delay=delay, addr=next_addr, packet=packet,traceid = traceid)

            return flag, traceid


        except Exception as exp:
            print("ERROR: ", str(exp))

    def process_packet(self, packet, surbKeys=None):
        # 解密Sphinx包
        loopix_node = self._node_ref()
        tag, routing, new_header, new_body, mac = loopix_node.crypto_node.decrypt_sphinx_packet(packet,
                                                                                                loopix_node.privk)
        routing_flag, meta_info = routing[0], routing[1:]

        if routing_flag == Relay_flag:
            # 处理中继节点
            print("receive a drop message")
            next_addr, drop_flag, trace_id, delay, next_name = meta_info[0]

            return ("DROP", [], trace_id) if drop_flag else (
                "ROUT", [delay, new_header, new_body, next_addr, next_name], trace_id)

        elif routing_flag == Dest_flag:
            # 处理目标节点
            print("receive a dest message")
            dest, decoded_packet = loopix_node.crypto_node.handle_received_forward(new_body, mac)
            if dest[:-1] == [loopix_node.host, loopix_node.port, loopix_node.name]:
                message = decoded_packet['message']
                trace_id = dest[-1]
                return ("LOOP", decoded_packet, trace_id) if message.startswith(b'HT') else (
                    "NEW", decoded_packet, trace_id)
            else:
                return ("ERROR", [], None)

        elif routing_flag == Surb_flag:
            print("receive a surb message")
            surb_id = routing[-1]
            trace_id = routing[1][-1]
            message = loopix_node.crypto_node.handle_receive_surb(new_body, surb_id, surbKeys)
            return ("SURB", message, trace_id)

    def _subscribe_client(self, client_data):
        loopix_node = self._node_ref()
        subscribe_key, subscribe_host, subscribe_port = client_data
        loopix_node.receiver.clients[subscribe_key] = (subscribe_host, subscribe_port)
        print("[%s] > Subscribed client" % loopix_node.name)
