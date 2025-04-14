from twisted.conch.ssh.connection import messages

from tools.Serialization import decode
from tools.sphinxmix.SphinxClient import Relay_flag,Dest_flag,Surb_flag
import weakref
import itertools


class LoopixProcess():
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None

    def read_packet(self):
        return

    def read_packet_client(self, packet):
        decoded_packet = decode(packet)
        loopix_node = self._node_ref()
        if not decoded_packet[0] == 'DUMMY':
            flag, decrypted_packet = self.process_packet(decoded_packet)
            if flag == "NEW":
                message = decrypted_packet['message']
                loopix_node.receiver.put_real_message(message)
                if 'surb' in decrypted_packet:
                    surb = decrypted_packet['surb']
                    loopix_node.message_maker.make_reply_message(surb,message)
                else:
                    pass
            elif flag == "LOOP":
                pass
            return flag, decrypted_packet
        else:
            return False, None

    def read_packet_mixnode(self, packet):
        """ 解码和处理收到的数据包 """
        loopix_node = self._node_ref()
        try:
            decoded_packet = decode(packet)
            flag, decrypted_packet = self.process_packet(decoded_packet)
            if flag == "ROUT":
                delay, new_header, new_body, next_addr, _ = decrypted_packet
                loopix_node.reactor.callFromThread(self._send_or_delay, delay, (new_header, new_body), next_addr)
            elif flag == "LOOP":
                pass
        except Exception as exp:
            print("ERROR:", str(exp))

    def read_packet_provider(self, packet):
        loopix_node = self._node_ref()
        try:
            decoded_packet = decode(packet)
            if decoded_packet[0] == 'SUBSCRIBE':
                self._subscribe_client(decoded_packet[1:])
            elif decoded_packet[0] == 'PULL':
                pulled_messages = loopix_node.receiver.pull_messages(client_id=decoded_packet[1])
                list(map(lambda pair: loopix_node.sender.send(pair[0], *pair[1]),
                         zip(pulled_messages, itertools.repeat(loopix_node.receiver.clients[decoded_packet[1]]))))
            else:
                flag, decrypted_packet = self.process_packet(decoded_packet)
                if flag == "ROUT":
                    delay, new_header, new_body, next_addr, next_name = decrypted_packet
                    if loopix_node.is_assigned_client(next_name):
                        loopix_node.receiver.put_into_storage(next_name, (new_header, new_body))
                    else:
                        loopix_node.reactor.callFromThread(self._send_or_delay,
                                                    delay,
                                                    (new_header, new_body),
                                                    next_addr)
                else:
                    pass

        except Exception as exp:
            print("ERROR: ", str(exp))

    def process_packet(self, packet):
        # 解密Sphinx包
        loopix_node = self._node_ref()
        tag, routing, new_header, new_body, mac = loopix_node.crypto_node.decrypt_sphinx_packet(packet, loopix_node.privk)
        routing_flag, meta_info = routing[0], routing[1:]

        if routing_flag == Relay_flag:
            # 处理中继节点
            print("drop message")
            next_addr, drop_flag, type_flag, delay, next_name = meta_info[0]
            print(type_flag)
            return ("DROP", []) if drop_flag else ("ROUT", [delay, new_header, new_body, next_addr, next_name])

        elif routing_flag == Dest_flag:
            # 处理目标节点
            print("dest message")
            dest, decoded_packet = loopix_node.crypto_node.handle_received_forward(new_body, mac)
            if dest == [loopix_node.host, loopix_node.port, loopix_node.name]:
                message = decoded_packet['message']
                return ("LOOP", decoded_packet) if message.startswith(b'HT') else ("NEW", decoded_packet)
            else:
                return ("ERROR", [])

        elif routing_flag == Surb_flag:
            print("surb message")
            surb_id = routing[-1]
            message = loopix_node.crypto_node.handle_receive_surb(new_body, surb_id)
            print(message)
            return ("SURB", message)


    def _send_or_delay(self, delay, packet, addr):
        """ 根据延迟发送或处理包 """
        host,port = addr
        loopix_node = self._node_ref()
        loopix_node.reactor.callLater(delay, loopix_node.sender.send, packet, host,port)

    def _subscribe_client(self, client_data):
        loopix_node = self._node_ref()
        subscribe_key, subscribe_host, subscribe_port = client_data
        loopix_node.receiver.clients[subscribe_key] = (subscribe_host, subscribe_port)
        print("[%s] > Subscribed client" % loopix_node.name)


