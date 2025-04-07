from tools.Serialization import decode
from tools.sphinxmix.SphinxClient import Relay_flag,Dest_flag
import weakref
import itertools


class LoopixProcess():
    def __init__(self, loopixnode):
        self._node_ref = weakref.ref(loopixnode) if loopixnode else None

    def read_packet(self):
        return
    def read_packet_client(self, packet):
        decoded_packet = decode(packet)
        print("here is client")
        if not decoded_packet[0] == 'DUMMY':
            print("dummy")
            flag, decrypted_packet = self.process_packet(decoded_packet)
            return flag, decrypted_packet

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
                print(f"[{loopix_node.name}] > Received loop message")
        except Exception as exp:
            print("ERROR:", str(exp))

    def read_packet_provider(self, packet):
        loopix_node = self._node_ref()
        try:
            decoded_packet = decode(packet)
            if decoded_packet[0] == 'SUBSCRIBE':
                print("receive a sub message")
                self._subscribe_client(decoded_packet[1:])
            elif decoded_packet[0] == 'PULL':
                print("pull a message")
                pulled_messages = loopix_node.receiver.pull_messages(client_id=decoded_packet[1])
                list(map(lambda pair: loopix_node.sender.send(pair[0], *pair[1]),
                         zip(pulled_messages, itertools.repeat(loopix_node.receiver.clients[decoded_packet[1]]))))
            else:
                flag, decrypted_packet = self.process_packet(decoded_packet)
                if flag == "ROUT":
                    delay, new_header, new_body, next_addr, next_name = decrypted_packet
                    if loopix_node.is_assigned_client(next_name):
                        loopix_node.put_into_storage(next_name, (new_header, new_body))
                    else:
                        loopix_node.reactor.callFromThread(self._send_or_delay,
                                                    delay,
                                                    (new_header, new_body),
                                                    next_addr)
                elif flag == "LOOP":
                    print("[%s] > Received loop message" % loopix_node.name)
                elif flag == "DROP":
                    print("[%s] > Received drop message" % loopix_node.name)
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
            return ("DROP", []) if drop_flag else ("ROUT", [delay, new_header, new_body, next_addr, next_name])

        elif routing_flag == Dest_flag:
            # 处理目标节点
            print("dest message")
            dest, message = loopix_node.crypto_node.handle_received_forward(new_body, mac)
            if dest == [loopix_node.host, loopix_node.port, loopix_node.name]:
                return ("LOOP", [message]) if message.startswith(b'HT') else ("NEW", message)
            else:
                return "ERROR", []


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


