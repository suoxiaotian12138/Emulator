import threading
import time
from collections import deque
from typing import Tuple
from tools.sphinxmix import SphinxClient

from Node.LoopixNodes import Loopix_Client


class LoopixReceiverWithMixBarrage(Loopix_Client):
    def __init__(self, sec_params, name, port, host, privk, pubk, group=None):
        super().__init__(sec_params, name, port, host, privk, pubk, group)
        self.mix_barrage_storage = {}

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        info = None
        try:
            _, _, info = self.process.read_packet_client(packet, False)
        except Exception as e:
            print(e)
        if isinstance(info, tuple):
            msg, decrypted_packet = info[0], info[1]
            try:
                msg = msg.decode('utf-8')
                if msg.startswith('rd'):
                    r = msg.split(':')
                    round = r[0].replace('rd', '')
                    flowid = r[1].replace('flow', '')
                    id = r[2]
                    kkk = 'R' + round + ':F' + flowid
                    res = self.mix_barrage_storage.get(kkk, [])
                    res.append(id)
                    self.mix_barrage_storage[kkk] = list(set(res))
                    print('TD-10', kkk, id)
                elif msg.startswith('GR'):
                    r = msg.split(':')
                    round = r[0].replace('GR', '')
                    flowid = r[1].replace('flow', '')
                    kkk = 'R' + round + ':F' + flowid
                    r = self.mix_barrage_storage.get(kkk, [])
                    message = 'RECV:' + kkk + ':' + str(len(r))
                    if 'surb' in decrypted_packet:
                        surb = decrypted_packet['surb']
                        M = message
                        message = message.encode('utf-8')
                        surb_id = surb['id']
                        surb_header = surb['header']
                        reply_header, reply_body = SphinxClient.package_surb(self.sec_params, surb_header,
                                                                             message)
                        packet = (reply_header, reply_body)
                        host = self.routingtable["provider_info"].host
                        port = self.routingtable["provider_info"].port
                        self.sender.send(packet, host, port)
                        print('sendRECE:', M)

            except Exception as e:
                print(e)
        else:
            pass
        try:
            print('=========GT2=========')
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")
