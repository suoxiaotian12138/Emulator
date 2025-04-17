import threading
import time
from collections import deque
from Node.LoopixNodes import Loopix_Client


class LoopixReceiverWithMixBarrage(Loopix_Client):
    def __init__(self, sec_params, name, port, host, privk, pubk, group=None):
        super().__init__(sec_params, name, port, host, privk, pubk, group)
        self.mix_barrage_storage = {}
        self.now_all_pkt_pool = []

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        _, _, msg = self.process.read_packet_client(packet)
        print('GT1')
        try:
            msg = msg.decode('utf-8')
            print('XX', msg)
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
                print('RECV', kkk, len(r))
        except Exception as e:
            print(e)
        try:
            print('=========GT2=========')
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")
