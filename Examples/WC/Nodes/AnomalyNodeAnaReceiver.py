import threading
import time
from collections import deque
from Node.LoopixNodes import Loopix_Client


class LoopixReceiverWithMixBarrage(Loopix_Client):
    def __init__(self, sec_params, name, port, host, privk, pubk, group=None):
        super().__init__(sec_params, name, port, host, privk, pubk, group)
        self.mix_barrage_storage = {}
        self.packet_pool = deque()  # 用于暂存收到的数据包
        self.lock = threading.Lock()

        # 启动处理线程
        self.processor_thread = threading.Thread(target=self.process_packet_loop, daemon=True)
        self.processor_thread.start()

    def handle_packet(self, packet_addr):
        """ 收到 UDP 包时，仅存入池中 """
        with self.lock:
            self.packet_pool.append(packet_addr)

        try:
            # 继续注册下一个包的接收
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")

    def process_packet_loop(self):
        """ 独立线程后台处理包 """
        while True:
            if self.packet_pool:
                # with self.lock:
                #     packet_addr = self.packet_pool.popleft()
                self._process_single_packet()
            else:
                time.sleep(0.1)  # 防止 CPU 占用过高

    def _process_single_packet(self):
        print(len(self.packet_pool))
        # packet, addr = packet_addr
        # msg = self.process.read_packet_client(packet)
        # print('GT1')
        # msg = msg.decode('utf-8')
        # if msg.startswith('rd'):
        #     r = msg.split(':')
        #     round = r[0].replace('rd', '')
        #     flowid = r[1].replace('flow', '')
        #     id = r[2]
        #     kkk = f'R{round}:F{flowid}'
        #     res = self.mix_barrage_storage.get(kkk, [])
        #     res.append(id)
        #     self.mix_barrage_storage[kkk] = list(set(res))
        #     print('TD-10', kkk, id)
        # elif msg.startswith('GR'):
        #     r = msg.split(':')
        #     round = r[0].replace('GR', '')
        #     flowid = r[1].replace('flow', '')
        #     kkk = f'R{round}:F{flowid}'
        #     r = self.mix_barrage_storage.get(kkk, [])
        #     print('RECV', kkk, len(r))
