from Node.LoopixNodes import Loopix_Client


class Traffic_Ana_Receiver(Loopix_Client):

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        self.process.read_packet_client(packet)
        print(packet)
        print(addr)
        try:
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")

