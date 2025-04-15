
from twisted.internet import reactor, task
from twisted.internet.protocol import DatagramProtocol













class GlobalMonitor(DatagramProtocol):
    def __init__(self, name, port, host):
        self.name = name
        self.port = port
        self.host = host
        self.reactor = reactor

    def startProtocol(self):
        print("[%s] > Started" % self.name)
        self.turn_on_processing()

    def datagramReceived(self, data, addr):
        self.receiver.put((data,addr))

    def turn_on_processing(self):
        reactor.callLater(20.0, self.get_and_addCallback, self.handle_packet)

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr

        self.process(packet)
        try:
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")


    def process(self,packet):


    def log_delay(self, src, dst, delay):
        ...

    def log_packet(self, src, dst):
        ...

    def summary(self):
        ...