from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.python import failure
from twisted.internet.defer import Deferred
from twisted.internet import reactor, task, abstract
from tools.Serialization import encode,decode

#此方法仅用于发送数据包，


#loopix数据包发送，包头和包体都是由sphinx库生成的


class Loopix_sender():
    def __init__(self, transport, reactor):
        self.transport = transport
        self.reactor = reactor

    def send(self, packet, host, port, resolved_adrs=None):
        """ 发送 UDP 数据包的独立函数 """
        encoded_packet = encode(packet)

        if abstract.isIPAddress(host):
            self.transport.write(encoded_packet, (host, port))
        else:
            def send_to_ip(ip_addr):
                self.transport.write(encoded_packet, (ip_addr, port))
            try:
                self.transport.write(encoded_packet, (resolved_adrs[host], port))
            except KeyError:
                d: Deferred = reactor.resolve(host)
                d.addCallback(send_to_ip)
                d.addErrback(lambda failure_obj: print(f"DNS 解析失败: {host} - {failure_obj}"))

        return None

