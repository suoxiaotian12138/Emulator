from twisted.internet import reactor
from twisted.internet.protocol import Protocol




class Tor_node_basic(Protocol):
    #一个待实现功能记录：密钥的定期更新，以及在更新的时候保证正常运行
    def __init__(self, name, port, host, privk, pubk):
        self.name = name
        self.port = port
        self.host = host
        self.privk = privk
        self.pubk = pubk

    def connectionMade(self):
        """当 TCP 连接建立时调用"""
        print("TCP Connection established")
        self.transport.write(b"Hello, Client!\n")

    def dataReceived(self, data):
        print(f"Received: {data.decode()}")
        self.transport.write(data)  # Echo 数据

    def connectionLost(self, reason=None):
        print("Connection closed")


class Tor_node(Tor_node_basic):
    def __init__(self, name, port, host, privk, pubk):
        super().__init__(name, port, host, privk, pubk)
        self.name = name

class Tor_client(Tor_node_basic):
    def __init__(self, name, port, host, privk, pubk):
        super().__init__(name, port, host, privk, pubk)
        self.name = name

class Tor_V3_directory(Tor_node_basic):
    def __init__(self, name, port, host, privk, pubk):
        super().__init__(name, port, host, privk, pubk)
        self.name = name