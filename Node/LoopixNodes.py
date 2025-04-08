import os
from twisted.internet import reactor, task
from twisted.internet.protocol import DatagramProtocol
from queue import Queue
import twisted.names.client
from twisted.internet.defer import Deferred

from Relay.PacketSender import Loopix_sender
from Relay.PacketReceiver import LoopixReceiver
from Relay.PacketProccess import LoopixProcess
from Packet.MessageMaker import Loopix_message_maker
from Routing.RoutingTable import LoopixRoutingTable
from Crypto.CryptoNode import LoopixCrypto
from tools.json_reader import JSONReader
from Databasemanage import LoopixDatamanager
from cryptography.hazmat.primitives import serialization
from Attack.Passive_detect import Passive_detect_by_record



class Loopix_node(DatagramProtocol):

    def __init__(self, sec_params, name, port, host, privk, pubk):
        self.name = name
        self.port = port
        self.host = host
        self.privk = privk
        self.pubk = pubk
        self.group = 0
        self.sec_params = sec_params
        self.jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json'))
        self.reactor = reactor
        self.output_buffer = Queue()

    def startProtocol(self):
        print("[%s] > Started" % self.name)
        self.plugin_initial()


    def plugin_initial(self,nodetype = "mixnode"):
        self.crypto_node = LoopixCrypto(self.sec_params)
        self.process = LoopixProcess(self)
        self.sender = Loopix_sender(self.transport, self.reactor)
        self.routingtable = LoopixRoutingTable(nodetype).routing_table
        self.message_maker = Loopix_message_maker(self)
        self.receiver = LoopixReceiver(config_params=self.config_params, message_maker=self.message_maker)


    def turn_on_processing(self):
        reactor.callLater(20.0, self.get_and_addCallback, self.handle_packet)

    def get_and_addCallback(self, function):
        self.receiver.get().addCallback(function)

    def add_callback_to(self, func, callback_func):
        """调用任意函数，并将其返回值传递给 callback_func"""
        result = func()  # 调用原函数
        if isinstance(result, Deferred):
            # 如果是 Deferred，绑定回调
            result.addCallback(callback_func)
        else:
            # 否则直接回调（模拟立即完成）
            reactor.callLater(0, callback_func, result)

    def datagramReceived(self, data, addr):
        print("received datagram")
        self.receiver.put((data,addr))

    def handle_packet(self, packet):
        """ 处理收到的 UDP 数据包 """
        self.process.read_packet()
        try:
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")

    def stopProtocol(self):
        print("[%s] > Stopped" % self.name)



class Loopix_Mixnode(Loopix_node):

    def __init__(self, sec_params, name, port, host, privk, pubk, group):
        super().__init__(sec_params, name, port, host, privk, pubk)
        self.type = "mixnode"
        self.group = group
        self.config_params = self.jsonReader.get_loopix_config_params("parametersMixnodes")
        self.register()


    def startProtocol(self):
        print("[%s] > Started" % self.name)
        self.plugin_initial()
        self.turn_on_processing()
        # self.message_maker.make_stream("LOOP")


    def register(self):
        dbManager = LoopixDatamanager.LoopixDatamanager("database.db")
        dbManager.insert_row_into_table('Mixnodes',[None, self.name, self.port, self.host, self.pubk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'), self.group])
        dbManager.close_connection()

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        self.process.read_packet_mixnode(packet)
        try:
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")



class Loopix_Client(Loopix_node):
    def __init__(self, sec_params, name, port, host, privk,pubk,group=None):
        super().__init__(sec_params, name, port, host, privk,pubk)
        self.type = "client"
        self.config_params = self.jsonReader.get_loopix_config_params(paramsname="parametersClients")


    def startProtocol(self):
        print("[%s] > Started" % self.name)

        # self.transport.write(b"hello", ("127.0.0.1", 9999))
        self.plugin_initial()
        self.turn_on_processing()
        # self.message_maker.make_stream("LOOP")
        # self.message_maker.make_stream("DROP")
        self.message_maker.make_stream("REAL")

    def plugin_initial(self,nodetype = "client"):
        self.crypto_node = LoopixCrypto(self.sec_params)
        self.process = LoopixProcess(self)
        self.sender = Loopix_sender(self.transport, self.reactor)
        self.routingtable = LoopixRoutingTable(nodetype).routing_table
        self.provider = self.routingtable["provider_info"]
        self.subscribe_provider()
        self.message_maker = Loopix_message_maker(self)
        self.receiver = LoopixReceiver(config_params=self.config_params, message_maker=self.message_maker)
        self.register()

    def subscribe_provider(self):
        lc = task.LoopingCall(self.sender.send, ['SUBSCRIBE', self.name, self.host, self.port], self.provider.host, self.provider.port)
        lc.start(self.config_params.TIME_PULL, now=True)

    def register(self):
        dbManager = LoopixDatamanager.LoopixDatamanager("database.db")
        dbManager.insert_row_into_table('Clients',[None, self.name, self.port, self.host, self.pubk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8'), self.provider.name])
        dbManager.close_connection()

    def retrieve_messages(self):
        lc = task.LoopingCall(self.sender.send, ['PULL', self.name],self.provider.host,self.provider.port)
        lc.start(self.config_params.TIME_PULL, now=True)

    def turn_on_processing(self):
        self.retrieve_messages()
        reactor.callLater(20.0, self.get_and_addCallback, self.handle_packet)

    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        self.process.read_packet_client(packet)
        try:
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")


class Loopix_Provider(Loopix_node):
    def __init__(self, sec_params, name, port, host, privk, pubk,group=None):
        super().__init__(sec_params, name, port, host, privk,pubk)
        self.type = "client"
        self.config_params = self.jsonReader.get_loopix_config_params("parametersProviders")
        self.register()



    def startProtocol(self):
        print("[%s] > Started" % self.name)
        self.plugin_initial()
        self.turn_on_processing()
        # self.message_maker.make_stream("LOOP")


    def plugin_initial(self,nodetype = "provider"):
        self.crypto_node = LoopixCrypto(self.sec_params)
        self.process = LoopixProcess(self)
        self.sender = Loopix_sender(self.transport, self.reactor)
        self.routingtable = LoopixRoutingTable(nodetype).routing_table
        self.message_maker = Loopix_message_maker(self)
        self.receiver = LoopixReceiver(config_params=self.config_params, message_maker=self.message_maker)
        self.storagebox_initial()

    def register(self):
        dbManager = LoopixDatamanager.LoopixDatamanager("database.db")
        dbManager.insert_row_into_table('Providers',[None, self.name, self.port, self.host, self.pubk.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')])
        dbManager.close_connection()



    def handle_packet(self, packet_addr):
        """ 处理收到的 UDP 数据包 """
        packet, addr = packet_addr
        self.process.read_packet_provider(packet)
        try:
            # 再次调用 handle_packet 以实现循环监听
            self.reactor.callFromThread(self.get_and_addCallback, self.handle_packet)
        except Exception as exp:
            print(f"[{self.name}] > Exception during scheduling next get: {str(exp)}")

    def storagebox_initial(self):
        self.receiver.setup_storage_clients()

    def turn_on_processing(self):
        reactor.callLater(20.0, self.get_and_addCallback, self.handle_packet)

    def is_assigned_client(self, client_id):
        return any(c == client_id for c in self.receiver.clients)






