## provider as cc receiver

import os
import sys
sys.path.append('D:\Oniverse\Emulator')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from Databasemanage.database_init import loopix_database_initial

from Relay.PacketProccess import LoopixProcess
from Packet.MessageMaker import Loopix_message_maker
from Routing.RoutingTable import LoopixRoutingTable
from Crypto.CryptoNode import LoopixCrypto

from Relay.PacketSender import Loopix_sender
from example.lhz.LoopixReceiverCC import LoopixReceiverCC


CC_RECV_FILE_PATH = "example/lhz/torecv/cc_recv"
SENDER_ADDR = ('127.0.0.1', 9995)

def plugin_initial_cc_provider(self, nodetype = "provider"):
    self.routingtable = LoopixRoutingTable(nodetype,self.name).routing_table
    self.crypto_node = LoopixCrypto(self)
    # self.receiver = LoopixReceiver(self)
    self.receiver = LoopixReceiverCC(self)
    self.receiver.set_output_filepath(CC_RECV_FILE_PATH)
    self.receiver.set_sender_addr(SENDER_ADDR)
    self.receiver.turn_on()

    self.process = LoopixProcess(self)
    self.sender = Loopix_sender(self.transport, self.reactor)
    self.message_maker = Loopix_message_maker(self)
    self.storagebox_initial()



loopix_database_initial()
node_set = [9994, '127.0.0.1', 'provider1', 1]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('Provider')
created_node.__class__.plugin_initial = plugin_initial_cc_provider


application = service.Application('Provider')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
