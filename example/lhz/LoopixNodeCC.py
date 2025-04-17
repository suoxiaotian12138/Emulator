from Relay.PacketProccess import LoopixProcess
from Packet.MessageMaker import Loopix_message_maker
from Routing.RoutingTable import LoopixRoutingTable
from Crypto.CryptoNode import LoopixCrypto
from LoopixSenderCC import LoopixSenderCC
from LoopixReceiverCC import LoopixReceiverCC

import os
import sys
import types
sys.path.append('D:\Oniverse\Emulator')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from Databasemanage.database_init import loopix_database_initial

CC_SEND_FOLDER_PATH = "tosent/"
CC_RECV_FILE_PATH = "cc_recv_bits.txt"

def plugin_initial_cc(self, nodetype = "mixnode"):
    self.crypto_node = LoopixCrypto(self.sec_params)
    self.process = LoopixProcess(self)
    # self.sender = Loopix_sender(self.transport, self.reactor)
    self.sender = LoopixSenderCC(self.transport, self.reactor)
    self.sender.read_folder_to_bitstrings(CC_SEND_FOLDER_PATH)

    self.routingtable = LoopixRoutingTable(nodetype).routing_table
    self.message_maker = Loopix_message_maker(self)
    # self.receiver = LoopixReceiver(config_params=self.config_params, message_maker=self.message_maker)
    self.receiver = LoopixReceiverCC(config_params = self.config_params, message_maker = self.message_maker)
    self.receiver.set_output_filepath(CC_RECV_FILE_PATH)


loopix_database_initial()
node_set = [9995, '127.0.0.1', 'client1', 1]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('Client')
created_node.__class__.plugin_initial = plugin_initial_cc

application = service.Application('Client')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
