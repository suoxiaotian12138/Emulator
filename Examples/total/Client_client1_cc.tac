## client as cc sender

import os
import sys
import types
sys.path.append('D:\Oniverse\Emulator')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from Databasemanage.database_init import loopix_database_initial

from Relay.PacketProccess import LoopixProcess
from Packet.MessageMaker import Loopix_message_maker
from Routing.RoutingTable import LoopixRoutingTable
from Crypto.CryptoNode import LoopixCrypto

from Relay.PacketReceiver import LoopixReceiver
from example.lhz.LoopixSenderCC import LoopixSenderCC

CC_SEND_FOLDER_PATH = "cctosent"
RECV_HOST = '127.0.0.1'
RECV_PORT = 7774

def plugin_initial_cc_client(self, nodetype = "client"):
    self.crypto_node = LoopixCrypto(self)
    self.process = LoopixProcess(self)
    # self.sender = Loopix_sender(self.transport, self.reactor)
    self.sender = LoopixSenderCC(self.transport, self.reactor)
    self.sender.set_folder_path(CC_SEND_FOLDER_PATH)
    self.sender.try_cc_initial()
    self.sender.set_receiver_addr(RECV_HOST, RECV_PORT)
    self.routingtable = LoopixRoutingTable(nodetype,self.name).routing_table
    self.receiver = LoopixReceiver(self)
    # self.receiver = LoopixReceiverCC(config_params = self.config_params, message_maker = self.message_maker)
    # self.receiver.set_output_filepath(CC_RECV_FILE_PATH)
    # self.receiver.turn_on()
    self.provider = self.routingtable["provider_info"]
    # self.subscribe_provider()
    self.message_maker = Loopix_message_maker(self)
    self.register()
    self.receiver.check_new_file()


loopix_database_initial()
node_set = [9995, '127.0.0.1', 'client1', 1]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('Client')
created_node.__class__.plugin_initial = plugin_initial_cc_client

application = service.Application('Client')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
