
import os
import sys
sys.path.append('D:\Emulator')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from Databasemanage.database_init import loopix_database_initial

loopix_database_initial()
node_set = [8885, '127.0.0.1', 'client1x', 1]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('MixBarrageClient')
application = service.Application('MixBarrageClient')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
