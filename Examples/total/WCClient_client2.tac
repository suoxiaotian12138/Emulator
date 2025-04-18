
import os
import sys
sys.path.append('D:\Oniverse\Emulator')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from Databasemanage.database_init import loopix_database_initial


loopix_database_initial()
node_set = [8886, '127.0.0.1', 'client2', 1]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('MixBarrageReceiver')
application = service.Application('MixBarrageReceiver')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
