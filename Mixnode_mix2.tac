
import os
import sys
sys.path.append('D:\project\Oniverse')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from Databasemanage.database_init import loopix_database_initial
from Attack.CD_attack import AttackerHook

loopix_database_initial()
node_set = [9992, '127.0.0.1', 'mix2', 2]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('Mixnode')
application = service.Application('Mixnode')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
created_node.startProtocol()


drop_list=[
        (("127.0.0.1", 9993), 0),
    ]

attacker = AttackerHook(
        drop_list = drop_list
)
attacker.inject(created_node)

