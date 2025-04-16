from Node.LoopixNodes import Loopix_Client


class Loopix_Sender_with_MixBarrage(Loopix_Client):

    def startProtocol(self):
        print("[%s] > Started" % self.name)

        self.plugin_initial()
        self.turn_on_processing()

        self.message_maker.make_stream("REAL")
        self.generate_probe_matrix()

    def generate_probe_matrix(self):
        tb = self.routingtable['mixnodes']
        print('---------', tb)
