# import sys
# sys.path.append('D:\Oniverse\Emulator')
# from twisted.application import service, internet
# from Crypto.NodeBuild import LoopixNodeSetup
# from Databasemanage.database_init import loopix_database_initial
#
# loopix_database_initial()
# node_set = [9995, '127.0.0.1', 'client1', 1]
# setup = LoopixNodeSetup(node_set)
# created_node = setup.NodeBuild('Client')
# application = service.Application('Client')
# udp_server = internet.UDPServer(created_node.port, created_node)
#
# udp_server.setServiceParent(application)
import time

# %%[1]
from Relay.PacketSender import Loopix_sender
import os
from example.lhz.cc.utils import verbose_print
from example.lhz.cc.Encoder import Encoder
from example.lhz.cc.Embedder import Embedder


class LoopixSenderCC(Loopix_sender):
    def __init__(self, transport, reactor, cc_send_batch: int = 8):
        super().__init__(transport, reactor)
        self._packet_buffer = []
        self._cc_send_batch = cc_send_batch
        self._bits_to_transmit = None
        self._codes_to_transmit = None
        self._features_to_transmit = None
        self._filepaths_to_transmit = None

        self._encoder = Encoder()
        self._embedder = Embedder()
        self._current_sent_index = [0, 0] # filepath, index

        self._num_enqueued_packets = 0
        self._num_sent_packets = 0

        self._file_folder_path = None
        self._receiver_addr = None

    def set_folder_path(self, folder_path: str):
        self._file_folder_path = folder_path

    def set_receiver_addr(self, host, port):
        self._receiver_addr = (host, port)

    def enqueue_packet(self, packet: tuple):
        # tuple: (header, body)
        self._packet_buffer.append(packet)
        self._num_enqueued_packets += 1

    def _dequeue_packet(self) -> tuple:
        if len(self._packet_buffer) == 0:
            return None
        return self._packet_buffer.pop(0)

    def _file_to_bitstring(self, filepath: str):
        with open(filepath, 'rb') as f:
            content = f.read()
            bit_string = ''.join(format(byte, '08b') for byte in content)
        verbose_print(f"Read file: {filepath}, size: {len(content)} bytes, bit string length: {len(bit_string)} bits")
        return bit_string

    def _read_folder_to_bitstrings(self, file_extensions: list = None):
        bitstrings = {}
        for root, dirs, files in os.walk(self._file_folder_path):
            for file in files:
                if file_extensions is None or file.lower().endswith(tuple(file_extensions)):
                    filepath = os.path.join(root, file)
                    try:
                        bit_string = self._file_to_bitstring(filepath)
                        bitstrings[filepath] = bit_string
                        print(f"Read file: {filepath}, size: {len(bit_string)} bits")
                        print(f"Bit string: {bit_string[:64]}...")  # Print the first 64 bits for debugging
                    except Exception as e:
                        print(f"Failed to read：{filepath}, error：{e}")

        self._bits_to_transmit = bitstrings

    def _bitstrings_to_codes(self, method: str = "fix"):
        codes_to_transmit = {}
        for filepath, bit_string in self._bits_to_transmit.items():
            if method == "fix": # only for test
                self._encoder.set_bit_string(bit_string)
                self._encoder.bits_to_decimal_codes_fix(code_unit_size = 4, bit_unit_size = 1)
                codes = self._encoder.get_codes_one_dimensional()
                codes_to_transmit[filepath] = codes
            else:
                raise ValueError("Invalid method for coding.")
        self._codes_to_transmit = codes_to_transmit

    def _codes_to_features(self, method: str = "replay"):
        features_to_transmit = {}
        for filepath, codes in self._codes_to_transmit.items():
            if method == "replay":
                self._embedder.set_one_dimentional_codes(codes)
                legitimate_features = self._embedder.sequence_generator_distribution(distribution = "poisson")
                self._embedder.codes_to_features_replay(legitimate_features = legitimate_features)
                features = self._embedder.get_embedded_features()
                features_to_transmit[filepath] = features

            else:
                raise ValueError("Invalid method for embedding.")
        self._features_to_transmit = features_to_transmit
        self._filepaths_to_transmit = list(features_to_transmit.keys())

    def _ipd_features_to_exact_timestamp(self, features: list):
        send_times = [0, ]
        time_cursor = 0
        for feature in features:
            time_cursor += feature
            send_times.append(time_cursor)
        return send_times


    def try_cc_initial(self):
        self._read_folder_to_bitstrings()
        self._bitstrings_to_codes()
        self._codes_to_features()

    def cc_send_batch(self, host: str, port: int):
        verbose_print(f"current_sent_index: {self._current_sent_index}")
        filepath_to_transmit = self._filepaths_to_transmit[self._current_sent_index[0]]
        features_to_transmit = self._features_to_transmit[filepath_to_transmit][self._current_sent_index[1]: self._current_sent_index[1] + self._cc_send_batch]
        self._current_sent_index[1] += len(features_to_transmit)
        print(f"feature to transmit: {features_to_transmit}")
        delay_times = self._ipd_features_to_exact_timestamp(features_to_transmit)
        print(f"delay times: {delay_times}")
        for delay_time in delay_times:
            packet = self._dequeue_packet()
            self.reactor.callLater(delay_time, super().send, packet, host, port)
            verbose_print(f"Sending packet with delay: {delay_time}")
        if self._current_sent_index[1] >= len(self._features_to_transmit[filepath_to_transmit]): # finish this file
            self._current_sent_index[0] = (self._current_sent_index[0] + 1) % len(self._filepaths_to_transmit)
            self._current_sent_index[1] = 0




    def send(self, packet: tuple, host: str, port: int):
        if (host, port) == self._receiver_addr:
            self.enqueue_packet(packet)
            if len(self._packet_buffer) > self._cc_send_batch:
                self.cc_send_batch(host, port)
            else:
                print(f"current we have {len(self._packet_buffer)} packets in the buffer, waiting for more packets to cc send.")
        else:
            super().send(packet, host, port)


