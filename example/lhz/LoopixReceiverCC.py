from Relay.PacketReceiver import LoopixReceiver
from example.lhz.cc.Decoder import Decoder
from example.lhz.cc.Extractor import Extractor
import time
from example.lhz.cc.utils import verbose_print

class LoopixReceiverCC(LoopixReceiver):
    def __init__(self, loopixnode, filepath_output: str = "cc_recv_bits.txt", output_batch_size: int = 8):
        super().__init__(loopixnode)
        self._extractor = Extractor()
        self._decoder = Decoder()
        self._filepath_output = filepath_output
        self._output_batch_size = output_batch_size

        self._on = 0
        self._sender_addr = None

        self._cc_decoding_method = "fix"
        self._cc_extracting_method = "replay"
        self._cc_extracting_features = "ipd"

    def turn_on(self):
        self._on = 1
        self._pkt_arrival_times = []
        self._bit_strings = ""
        self._extracted_features = None
        self._extracted_codes = None
        self._extracted_text = ""
        self._extracted_text_unit = ""

    def set_sender_addr(self, addr: tuple):
        self._sender_addr = addr

    def set_output_filepath(self, filepath: str):
        self._filepath_output = filepath
    def put(self, obj):
        super().put(obj)
        print(f"Received packet of length {len(obj[0])} at time {time.time()}")
        if self._on and self._sender_addr == obj[1]:
            print(f"append a packet from {self._sender_addr} at time {time.time()}")
            self._pkt_arrival_times.append(time.time())
            if len(self._pkt_arrival_times) > self._output_batch_size:
                self._cc_receive_batch()
                self._pkt_arrival_times = [] # clear

    def _arrival_times_to_features(self, method: str = "ipd"):
        # here features = inter-packet delay
        if method == "ipd":
            if len(self._pkt_arrival_times) < 2:
                features = []
            else:
                inter_pkt_delays = [self._pkt_arrival_times[i] - self._pkt_arrival_times[i-1] for i in range(1, len(self._pkt_arrival_times))]
                features = inter_pkt_delays
        else:
            raise ValueError("Invalid method for arrival_times_to_features.")
        self._extracted_features = features
    def _features_to_codes(self, method: str = "replay"):
        # here codes = extracted features
        if method == "replay":
            self._extractor.set_extracted_features(self._extracted_features)
            legitimate_features = self._extractor.sequence_generator_distribution()
            self._extractor.rearrange_features_by_anchor(0, 0,  0)
            self._extractor.features_to_codes_replay(legitimate_features, unique_codes = [0, 1]) # we fix unique codes just for testing
            extracted_codes = self._extractor.get_extracted_codes()
        else:
            raise ValueError("Invalid method for extracting codes.")
        self._extracted_codes = extracted_codes
    def _codes_to_bits(self, method: str = "fix"):
        if method == "fix":
            self._decoder.set_extracted_codes(self._extracted_codes)
            self._decoder.reshape_extracted_codes(code_unit_size = 4)
            self._decoder.decimal_codes_to_bits_fix(bit_unit_size = 1)
            bit_string = self._decoder.get_bit_string()
        else:
            raise ValueError("Invalid method for decoding.")

        self._bit_strings = bit_string
    def _bits_to_text(self):
        # here we convert bits to text, 8 bits = 1 byte
        # and 1 byte = 1 character
        text = ""
        for i in range(0, len(self._bit_strings), 8):
            byte = self._bit_strings[i:i+8]
            text += chr(int(byte, 2))
        self._extracted_text_unit = text
        self._extracted_text += text

    def _to_log(self, filepath: str):
        with open(filepath, 'w') as f:
            f.write(
                f"Sender address: {self._sender_addr}, "
                f"Secoding method: {self._cc_decoding_method.upper()}, "
                f"Extracting method: {self._cc_extracting_method.upper()}, "
                f"Extracting feature: {self._cc_extracting_features.upper()}\n"
            )
            f.write(f"Received text: {self._extracted_text}\n")
            f.write(f"Received {len(self._pkt_arrival_times)} packets\n")
            f.write(f"Extracted features: {[round(f, 3) for f in self._extracted_features]}\n")
            f.write(f"Extracted codes: {self._extracted_codes}\n")
            f.write(f"Decoded bit string: {self._bit_strings}\n")
            f.write(f"Decoded text unit: {self._extracted_text_unit}\n")

    def _cc_receive_batch(self):
        self._arrival_times_to_features(self._cc_extracting_features)
        self._features_to_codes(self._cc_extracting_method)
        self._codes_to_bits(self._cc_decoding_method)
        self._bits_to_text()
        self._to_log(self._filepath_output)
        # verbose_print(f"Received {len(self._pkt_arrival_times)} packets")
        # verbose_print(f"extracted features: {self._extracted_features}")
        # verbose_print(f"extracted codes: {self._extracted_codes}")
        # verbose_print(f"decoded bit string: {self._bit_strings}")
        # verbose_print(f"decoded text: {self._extracted_text}")
