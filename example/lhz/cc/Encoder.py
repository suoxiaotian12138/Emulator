# Encoder.py
# input: message (bits, random or customized)
# output: codes (values that can be directly embedded into traffic features)

# encoding methods:
# 1. Fixed: output decimal codes
# 2. Continuous: continuous code ranging from 0 to modulo
# 3. Spreading code: Walsh-Hadamard spreading code, could result in negative codes, need to be normalized
# 4. Bipolar code: R-S code, Golay code, convolutional code, Turbo code, LDPC code

from scipy.linalg import hadamard
import numpy as np
from reedsolo import RSCodec

class Encoder:
    def __init__(self, bit_string: str = ""):
        self._bit_string = bit_string
        self._codes = None
        self._codes_one_dimensional = None

    def set_bit_string(self, bit_string: str):
        self._bit_string = bit_string
    def get_codes(self):
        return self._codes
    def get_codes_one_dimensional(self):
        if self._codes_one_dimensional is None:
            self.codes_one_dimensional()
        return self._codes_one_dimensional

    def bits_to_decimal_codes_fix(self, code_unit_size: int, bit_unit_size: int):
        # Convert bits to symbols in decimal, fixed size of bits for each symbol
        temp_codes = []
        for i in range(0, len(self._bit_string), bit_unit_size):
            bits_unit = self._bit_string[i: i + bit_unit_size]
            if len(bits_unit) < bit_unit_size:
                bits_unit += "0" * (bit_unit_size - len(bits_unit))
            temp_codes.append(int(bits_unit, 2))
        codes = []
        for i in range(0, len(temp_codes), code_unit_size):
            temp_code = temp_codes[i: i + code_unit_size]
            if len(temp_code) < code_unit_size:
                temp_code += [0] * (code_unit_size - len(temp_code))
            codes.append(temp_code)
        self._codes = codes

    def bits_to_decimal_codes_spreading(self, code_unit_size: int, bit_unit_size: int):
        # Paper: Liu, Yali, et al. "Hide and seek in time—robust covert timing channels." Computer Security–ESORICS 2009: 14th European Symposium on Research in Computer Security, Saint-Malo, France, September 21-23, 2009.
        # generate spreading code: Walsh-Hadamard spreading code matrix with length of spreading_ratio
        # code_unit_size: must be power of 2, N in the original paper
        # bit_unit_size: <= spreading_ratio, K in the original paper
        # Return: spreading code matrix for each bit unit

        H = hadamard(code_unit_size)
        codes = []
        for i in range(0, len(self._bit_string), bit_unit_size):
            bit_unit = self._bit_string[i: i + bit_unit_size]
            if len(bit_unit) < bit_unit_size:
                bit_unit += "0" * (bit_unit_size - len(bit_unit))
            spread_code = np.zeros(code_unit_size)
            for j in range(bit_unit_size):
                bit = 1 if bit_unit[j] == "1" else -1
                spread_code += H[j] * bit
            codes.append([int(s) for s in spread_code])
        # normalize the codes
        min = -bit_unit_size
        codes = [[s - min for s in code] for code in codes]
        self._codes = codes

    def bits_to_decimal_codes_geometric(self, bit_unit_size: int, code_unit_size: int, threshold_delta_sum: int):
        # Paper: Sellke, Sarah H., et al. "TCP/IP timing channels: Theory to implementation." IEEE INFOCOM 2009. IEEE, 2009.
        # bit_unit_size: L in the original paper
        # code_unit_size: n in the original paper
        # threshold_delta_sum: K in the original paper
        # Delta, delta, in second if we use ipd
        # Return: geometric codes matrix
        codes = []
        def comb_generation(n: int, K: int):
            if n == 1:
                return [(i,) for i in range(K + 1)]
            else:
                res = list()
                for i in range(K + 1):
                    for subcomb in comb_generation(n - 1, K - i):
                        res.append((i,) + subcomb)
                return res
        combs = comb_generation(code_unit_size, threshold_delta_sum)
        assert len(combs) >= 2 ** bit_unit_size

        for i in range(0, len(self._bit_string), bit_unit_size):
            bit_unit = self._bit_string[i: i + bit_unit_size]
            if len(bit_unit) < bit_unit_size:
                bit_unit += "0" * (bit_unit_size - len(bit_unit))
            comb = combs[int(bit_unit, 2)]
            code = []
            for k in comb:
                code.append(k)
            codes.append(code)
        self._codes = codes


    def bits_to_decimal_codes_RS(self, bit_unit_size: int, code_unit_size: int, parity_size: int, c_exp: int = 8):
        # Paper: Houmansadr, Amir, and Nikita Borisov. "CoCo: coding-based covert timing channels for network flows." International Workshop on Information Hiding. Berlin, Heidelberg: Springer Berlin Heidelberg, 2011.
        # bit_unit_size: each x bits to a decimal, less than 8
        # code_unit_size: each x decimal to a R-S code unit
        # parity_size: R-S code parity size
        # Return: R-S code in decimal format
        if bit_unit_size > 8:
            raise ValueError("R-S codec only supports bit_unit_size <= 8")
        decimal_codes = []
        for i in range(0, len(self._bit_string), bit_unit_size):
            bits_unit = self._bit_string[i: i + bit_unit_size]
            if len(bits_unit) < bit_unit_size:
                bits_unit += "0" * (bit_unit_size - len(bits_unit))
            decimal_codes.append(int(bits_unit, 2))
        rs_codec = RSCodec(nsym = parity_size, c_exp = c_exp)
        RS_codes = []
        msg_unit_size = code_unit_size - parity_size
        for i in range(0, len(decimal_codes), msg_unit_size):
            code_unit = decimal_codes[i: i + msg_unit_size]
            if len(code_unit) < msg_unit_size:
                code_unit += [0] * (msg_unit_size - len(code_unit))
            RS_code = rs_codec.encode(bytes(code_unit))
            RS_codes.append(list(RS_code))
        self._codes = RS_codes

    def codes_one_dimensional(self):
        one_dimensional_codes = []
        for code in self._codes:
            one_dimensional_codes += code
        self._codes_one_dimensional = one_dimensional_codes



