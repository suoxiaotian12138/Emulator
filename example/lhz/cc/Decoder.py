# Decoder.py
# input: message (bits, random or customized)
# output: decoded message
from reedsolo import RSCodec
from scipy.linalg import hadamard
import numpy as np

class Decoder:
    def __init__(self, extracted_codes: list = None):
        self._extracted_codes = extracted_codes
        self._bit_string = None
        self._codes = None

    def set_extracted_codes(self, extracted_codes: list):
        self._extracted_codes = extracted_codes
    def get_bit_string(self):
        return self._bit_string
    def reshape_extracted_codes(self, code_unit_size: int):
        # Reshape extracted codes to 2D array
        temp_codes = []
        for i in range(0, len(self._extracted_codes), code_unit_size):
            extracted_code = self._extracted_codes[i: i + code_unit_size]
            if len(extracted_code) < code_unit_size:
                extracted_code += [0] * (code_unit_size - len(extracted_code))
            temp_codes.append(extracted_code)
        self._codes = temp_codes

    def decimal_codes_to_bits_fix(self, bit_unit_size: int):
        # Convert decimal codes to bits, directly from binary representation to decimal
        bit_string = ''
        for code in self._codes:
            for c in code:
                bit_string += format(c, f"0{bit_unit_size}b")
        self._bit_string = bit_string

    def decimal_codes_to_bits_spreading(self, code_unit_size: int, bit_unit_size: int):
        # related paper: Liu, Yali, et al. "Hide and seek in time—robust covert timing channels."
        # Computer Security–ESORICS 2009: 14th European Symposium on Research in Computer Security, Saint-Malo, France, September 21-23, 2009.
        # generate spreading code: Walsh-Hadamard spreading code matrix with length of spreading_ratio
        # code_unit_size: must be power of 2
        # bit_unit_size: <= code_unit_size
        # return: bit_string
        # denormalize the codes
        min = -bit_unit_size
        self._codes = [[s + min for s in code] for code in self._codes]
        H = hadamard(code_unit_size)
        bit_string = ''
        for i in range(len(self._codes)):
            code = self._codes[i]
            for j in range(bit_unit_size):
                correlation = np.dot(code, H[j]) / code_unit_size
                bit_string += '1' if correlation > 0 else '0'
        self._bit_string = bit_string

    def decimal_codes_to_bits_geometric(self, code_unit_size: int, bit_unit_size: int, threshold_delta_sum: int):
        # Paper: Sellke, Sarah H., et al. "TCP/IP timing channels: Theory to implementation." IEEE INFOCOM 2009. IEEE, 2009.
        # bit_unit_size: L in the original paper
        # code_unit_size: n in the original paper
        # threshold_delta_sum: K in the original paper
        # Delta, delta, in second if we use ipd
        # Return: bit string
        def comb_generation(n: int, K: int):
            if n == 1:
                return [(i,) for i in range(K + 1)]
            else:
                res = list()
                for i in range(K + 1):
                    for subcomb in comb_generation(n - 1, K - i):
                        res.append((i,) + subcomb)
                return res
        bit_string = ''
        combs = comb_generation(code_unit_size, threshold_delta_sum)

        for i in range(len(self._codes)):
            code = self._codes[i]
            if len(code) != code_unit_size or sum(code) > threshold_delta_sum:
                print(f"Invalid code: {code}")
                continue
            # find the index of the code where combo[i] == code
            for j in range(2 ** bit_unit_size):
                if combs[j] == tuple(code):
                    bit_string += format(j, f"0{bit_unit_size}b")
                    break
        self._bit_string = bit_string

    def decimal_codes_to_bits_RS(self, code_unit_size: int, bit_unit_size: int, parity_size: int, c_exp: int = 8):
        # Paper: Houmansadr, Amir, and Nikita Borisov. "CoCo: coding-based covert timing channels for network flows." International Workshop on Information Hiding. Berlin, Heidelberg: Springer Berlin Heidelberg, 2011.
        # bit_unit_size: k in the original paper
        # code_unit_size: n in the original paper
        # parity_size: R-S code parity size
        # Return: R-S code in decimal format
        if bit_unit_size > 8:
            raise ValueError("R-S codec only supports bit_unit_size <= 8")
        bit_string = ''
        rs_codec = RSCodec(nsym = parity_size, c_exp = c_exp)
        for RS_code in self._codes:
            if len(RS_code) != code_unit_size:
                RS_code += [0] * (code_unit_size - len(RS_code))
            decoded_RS_code = list(rs_codec.decode(bytes(RS_code))[0])
            for i in range(code_unit_size - parity_size):
                bit_string += format(decoded_RS_code[i], f"0{bit_unit_size}b")
        self._bit_string = bit_string