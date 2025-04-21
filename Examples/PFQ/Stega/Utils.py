import bitarray


def str2bit(str):
    ba = bitarray.bitarray()
    ba.frombytes(str.encode('utf-8'))
    bit = ba.tolist()
    return bit


def bit2str(bit):
    bit = [bool(item) for item in bit]
    ba = bitarray.bitarray(bit)
    str = ba.tobytes().decode('utf-8', 'ignore')
    return str


# e.g. [0, 1, 1, 1] looks like 1110=14
def bits2int(bits):
    res = 0
    for i, bit in enumerate(bits):
        res += bit * (2 ** i)
    return res


def int2bits(inp, num_bits):
    if num_bits == 0:
        return []
    strlist = ('{0:0%db}' % num_bits).format(inp)
    return [int(strval) for strval in reversed(strlist)]


def num_same_from_beg(bits1, bits2):
    assert len(bits1) == len(bits2)
    for i in range(len(bits1)):
        if bits1[i] != bits2[i]:
            break

    return i


def is_sent_finish(token_idx, tokenizer):
    token = tokenizer.decode(token_idx)
    return '.' in token or '!' in token or '?' in token

def kl(q, logq, logp):
    res = q*(logq-logp)/0.69315
    res[q==0] = 0
    return res.sum().item() # in bits