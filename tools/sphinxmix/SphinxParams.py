#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
#
# This file is part of Sphinx.
#
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.
#
# The LIONESS implementation and the xcounter CTR mode class are adapted
# from "Experimental implementation of the sphinx cryptographic mix
# packet format by George Danezis".


from os import urandom
from hashlib import sha256
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Python 2/3 compatibility
from builtins import bytes

zero_iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

#!/usr/bin/env python

# Copyright 2011 Ian Goldberg
# Copyright 2016 George Danezis (UCL InfoSec Group)
#
# This file is part of Sphinx.
#
# Sphinx is free software: you can redistribute it and/or modify
# it under the terms of version 3 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# Sphinx is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with Sphinx.  If not, see
# <http://www.gnu.org/licenses/>.
#
# The LIONESS implementation and the xcounter CTR mode class are adapted
# from "Experimental implementation of the sphinx cryptographic mix
# packet format by George Danezis".

from os import urandom
from hashlib import sha256
import hmac

# Replaced petlib with cryptography

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Python 2/3 compatibility
from builtins import bytes

zero_iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

class Group_ECC:
    """Group operations in ECC"""

    def __init__(self, gid=713):
        # 使用SECP256R1曲线作为默认
        self.G = ec.SECP256R1()
        # 生成私钥
        self.private_key = ec.generate_private_key(self.G, default_backend())
        # 公钥作为生成器
        self.g = self.private_key.public_key()

    def gensecret(self):
        """生成一个随机密钥"""
        return ec.generate_private_key(self.G, default_backend())

    def expon(self, base, exp):
        """使用私钥导出公钥"""
        # 确保基点是公钥类型
        if isinstance(base, ec.EllipticCurvePublicKey):
            pub_key = base
        else:
            raise TypeError("Base must be an EC public key")

        # 处理exp作为私钥或公钥的情况
        if isinstance(exp[0], ec.EllipticCurvePrivateKey):
            pub_key_exp = exp[0].public_key()
        elif isinstance(exp[0], ec.EllipticCurvePublicKey):
            pub_key_exp = exp[0]
        else:
            raise TypeError("Exponentiation base should be an EC public key or ECPrivateKey")

        # 将exp转换为整数
        exp_int = int.from_bytes(sha256(pub_key_exp.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)).digest(), "big")

        # 使用衍生的私钥
        derived_private_key = ec.derive_private_key(exp_int, self.G, default_backend())
        return derived_private_key.public_key()

    def expon_base(self, exp):
        """以基点进行指数运算"""
        if isinstance(exp[0], ec.EllipticCurvePrivateKey):
            pub_key_exp = exp[0].public_key()
        elif isinstance(exp[0], ec.EllipticCurvePublicKey):
            pub_key_exp = exp[0]
        else:
            raise TypeError("Exponentiation base should be an EC public key or ECPrivateKey")

        # 将exp转换为整数
        exp_int = int.from_bytes(sha256(pub_key_exp.public_bytes(
            encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)).digest(), "big")

        # 使用衍生的私钥
        derived_private_key = ec.derive_private_key(exp_int, self.G, default_backend())
        return derived_private_key.public_key()

    def makeexp(self, data):
        """将二进制数据转换为私钥"""
        digest = sha256(data).digest()
        int_val = int.from_bytes(digest, byteorder="big")  # 转换为整数
        return ec.derive_private_key(int_val, self.G, default_backend())

    def in_group(self, alpha):
        """检查一个点是否在ECC群中"""
        if isinstance(alpha, ec.EllipticCurvePublicKey):
            return True
        return False

    def printable(self, alpha):
        """将ECC点转换为字节"""
        if isinstance(alpha, ec.EllipticCurvePublicKey):
            return alpha.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
        else:
            raise TypeError("alpha必须是EC公钥")

 # Additional functions from the provided code
    def derive_key(self, k, flavor):
        """Derive the key from the given k and flavor."""
        assert len(k) == len(flavor) == self.k
        iv = flavor
        m = b"\x00" * self.k
        K = self.aes.enc(k, iv).update(m)
        return K

    def hb(self, k):
        "Compute a hash of alpha and s to use as a blinding factor"
        K = self.derive_key(k, b"hbhbhbhbhbhbhbhb")
        return self.group.makeexp(K)

    def hrho(self, k):
        "Compute a hash of s to use as a key for the PRG rho"
        K = self.derive_key(k, b"hrhohrhohrhohrho")
        return K

    def hmu(self, k):
        "Compute a hash of s to use as a key for the HMAC mu"
        K = self.derive_key(k, b"hmu:hmu:hmu:hmu:")
        return K

    def hpi(self, k):
        "Compute a hash of s to use as a key for the PRP pi"
        K = self.derive_key(k, b"hpi:hpi:hpi:hpi:")
        return K

    def htau(self, k):
        "Compute a hash of s to use to see if we've seen s before"
        K = self.derive_key(k, b"htauhtauhtauhtau")
        return K

    def h_body_K(self, k):
        "The Ultrix key to protect the user data."
        K = self.derive_key(k, b"UbodUbodUbodUbod")
        return K

    def h_root_K(self, k):
        "The Ultrix key to protect the root key."
        K = self.derive_key(k, b"UrooUrooUrooUroo")
        return K

    def derive_user_keys(self, k, iv, number=2):
        """Derive multiple keys."""
        material = self.aes.enc(k, iv).update(b"\x00" * self.k * number)
        st_ranges = range(0, self.k * number, self.k)

        return [material[st:st + self.k] for st in st_ranges]

class SphinxParams:

    def __init__(self, group=None, header_len = 192, body_len = 1024, assoc_len=0, k=16, dest_len=16):
        # Replaced petlib AES cipher with cryptography's Cipher
        self.aes = Cipher(algorithms.AES(bytes(k)), modes.CTR(zero_iv), backend=default_backend())
        self.cbc = Cipher(algorithms.AES(bytes(k)), modes.CBC(zero_iv), backend=default_backend())

        self.assoc_len = assoc_len
        self.max_len = header_len

        self.zero_pad = b"\x00" * (2 * self.max_len)

        self.m = body_len
        self.k = k
        self.dest_len = dest_len

        self.group = group
        if not group:
            self.group = Group_ECC()

    def aes_ctr(self, k, m, iv = zero_iv):
        # AES-CTR encryption
        encryptor = self.aes.encryptor()
        c = encryptor.update(m)
        return bytes(c)

    def aes_cbc_enc(self, k, m, iv = zero_iv):
        # AES-CBC encryption
        cipher = self.cbc.encryptor()
        cipher.set_padding(False)
        c = cipher.update(m)
        return bytes(c)

    def aes_cbc_dec(self, k, m, iv = zero_iv):
        # AES-CBC decryption
        cipher = self.cbc.decryptor()
        cipher.set_padding(False)
        c = cipher.update(m)
        return bytes(c)

    def lioness_enc(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2

        # Round 1
        k1 = self.hash(message[self.k:]+key+b'1')[:self.k]
        c = self.aes_ctr(key, message[:self.k], iv = k1)
        r1 = c + message[self.k:]

        # Round 2
        c = self.aes_ctr(key, r1[self.k:], iv = r1[:self.k])
        r2 = r1[:self.k] + c

        # Round 3
        k3 = self.hash(r2[self.k:]+key+b'3')[:self.k]
        c = self.aes_ctr(key, r2[:self.k], iv = k3)
        r3 = c + r2[self.k:]

        # Round 4
        c = self.aes_ctr(key, r3[self.k:], r3[:self.k])
        r4 = r3[:self.k] + c

        return r4

    def lioness_dec(self, key, message):
        assert len(key) == self.k
        assert len(message) >= self.k * 2

        r4 = message
        r4_short, r4_long = r4[:self.k], r4[self.k:]

        # Round 4
        r3_long = self.aes_ctr(key, r4_long, iv = r4_short)
        r3_short = r4_short

        # Round 3
        k2 = self.hash(r3_long+key+b'3')[:self.k]
        r2_short = self.aes_ctr(key, r3_short, iv = k2)
        r2_long = r3_long

        # Round 2
        r1_long = self.aes_ctr(key, r2_long, iv = r2_short)
        r1_short = r2_short

        # Round 1
        k0 = self.hash(r1_long+key+b'1')[:self.k]
        c = self.aes_ctr(key, r1_short, iv = k0)
        r0 = c + r1_long

        return r0

    # AES-CTR operation
    def xor_rho(self, key, plain):
        assert len(key) == self.k
        return self.aes_ctr(key, plain)

    # The HMAC; key is of length k, output is of length k
    def mu(self, key, data):
        mac = hmac.new(key, data, digestmod=sha256).digest()[:self.k]
        return mac

    # The PRP; key is of length k, data is of length m
    def pi(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m

        return self.lioness_enc(key, data)

    # The inverse PRP; key is of length k, data is of length m
    def pii(self, key, data):
        assert len(key) == self.k
        assert len(data) == self.m

        return self.lioness_dec(key, data)

    def small_perm(self, key, data):
        assert len(data) == self.k
        enc = self.cbc.encryptor()
        enc.set_padding(False)
        c = enc.update(data)
        return c

    def small_perm_inv(self, key, data):
        assert len(data) == self.k
        dec = self.cbc.decryptor()
        dec.set_padding(False)
        c = dec.update(data)
        return c

    # The various hashes
    def hash(self, data):
        return sha256(data).digest()

    def get_aes_key(self, s):
        group = self.group
        return bytes(self.hash(b"aes_key:" + group.printable(s))[:self.k])

    def get_aes_key_all(self, s):
        group = self.group
        k = self.hash

 # Additional functions from the provided code
    def derive_key(self, k, flavor):
        """Derive the key from the given k and flavor."""
        assert len(k) == len(flavor) == self.k
        iv = flavor
        m = b"\x00" * self.k
        encryptor = self.aes.encryptor()
        K = encryptor.update(m)
        return K

    def hb(self, k):
        "Compute a hash of alpha and s to use as a blinding factor"
        K = self.derive_key(k, b"hbhbhbhbhbhbhbhb")
        return self.group.makeexp(K)

    def hrho(self, k):
        "Compute a hash of s to use as a key for the PRG rho"
        K = self.derive_key(k, b"hrhohrhohrhohrho")
        return K

    def hmu(self, k):
        "Compute a hash of s to use as a key for the HMAC mu"
        K = self.derive_key(k, b"hmu:hmu:hmu:hmu:")
        return K

    def hpi(self, k):
        "Compute a hash of s to use as a key for the PRP pi"
        K = self.derive_key(k, b"hpi:hpi:hpi:hpi:")
        return K

    def htau(self, k):
        "Compute a hash of s to use to see if we've seen s before"
        K = self.derive_key(k, b"htauhtauhtauhtau")
        return K

    def h_body_K(self, k):
        "The Ultrix key to protect the user data."
        K = self.derive_key(k, b"UbodUbodUbodUbod")
        return K

    def h_root_K(self, k):
        "The Ultrix key to protect the root key."
        K = self.derive_key(k, b"UrooUrooUrooUroo")
        return K

    def derive_user_keys(self, k, iv, number=2):
        """Derive multiple keys."""
        material = self.aes.enc(k, iv).update(b"\x00" * self.k * number)
        st_ranges = range(0, self.k * number, self.k)

        return [material[st:st + self.k] for st in st_ranges]

def test_group():
    G = Group_ECC()
    sec1 = G.gensecret()
    sec2 = G.gensecret()
    gen = G.g

    assert G.expon(G.expon(gen, [ sec1 ]), [ sec2 ]) == G.expon(G.expon(gen, [ sec2 ]), [ sec1 ])
    assert G.in_group(G.expon(gen, [ sec1 ]))

def test_params():
    # Test Init
    params = SphinxParams()

    # Test Lioness
    k = b"A" * 16
    m = b"ARG"* 16

    c = params.lioness_enc(k,m)
    m2 = params.lioness_dec(k, c)
    assert m == m2

    # Test CTR
    k = urandom(16)
    c = params.aes_ctr(k, b"Hello World!")
    assert params.aes_ctr(k, c) == b"Hello World!"

    c = params.small_perm(b"\x00"*16, b"\x00"*16)
    c2 = params.small_perm_inv(b"\x00"*16, c)
    assert c2 == b"\x00"*16

    plain = b"Bob"
    k = urandom(16)
    c = params.aes_ctr(k, plain)
    p = params.aes_ctr(k, c)
    assert p == b"Bob"

    plain = b"ACB" * 16
    k = urandom(16)
    iv = urandom(16)
    ctxt = params.aes_cbc_enc(k, plain)
    assert len(ctxt) == len(plain)
    ptxt = params.aes_cbc_dec(k, ctxt)
    assert ptxt == plain
