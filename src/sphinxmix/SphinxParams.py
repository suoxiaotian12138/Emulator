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
from tools.Crypt.serialization import decode

# Python 2/3 compatibility
from builtins import bytes

zero_iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from hashlib import sha256

class Group_ECC:
    """Group operations in ECC"""

    def __init__(self, gid=713):
        self.G = ec.SECP256R1()
        self.backend = default_backend()
        self.k = 16

        # 不再使用随机私钥的公钥作为生成器！
        # self.private_key = ec.generate_private_key(self.G, self.backend)
        # self.g = self.private_key.public_key()  # ❌错误

        # ✅ 使用曲线的固定生成元表示（不可直接取 G 点，但我们用 keygen 一致生成）
        self.g = self.make_generator_point()  # 用于“代表性输出”，但建议不参与实际运算

    def make_generator_point(self):
        """生成一个确定性的公钥作为 g 的代表值，仅用于打印"""
        test_sk = ec.derive_private_key(1, self.G, self.backend)
        return test_sk.public_key()

    def gensecret(self):
        """生成一个随机私钥对象"""
        return ec.generate_private_key(self.G, self.backend)

    def keygen(self):
        """返回 (私钥, 公钥)，供发送方/接收方安全使用"""
        priv = self.gensecret()
        pub = priv.public_key()
        return priv, pub

    def expon(self, base, exp):
        """
        Perform ECDH(base, exp) where:
        - base: ec.EllipticCurvePublicKey
        - exp[0]: ec.EllipticCurvePrivateKey
        """
        if not isinstance(base, ec.EllipticCurvePublicKey):
            raise TypeError("Base must be an EC public key")

        if not isinstance(exp[0], ec.EllipticCurvePrivateKey):
            raise TypeError("Exponent must be an EC private key")

        # True ECDH shared secret
        shared = exp[0].exchange(ec.ECDH(), base)
        return shared  # This is a byte string

    def expon_base(self, exp):
        """Get public key of a blinded secret (exp must be private key)"""
        if isinstance(exp[0], ec.EllipticCurvePrivateKey):
            return exp[0].public_key()
        else:
            raise TypeError("Expon_base must receive a private key")

    def makeexp(self, data):
        """将原始字节映射为 ECC 私钥"""
        digest = sha256(data).digest()
        int_val = int.from_bytes(digest, byteorder="big")
        return ec.derive_private_key(int_val, self.G, self.backend)

    def in_group(self, alpha):
        if not isinstance(alpha, ec.EllipticCurvePublicKey):
            return False
        try:
            # 检查是否属于正确曲线
            if not isinstance(alpha.curve, ec.SECP256R1):
                return False
            alpha.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            return True
        except Exception:
            return False

    def pubkey_from_bytes(self, data: bytes):
        """将字节转换为公钥对象"""
        return ec.EllipticCurvePublicKey.from_encoded_point(self.G, data)

    def printable(self, alpha):
        """将公钥转换为字节表示（Uncompressed Point）"""
        if not self.in_group(alpha):
            raise TypeError("alpha 必须是 EC 公钥")
        return alpha.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )



    # ========= 派生密钥函数（保留原样） =========
    def derive_key(self, k, flavor):
        assert len(k) == len(flavor) == self.k
        cipher = Cipher(algorithms.AES(k), modes.CTR(flavor), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(b"\x00" * self.k)

    def hb(self, k): return self.makeexp(self.derive_key(k, b"hbhbhbhbhbhbhbhb"))
    def hrho(self, k): return self.derive_key(k, b"hrhohrhohrhohrho")
    def hmu(self, k): return self.derive_key(k, b"hmu:hmu:hmu:hmu:")
    def hpi(self, k): return self.derive_key(k, b"hpi:hpi:hpi:hpi:")
    def htau(self, k): return self.derive_key(k, b"htauhtauhtauhtau")
    def h_body_K(self, k): return self.derive_key(k, b"UbodUbodUbodUbod")
    def h_root_K(self, k): return self.derive_key(k, b"UrooUrooUrooUroo")

    def derive_user_keys(self, k, iv, number=2):
        cipher = Cipher(algorithms.AES(k), modes.CTR(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        material = encryptor.update(b"\x00" * (self.k * number))
        return [material[i:i + self.k] for i in range(0, len(material), self.k)]


class SphinxParams:

    def __init__(self, group=None, header_len=192, body_len=1024, assoc_len=0, k=16, dest_len=16):
        # Replaced petlib AES cipher with cryptography's Cipher

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
        cipher = Cipher(algorithms.AES(k), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(m) + encryptor.finalize()

    def aes_cbc_enc(self, k, m, iv = zero_iv):
        # AES-CBC encryption
        cbc = Cipher(algorithms.AES(bytes(k)), modes.CBC(iv), backend=default_backend())
        cipher = cbc.encryptor()
        cipher.set_padding(False)
        c = cipher.update(m)
        return bytes(c)

    def aes_cbc_dec(self, k, m, iv = zero_iv):
        # AES-CBC decryption
        cbc = Cipher(algorithms.AES(bytes(k)), modes.CBC(iv), backend=default_backend())
        cipher = cbc.decryptor()
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
        assert r4 != message, "[ERROR] Encryption failed: output equals input!"

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
        cipher = Cipher(algorithms.AES(key), modes.CBC(zero_iv), backend=default_backend())
        enc = cipher.encryptor()
        return enc.update(data)

    def small_perm_inv(self, key, data):
        assert len(data) == self.k
        cipher = Cipher(algorithms.AES(key), modes.CBC(zero_iv), backend=default_backend())
        dec = cipher.decryptor()
        return dec.update(data)

    # The various hashes
    def hash(self, data):
        return sha256(data).digest()

    def get_aes_key(self, s):
        if isinstance(s, bytes):
            material = s
        elif self.group.in_group(s):  # EC 公钥
            material = self.group.printable(s)
        else:
            raise TypeError("Unsupported key type passed to get_aes_key.")

        return bytes(self.hash(b"aes_key:" + material)[:self.k])


 # Additional functions from the provided code
    def derive_key(self, k, flavor):
        assert len(k) == len(flavor) == self.k
        cipher = Cipher(algorithms.AES(k), modes.CTR(flavor), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(b"\x00" * self.k)

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
        cipher = Cipher(algorithms.AES(k), modes.CTR(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        material = encryptor.update(b"\x00" * (self.k * number))
        return [material[i:i + self.k] for i in range(0, len(material), self.k)]


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

def test_lioness_roundtrip():
    from os import urandom
    params = SphinxParams()
    key = urandom(params.k)
    msg = urandom(params.k * 2)

    cipher = params.lioness_enc(key, msg)
    plain = params.lioness_dec(key, cipher)

    assert cipher != msg, "加密未生效：cipher 等于明文！"
    assert plain == msg, "解密失败：无法还原明文！"


