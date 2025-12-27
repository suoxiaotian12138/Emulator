import hmac
import datetime

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID


bend = default_backend()

def b64decode(data):
    return base64.b64decode(data + '=' * (len(data) % 4))

def hmac_sha256(k: bytes, m: bytes) -> bytes:
    return hmac.new(k, m, hashlib.sha256).digest()

def hkdf_sha256(prk: bytes, length: int, info: bytes = b'') -> bytes:
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
        backend=backend            # 与 Torpy 完全一致
    ).derive(prk)

def sha1_stream(seed: bytes):
    h = hashlib.sha1()
    h.update(seed)
    return h                       # same object used as "stream"

def sha1_stream_clone(h):
    return h.copy()

def sha1_stream_update(h, data: bytes):
    h.update(data)

def sha1_stream_finalize(h):
    return h.digest()

# -- AES-CTR helpers ---------------------------------------------------------
def _aes_ctr_cipher(key: bytes, decrypt: bool):
    iv = b"\x00" * 16                       # Tor CTR IV starts with zeros
    cipher = Cipher(
        algorithms.AES(key),
        modes.CTR(iv),
        backend=default_backend(),
    )
    return cipher.decryptor() if decrypt else cipher.encryptor()

def aes_ctr_encryptor(key: bytes):
    return _aes_ctr_cipher(key, decrypt=False)

def aes_ctr_decryptor(key: bytes):
    return _aes_ctr_cipher(key, decrypt=True)

def aes_update(ctx, data: bytes) -> bytes:
    return ctx.update(data)

def to_hex(b: bytes, max_len: int = 32):
    head = b.hex()
    return head if len(head) <= max_len else head[:max_len] + "..."

def curve25519_get_shared(private, public):
    return private.exchange(public)


def curve25519_public_from_private(private):
    return private.public_key()


def curve25519_public_from_bytes(data):
    return X25519PublicKey.from_public_bytes(data)


def curve25519_to_bytes(key):
    if isinstance(key, X25519PublicKey):
        return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    else:
        return key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )

def hmac_msg(key, msg):
    hmac = HMAC(key, algorithm=hashes.SHA256(), backend=bend)
    hmac.update(msg)
    return hmac.finalize()


def rsa_identity_digest(rsa_priv: rsa.RSAPrivateKey) -> bytes:
    """
    按 Tor 规范计算 20B 身份摘要：对 RSA 身份公钥的 PKCS#1 DER 做 SHA1。
    返回原始 20 字节（供 NTor 使用）。
    """
    der_pkcs1 = rsa_priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1  # 关键：用 PKCS1，而不是 SubjectPublicKeyInfo
    )
    return hashlib.sha1(der_pkcs1).digest()



# ====================== cert_cell_helpers.py ======================
import time, struct, hashlib, base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

# Tor cert-spec constants
CERT_VERSION = 1
KEYTYPE_ED25519 = 1
KEYTYPE_RSA     = 2

# CERT TYPES (tor-spec.txt)
CT_RSA_ID_X509              = 2
CT_ED_ID_SIGNING            = 4
CT_ED_SIGNING_TLS           = 5
CT_ED_SIGNING_LINK_AUTH     = 6
CT_RSA_TO_ED_CROSS          = 7
CROSSCERT_PREFIX = b"Tor TLS RSA/Ed25519 cross-certificate"

def _ext_signed_with(pubkey_bytes: bytes) -> bytes:
    # LEN(2)=32, TYPE(1)=4, FLAGS(1)=0, DATA(32)=pubkey_raw
    return struct.pack(">HBB", 32, 4, 0) + pubkey_bytes

def build_ed25519_cert(cert_type: int,
                       issuer_sk: ed25519.Ed25519PrivateKey,
                       subject_key_bytes: bytes,
                       exp_hours: int,
                       issuer_pub_for_ext: bytes,
                       keytype: int) -> bytes:
    body  = struct.pack(">BBIB", CERT_VERSION, cert_type, exp_hours, keytype)
    body += subject_key_bytes
    body += struct.pack(">B", 1)          # N_EXTENSIONS = 1
    body += _ext_signed_with(issuer_pub_for_ext)
    sig   = issuer_sk.sign(body)
    return body + sig

def rsa_pubkey_spki_der(rsa_key: rsa.RSAPrivateKey) -> bytes:
    return rsa_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_pubkey_pkcs1_der(rsa_key: rsa.RSAPrivateKey) -> bytes:
    return rsa_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.PKCS1
    )

def rsa_id_x509_der(path_cert_pem: str) -> bytes:
    # 直接把自签的 X.509 证书读出来，转 DER
    from cryptography import x509
    with open(path_cert_pem, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return cert.public_bytes(serialization.Encoding.DER)

def hours_since_epoch(ts: int | None = None) -> int:
    """返回自 Unix 纪元起到 ts（或现在）的小时数。"""
    if ts is None:
        ts = int(time.time())
    return ts // 3600

import struct, hashlib

# 和 Tor C 里一样的前缀

def build_rsa_to_ed_crosscert(rsa_id_sk, ed_id_pub32: bytes, expiration_hours: int) -> bytes:
    assert len(ed_id_pub32) == 32

    # 1) ED key (32B) + expiration (4B big-endian hours since epoch)
    exp_bytes = struct.pack(">I", expiration_hours)

    # 2) 先计算 SHA256(prefix ∥ ed_key ∥ expiration)
    digest = hashlib.sha256(CROSSCERT_PREFIX + ed_id_pub32 + exp_bytes).digest()

    # 3) 用 PKCS#1 v1.5 对 digest 做“原始”签名
    signature = _rsa_pkcs1_v1_5_sign_raw(digest, rsa_id_sk)
    sig_len = len(signature)
    assert sig_len <= 255
    sig_len_byte = bytes([sig_len])

    # 4) 最终格式：ED_KEY (32B) ∥ EXP (4B) ∥ SIG_LEN (1B) ∥ SIGNATURE (sig_len B)
    return ed_id_pub32 + exp_bytes + sig_len_byte + signature


def rsa_identity_x509_der(rsa_id_sk: rsa.RSAPrivateKey) -> bytes:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Tor RSA Identity")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(rsa_id_sk.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(rsa_id_sk, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)
# ====================== END helpers ======================



def debug_build_crosscert(rsa_id_sk, ed32):
    # 1) EXP
    exp_hr = hours_since_epoch() + 365*24
    exp_be = struct.pack(">I", exp_hr)

    # 2) SIGLEN
    k = (rsa_id_sk.key_size + 7)//8
    siglen_b = struct.pack("B", k)

    # 3) to_sign
    to_sign = CROSSCERT_PREFIX + ed32 + exp_be + siglen_b
    print("---- DEBUG crosscert ----")
    print("PREFIX         :", CROSSCERT_PREFIX)
    print("ED25519_KEY    :", ed32.hex())
    print("EXPIRATION(H)  :", exp_hr)
    print("EXPIRATION(BE) :", exp_be.hex())
    print("SIGLEN         :", k)
    print("to_sign hex    :", to_sign.hex())
    print("sha256(to_sign):", hashlib.sha256(to_sign).hexdigest())
    print("-------------------------")

def _rsa_pkcs1_v1_5_sign_raw(digest20: bytes, privkey: rsa.RSAPrivateKey) -> bytes:
    """
    对 20 字节 SHA‑1 做原始 PKCS#1 v1.5 填充并指数运算。
    这里我们要改造为对 32 字节 SHA‑256 摘要做相同填充。
    """
    # 只要把 len(digest20)=32 改为 32 就行
    k = (privkey.key_size + 7)//8
    # EM = 0x00 || 0x01 || PS || 0x00 || digest
    ps = b'\xff' * (k - len(digest20) - 3)
    em = b'\x00\x01' + ps + b'\x00' + digest20
    num = int.from_bytes(em, 'big')
    sig_int = pow(num, privkey.private_numbers().d,
                  privkey.private_numbers().public_numbers.n)
    return sig_int.to_bytes(k, 'big')


