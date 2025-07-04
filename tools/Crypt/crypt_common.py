import hmac
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hmac import HMAC



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
    Return the raw 20-byte SHA-1 digest of the RSA identity public key.
    Pass this value to NtorServerKeyAgreement(...).

    :param rsa_priv: server's long-term RSA *private* key object
    """
    der = rsa_priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha1(der).digest()
