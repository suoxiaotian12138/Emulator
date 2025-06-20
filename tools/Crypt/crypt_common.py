import hmac
from cryptography.hazmat.primitives import hashes
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.backends.openssl.backend import backend





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