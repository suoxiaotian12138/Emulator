from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from examples.Tor_simplified.Tor_Cell import RelayedTorCell
import struct
import hashlib, logging
import threading
from tools.Crypt.key_generator import curve25519_setup
from tools.Crypt.crypt_common import (
    hmac_msg,
    hmac_sha256,
    hkdf_sha256,
    sha1_stream,
    sha1_stream_clone,
    sha1_stream_update,
    sha1_stream_finalize,
    aes_ctr_encryptor,
    aes_ctr_decryptor,
    aes_update,
    to_hex,
    curve25519_public_from_bytes,
    curve25519_to_bytes,
    curve25519_get_shared,
)

logger = logging.getLogger(__name__)


KEY_MAT_LEN = 72
HASH_LEN = 20
KEY_LEN = 16
DIGEST_LEN = 4
KEY_MATERIAL_LENGTH = 20 * 2 + 16 * 2


class cached_property:
    def __init__(self, func):
        self.__doc__ = func.__doc__
        self.func = func
        self.lock = threading.RLock()

    def __get__(self, obj, cls):
        if obj is None:
            return self
        with self.lock:
            value = obj.__dict__[self.func.__name__] = self.func(obj)
            return value


class NtorKeyAgreement:
    TYPE = 2

    def __init__(self, onion_router):
        self.protoid = b'ntor-curve25519-sha256-1'
        self.t_mac = self.protoid + b':mac'
        self.t_key = self.protoid + b':key_extract'
        self.t_verify = self.protoid + b':verify'
        self.m_expand = self.protoid + b':key_expand'
        self._x, self._X = curve25519_setup()
        self._onion_router = onion_router

    @property
    def _fingerprint_bytes(self):
        return self._onion_router.fingerprint

    @cached_property
    def _B(self):
        return curve25519_public_from_bytes(self._onion_router.descriptor.ntor_key)

    @cached_property
    def handshake(self):
        return self._fingerprint_bytes + curve25519_to_bytes(self._B) + curve25519_to_bytes(self._X)

    def complete_handshake(self, handshake_response):
        y = handshake_response[:32]
        auth = handshake_response[32:]
        if len(auth) != 32:
            raise ValueError("Invalid auth length")

        # # ---------- DEBUG BEGIN ----------
        # def H(label, data):
        #     print(f"[NTOR-CLI] {label} ({len(data)}B) = {data.hex()}")
        #
        # H("ID", self._fingerprint_bytes)
        # H("B", curve25519_to_bytes(self._B))
        # H("X", curve25519_to_bytes(self._X))
        # H("Y(from srv)", y)
        # H("AUTH(from srv)", auth)
        # # ---------- DEBUG END ------------

        si = curve25519_get_shared(self._x, curve25519_public_from_bytes(y))
        si += curve25519_get_shared(self._x, self._B)
        si += self._fingerprint_bytes
        si += curve25519_to_bytes(self._B)
        si += curve25519_to_bytes(self._X)
        si += y
        si += self.protoid

        key_seed = hmac_msg(self.t_key, si)
        verify = hmac_msg(self.t_verify, si)

        ai = verify
        ai += self._fingerprint_bytes
        ai += curve25519_to_bytes(self._B)
        ai += y
        ai += curve25519_to_bytes(self._X)
        ai += self.protoid
        ai += b'Server'

        # # ---------- DEBUG BEGIN ----------
        # expect_auth = hmac_msg(self.t_mac, ai)
        #
        # H("g^xy", si[:32])
        # H("g^xb", si[32:64])
        # H("secret_input(HMAC key_extract)", si)
        # H("key_seed", key_seed)
        # H("verify", verify)
        # H("auth_input(mac)", ai)
        # H("AUTH(expect)", expect_auth)
        # if auth != expect_auth:
        #     print("[NTOR-CLI] MISMATCH!")
        # # ---------- DEBUG END ------------

        if auth != hmac_msg(self.t_mac, ai):
            print("DEBUG  verify mismatch:",
                  auth.hex()[:16], hmac_msg(self.t_mac, ai).hex()[:16])
            raise ValueError("Auth input does not match")

        return hkdf_sha256(key_seed, length=KEY_MAT_LEN, info=self.m_expand)


class NtorServerKeyAgreement:
    PROTOID = b"ntor-curve25519-sha256-1"
    T_MAC = PROTOID + b":mac"
    T_KEY = PROTOID + b":key_extract"
    T_VERIFY = PROTOID + b":verify"
    M_EXPAND = PROTOID + b":key_expand"

    def __init__(self, identity_digest, ntor_priv: x25519.X25519PrivateKey):
        if len(identity_digest) != 20:
            raise ValueError("identity_digest must be 20 bytes")
        self.ID = identity_digest
        self.b_priv = ntor_priv
        self.B = ntor_priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        self.KEYID_B = hashlib.sha256(self.B).digest()

    def handle_create2(self, cell_payload: bytes) -> Tuple[bytes, bytes]:
        htype, hlen = struct.unpack_from("!HH", cell_payload, 0)
        if htype == 2:
            if hlen < 84 or len(cell_payload) < 4 + hlen:
                raise ValueError(f"Invalid NTor handshake length: hlen={hlen}, total={len(cell_payload)}")

            hdata = memoryview(cell_payload)[4:]
            nodeid = bytes(hdata[:20])
            keyid_B = bytes(hdata[20:52])
            X_bytes = bytes(hdata[52:84])

            # # ---------- DEBUG BEGIN ----------
            # def H(label, data):
            #     print(f"[NTOR-SRV] {label} ({len(data)}B) = {data.hex()}")
            #
            # H("ID(from cli)", nodeid)
            # H("KEYID_B(from cli)", keyid_B)
            # H("B(self)", self.B)
            # H("KEYID_B(self)", self.KEYID_B)
            # H("X(from cli)", X_bytes)
            # # ---------- DEBUG END ------------

            if keyid_B == self.B:
                keyid_B = hashlib.sha256(keyid_B).digest()
            elif keyid_B == hashlib.sha256(self.B).digest():
                pass
            elif keyid_B != self.KEYID_B:
                raise ValueError("KEYID(B) mismatch; wrong onion key")

            X_pub = x25519.X25519PublicKey.from_public_bytes(X_bytes)

            y_priv = x25519.X25519PrivateKey.generate()
            Y_bytes = y_priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )

            g_xy = y_priv.exchange(X_pub)
            g_xb = self.b_priv.exchange(X_pub)

            secret_input = (
                g_xy + g_xb +
                self.ID + self.B + X_bytes + Y_bytes + self.PROTOID
            )
            key_seed = hmac_sha256(self.T_KEY, secret_input)
            verify = hmac_sha256(self.T_VERIFY, secret_input)
            key_material = hkdf_sha256(key_seed, length=KEY_MAT_LEN, info=self.M_EXPAND)

            auth_input = (
                verify + self.ID + self.B + Y_bytes + X_bytes +
                self.PROTOID + b"Server"
            )
            auth = hmac_sha256(self.T_MAC, auth_input)
            created2_hdata = Y_bytes + auth

            return created2_hdata, key_material

        elif htype == 3:

            if hlen < 32 + 32 + 32 + 32:
                raise ValueError("Invalid ntor-v3 handshake length")
            hdata = memoryview(cell_payload)[4:4 + hlen]
            if len(hdata) < 32 + 32 + 32 + 32:
                raise ValueError("ntor-v3 payload too short")
            node_id = bytes(hdata[:32])
            key_id = bytes(hdata[32:64])
            X_bytes = bytes(hdata[64:96])
            # MSG and MAC
            if len(hdata) < 96 + 32:
                raise ValueError("ntor-v3 payload missing MAC")
            msg = bytes(hdata[96:-32]) if len(hdata) > 128 else b""
            mac = bytes(hdata[-32:])
            # 验证 node_id 和 key_id（可选）
            # if node_id != self.ID:
            #     raise ValueError("NODEID mismatch")
            if key_id not in [self.B, self.KEYID_B, hashlib.sha256(self.B).digest()]:
                raise ValueError("KEYID mismatch")
            # 生成服务端 Y 公钥
            y_priv = x25519.X25519PrivateKey.generate()
            Y_bytes = y_priv.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw
            )
            X_pub = x25519.X25519PublicKey.from_public_bytes(X_bytes)
            g_xy = y_priv.exchange(X_pub)
            g_xb = self.b_priv.exchange(X_pub)
            secret_input = (
                g_xy + g_xb + self.ID + self.B + X_bytes + Y_bytes + self.PROTOID
            )
            key_seed = hmac_sha256(self.T_KEY, secret_input)
            verify = hmac_sha256(self.T_VERIFY, secret_input)
            key_material = hkdf_sha256(key_seed, length=KEY_MAT_LEN, info=self.M_EXPAND)
            auth_input = (
                verify + self.ID + self.B + Y_bytes + X_bytes + self.PROTOID + b"Server"
            )
            auth = hmac_sha256(self.T_MAC, auth_input)
            server_msg = b""  # optional extra server message, can be blank
            created2_payload = Y_bytes + auth + server_msg
            return created2_payload, key_material
        else:
            raise ValueError(f"Unsupported CREATE2 handshake_type: {htype}")

class _BaseCryptoState:
    def __init__(self):
        self._forward_digest = None
        self._backward_digest = None
        self._forward_cipher = None
        self._backward_cipher = None

    def _digesting_func(self, payload):
        self._forward_digest.update(payload)
        clone = sha1_stream_clone(self._forward_digest)
        return sha1_stream_finalize(clone)[:DIGEST_LEN]

    def _encrypting_func(self, payload):
        return aes_update(self._forward_cipher, payload)

    def _decrypting_func(self, payload):
        return aes_update(self._backward_cipher, payload)

    def _digest_check_func(self, payload, digest):
        clone = sha1_stream_clone(self._backward_digest)
        sha1_stream_update(clone, payload)
        expected = sha1_stream_finalize(clone)[:DIGEST_LEN]

        if expected != digest:
            logger.debug("cell digest mismatch (%s != %s); payload=%s",
                         to_hex(expected), to_hex(digest), to_hex(payload))
            return False

        sha1_stream_update(self._backward_digest, payload)
        return True

    def encrypt_forward(self, relay_cell):
        """
        IMPORTANT:
        - If relay_cell is already encrypted (inner_cell=None, has _encrypted),
          we must NOT call prepare() or touch digest.
          We only add one AES layer on the existing encrypted payload.
        - If relay_cell is plaintext (inner_cell exists), we prepare digest once,
          then encrypt.
        """
        if relay_cell.is_encrypted:
            # add a layer on existing ciphertext, do NOT recompute digest
            payload = relay_cell._serialize_payload()  # returns current ciphertext
            relay_cell.set_encrypted(self._encrypting_func(payload))
            return

        # plaintext relay cell
        if not relay_cell.digest:
            relay_cell.prepare(self._digesting_func)
        relay_cell.encrypt(self._encrypting_func)

    def decrypt_backward(self, relay_cell):
        encrypted = relay_cell.get_encrypted()
        payload = self._decrypting_func(encrypted)
        header = RelayedTorCell.parse_header(payload)

        if header["is_recognized"] == 0:
            payload_for_check = RelayedTorCell.set_header_digest(payload, b'\0' * DIGEST_LEN)
            if self._digest_check_func(payload_for_check, header["digest"]):
                relay_cell.set_decrypted(**header)
                return

        relay_cell.set_encrypted(payload)


class CryptoState(_BaseCryptoState):
    def __init__(self, data):
        super().__init__()
        df, db, kf, kb = struct.unpack("!20s20s16s16s", data)
        self._forward_digest = sha1_stream(df)
        self._backward_digest = sha1_stream(db)
        self._forward_cipher = aes_ctr_encryptor(kf)
        self._backward_cipher = aes_ctr_decryptor(kb)


class ServerCryptoState(_BaseCryptoState):
    def __init__(self, key_material: bytes):
        super().__init__()
        if len(key_material) != 2 * HASH_LEN + 2 * KEY_LEN:
            raise ValueError("key_material must be exactly 72 bytes")

        df, db, kf, kb = struct.unpack("!20s20s16s16s", key_material)

        self._forward_digest = sha1_stream(db)   # server → client
        self._backward_digest = sha1_stream(df)  # client → server
        self._forward_cipher = aes_ctr_encryptor(kb)
        self._backward_cipher = aes_ctr_decryptor(kf)

