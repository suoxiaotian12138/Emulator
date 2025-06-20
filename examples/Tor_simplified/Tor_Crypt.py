from typing import Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from torpy.cells import RelayedTorCell
import struct
import hashlib, logging

from tools.Crypt.crypt_common import (
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
)

logger = logging.getLogger(__name__)


KEY_MAT_LEN = 72
HASH_LEN = 20
KEY_LEN = 16
DIGEST_LEN = 4


class NtorServerKeyAgreement:
    PROTOID  = b"ntor-curve25519-sha256-1"
    T_MAC    = PROTOID + b":mac"
    T_KEY    = PROTOID + b":key_extract"
    T_VERIFY = PROTOID + b":verify"
    M_EXPAND = PROTOID + b":key_expand"

    def __init__(self, identity_digest,
                 ntor_priv: x25519.X25519PrivateKey) -> None:
        if len(identity_digest) != 20:
            raise ValueError("identity_digest must be 20 bytes")
        self.ID = identity_digest
        self.b_priv = ntor_priv
        self.B = ntor_priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        self.KEYID_B = hashlib.sha256(self.B).digest()

    # ----------------------------------------------------------
    def handle_create2(self, cell_payload: bytes) -> Tuple[bytes, bytes]:
        """
        参数: CellCreate2 的 payload (包含 HTYPE/HLEN)
        返回:
            created2_payload  —— 可直接填入 CellCreated2
            key_material      —— 72 B 对称密钥材料
        """
        # -- 1. 解析 CREATE2 包 --
        htype, hlen = struct.unpack_from("!HH", cell_payload, 0)
        if htype != 2:
            raise ValueError("Only NTor (htype 2) supported")
        if hlen != 84 or len(cell_payload) != 4 + hlen:
            print("hlen:", hlen)
            raise ValueError("Invalid NTor handshake length")

        hdata = memoryview(cell_payload)[4:]           # 84 B
        nodeid   = bytes(hdata[:20])
        keyid_B  = bytes(hdata[20:52])
        X_bytes  = bytes(hdata[52:])

        if keyid_B == self.B:
            # 客户端发来了 B 本身 → 把它哈希成 KEYID 再继续
            keyid_B = hashlib.sha256(keyid_B).digest()
        elif keyid_B != self.KEYID_B:
            raise ValueError("KEYID(B) mismatch; wrong onion key")

        # （NODEID 用于日志/识别，不影响密钥派生）

        X_pub = x25519.X25519PublicKey.from_public_bytes(X_bytes)

        # -- 2. 生成服务器临时密钥 Y --
        y_priv = x25519.X25519PrivateKey.generate()
        Y_bytes = y_priv.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)

        # -- 3. 共同秘密 + KEY_SEED --
        g_xy = y_priv.exchange(X_pub)     # EXP(X , y)
        g_xb = self.b_priv.exchange(X_pub)  # EXP(X , b)

        secret_input = (
            g_xy + g_xb +
            self.ID + self.B + X_bytes + Y_bytes + self.PROTOID
        )
        key_seed = hmac_sha256(self.T_KEY, secret_input)
        verify   = hmac_sha256(self.T_VERIFY, secret_input)
        key_material = hkdf_sha256(key_seed, length=KEY_MAT_LEN, info=self.M_EXPAND)

        # -- 4. 生成 AUTH / CREATED2 --
        auth_input = (
            verify + self.ID + self.B + Y_bytes + X_bytes +
            self.PROTOID + b"Server"
        )
        auth = hmac_sha256(self.T_MAC, auth_input)     # 32 B
        created2_hdata = Y_bytes + auth                # 64 B

        created2_payload = struct.pack("!H", len(created2_hdata)) + created2_hdata
        return created2_hdata, key_material


class RelayCryptoState:
    """
    Server-side circuit crypto after NTor.

    Layout of key_material (Tor spec §5.1.4):
        0-19  : Df (client forward digest)   ->  server *backward* digest
        20-39 : Db (client backward digest)  ->  server *forward*  digest
        40-55 : Kf (client forward key)      ->  server *backward* key
        56-71 : Kb (client backward key)     ->  server *forward*  key
    """

    def __init__(self, key_material: bytes):
        if len(key_material) != (2 * HASH_LEN + 2 * KEY_LEN):
            raise ValueError("key_material must be exactly 72 bytes")
        k72 = key_material[:72]
        (df, db, kf, kb) = struct.unpack("!20s20s16s16s", k72)

        # ---------- orientation swap ----------
        self._forward_digest  = sha1_stream(db)   # server → client
        self._backward_digest = sha1_stream(df)   # client → server

        self._forward_cipher  = aes_ctr_encryptor(kb)
        self._backward_cipher = aes_ctr_decryptor(kf)

    # -------- internal helpers (同客户端实现) --------
    def _digesting_func(self, payload):
        self._forward_digest.update(payload)
        d = self._forward_digest.copy()
        return d.digest()[:DIGEST_LEN]

    def _encrypting_func(self, payload):
        return aes_update(self._forward_cipher, payload)

    def _digest_check_func(self, payload, digest):
        dig_clone = sha1_stream_clone(self._backward_digest)
        sha1_stream_update(dig_clone, payload)
        new_d = sha1_stream_finalize(dig_clone)[:DIGEST_LEN]
        if new_d != digest:
            logger.debug(
                "cell digest mismatch (%s != %s); payload=%s",
                to_hex(new_d), to_hex(digest), to_hex(payload)
            )
            return False
        sha1_stream_update(self._backward_digest, payload)
        return True

    def _decrypting_func(self, payload):
        return aes_update(self._backward_cipher, payload)

    # -------- public API --------
    def encrypt_forward(self, relay_cell):
        # server → client
        if not relay_cell.digest:
            relay_cell.prepare(self._digesting_func)
        relay_cell.encrypt(self._encrypting_func)

    def decrypt_backward(self, relay_cell):
        # client → server
        encrypted = relay_cell.get_encrypted()
        payload = self._decrypting_func(encrypted)

        header = RelayedTorCell.parse_header(payload)
        print("header:", header)
        if header["is_recognized"] == 0:
            tmp = RelayedTorCell.set_header_digest(payload, b"\0" * DIGEST_LEN)
            if self._digest_check_func(tmp, header["digest"]):
                relay_cell.set_decrypted(**header)
                return

        # still encrypted
        relay_cell.set_encrypted(payload)


