from torpy.crypto_common import b64decode
from torpy.parsers import RouterDescriptorParser
from torpy.stream import TorWindow
from examples.Tor_simplified.Tor_Cell import *
from examples.Tor_simplified.Tor_Crypt import ServerCryptoState, CryptoState
from examples.Tor_simplified.Tor_Crypt import NtorKeyAgreement
import base64
import re

logger = logging.getLogger(__name__)



class Tor_Router:
    """
    客户侧在电路中标记某一个节点的信息，不是真正的节点，用于客户端与节点的握手和加解密过程
    """
    def __init__(self, router: dict):
        self.nickname = router['nickname']

        fingerprint = router['fingerprint']
        self.fingerprint_str = fingerprint
        if type(fingerprint) is not bytes:
            fingerprint = b64decode(fingerprint)
        self.fingerprint = fingerprint
        self._digest_b64 = router.get('digest')

        # 仍然生成 hex 摘要供现有代码使用
        self.digest = b64_desc_to_hex(router['digest']) if router.get('digest') else None

        self.ip = router['ip']
        self.or_port = router['or_port']
        self.addr = (self.ip, self.or_port)
        self.dir_port = router['dir_port']
        self.version = router['version']
        self.flags = router['flags']

        self.window = TorWindow()
        self._consensus = None
        self._service_key = None

        self.key_agreement_cls = NtorKeyAgreement(self)
        self._crypto_state = None
        self.descriptor_str = None

    def create_onion_skin(self):
        return self.key_agreement_cls.handshake

    def complete_handshake(self, handshake_response):
        shared_secret = self.key_agreement_cls.complete_handshake(handshake_response)
        self._crypto_state = CryptoState(shared_secret)

    def encrypt_forward(self, relay_cell):
        self._crypto_state.encrypt_forward(relay_cell)

    def decrypt_backward(self, relay_cell):
        self._crypto_state.decrypt_backward(relay_cell)

    @property
    def descriptor(self):
        descriptor_info = self.parse(self.descriptor_str)
        return Descriptor(**descriptor_info)

    def set_descriptor(self, descriptor_str):
        self.descriptor_str = descriptor_str

    def spawn_circuit_hop(self) -> "Tor_Router":
        """
        基于本节点的静态元信息（IP、端口、指纹、flags、descriptor 等），
        生成一个“用于单条电路的”全新 Router 实例：
          - 复制 *元数据*
          - 继承 descriptor_str（若已缓存）
          - 不复制任何会话/密钥状态（_crypto_state、window、key_agreement 等重置）
        """
        meta = {
            "nickname": self.nickname,
            "fingerprint": self.fingerprint_str,   # 仍用你现有的字符串形式
            "digest": self._digest_b64,
            "ip": self.ip,
            "or_port": self.or_port,
            "dir_port": self.dir_port,
            "version": self.version,
            "flags": self.flags,
        }
        hop = Tor_Router(meta)
        # 复用已拉取的 descriptor，避免重复网络 I/O
        hop.descriptor_str = self.descriptor_str
        return hop

    @staticmethod
    def parse(data):
        result = {}
        try:
            # Extract onion-key
            m = re.search(
                r"onion-key\s*-----BEGIN RSA PUBLIC KEY-----\s*(.+?)\s*-----END RSA PUBLIC KEY-----",
                data,
                re.DOTALL | re.IGNORECASE
            )
            if not m:
                raise ValueError("Missing onion-key")
            result['onion_key'] = b64decode(re.sub(r'\s+', '', m.group(1)))

            # Extract signing-key
            m = re.search(
                r"signing-key\s*-----BEGIN RSA PUBLIC KEY-----\s*(.+?)\s*-----END RSA PUBLIC KEY-----",
                data,
                re.DOTALL | re.IGNORECASE
            )
            if not m:
                raise ValueError("Missing signing-key")
            result['signing_key'] = b64decode(re.sub(r'\s+', '', m.group(1)))

            # Extract ntor-onion-key
            m = re.search(
                r"ntor-onion-key\s+([^\s\n]+)",
                data,
                re.IGNORECASE
            )
            if not m:
                raise ValueError("Missing ntor-onion-key")
            result['ntor_key'] = b64decode(m.group(1))

            return result

        except Exception as e:
            logger.debug("Can't parse router descriptor: %r", data)
            raise Exception(f"Can't parse router descriptor: {e}")


class Tor_Router_simple:
    def __init__(self, sock, sharekey=None):
        self.sock = sock
        self._crypto_state = None
        self.window = TorWindow()
        if sharekey is not None:
            self._crypto_state = ServerCryptoState(sharekey)

    def encrypt_forward(self, relay_cell):
        self._crypto_state.encrypt_forward(relay_cell)

    def decrypt_backward(self, relay_cell):
        self._crypto_state.decrypt_backward(relay_cell)

def b64_desc_to_hex(desc_b64: str) -> str:
    """
    将共识 r 行中的 DESC_B64（20 byte 的 SHA‑1，base64 无 '=' padding）
    转成 40 字符的十六进制串（DESC_HEX），
    供 /tor/server/d/<DESC_HEX> 使用。

    :param desc_b64:  共识里的第三列，如 'gX28yinjG1ZnL8u09OooQcZsAYI'
    :return:          '815DBCCA29E31B56672FCBB4F4EA2841C66C0182'
    """
    # 共识里通常把尾部 '=' 去掉了，需要补齐长度为 4 的倍数才能解码
    padded = desc_b64 + '=' * ((4 - len(desc_b64) % 4) % 4)
    digest_bytes = base64.b64decode(padded)
    if len(digest_bytes) != 20:
        raise ValueError(f"长度错误: 期望 20 字节，得到 {len(digest_bytes)}")
    return digest_bytes.hex().upper()


class Descriptor:
    def __init__(self, onion_key, signing_key, ntor_key):
        self._onion_key = onion_key
        self._signing_key = signing_key
        self._ntor_key = ntor_key

    @property
    def onion_key(self):
        return self._onion_key

    @property
    def signing_key(self):
        return self._signing_key

    @property
    def ntor_key(self):
        return self._ntor_key
