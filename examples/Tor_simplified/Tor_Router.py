from torpy.crypto_common import b64decode
from torpy.consesus import Descriptor
from torpy.parsers import RouterDescriptorParser
from torpy.stream import TorWindow
from examples.Tor_simplified.Tor_Cell import *
from examples.Tor_simplified.Tor_Crypt import ServerCryptoState, CryptoState
from examples.Tor_simplified.Tor_Crypt import NtorKeyAgreement


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
        self.digest = b64decode(router['digest']) if router['digest'] else None
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
        descriptor_info = RouterDescriptorParser.parse(self.descriptor_str)
        return Descriptor(**descriptor_info)

    def set_descriptor(self, descriptor_str):
        self.descriptor_str = descriptor_str


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


