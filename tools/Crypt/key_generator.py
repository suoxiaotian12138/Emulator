import ssl
import ipaddress
import tempfile
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey

from baselib.sphinxmix.SphinxParams import SphinxParams

def SECP256R1_setup():
    ''' setup the parameters of the loopix Crypto-system '''
    curve = ec.SECP256R1()
    private_key = ec.generate_private_key(curve)
    public_key = private_key.public_key()
    generator = public_key.public_numbers().x, public_key.public_numbers().y
    return curve, private_key, public_key, generator


def sphinx_SECP256R1_setup(params: SphinxParams):
    group = params.group
    curve = group.G
    priv, pub = group.keygen()
    generator = group.g
    return curve, priv, pub, generator


# Keys for the ntor protocol, Generate session key via dh exchange, 32bytes
def curve25519_setup():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def curve25519_get_shared(private, public):
    return private.exchange(public)


def ed25519_setup():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_cert_and_key_from_ed25519(private_key: ed25519.Ed25519PrivateKey):
    # 1. 获取公钥
    public_key = private_key.public_key()

    # 2. 构造证书字段
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Haidian"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OnionNode"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
    ])

    # 3. 构造自签名 X.509 证书
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False
    ).sign(private_key, algorithm=None)  # Ed25519 不需要手动指定哈希算法

    # 4. 写入临时文件
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt", mode='wb')
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key", mode='wb')

    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.close()

    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,  # 可用于 SSL/TLS
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_file.close()

    return cert_file.name, key_file.name


def create_server_context(certfile: str, keyfile: str) -> ssl.SSLContext:
    """
    模拟 Tor 节点服务端的 SSLContext，用于接受 TLS 客户端连接。
    该 Context 使用已有的证书和私钥，支持 TLS 1.2/1.3，禁用旧协议。
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    context.options |= (
        ssl.OP_NO_SSLv2 |
        ssl.OP_NO_SSLv3 |
        ssl.OP_NO_TLSv1 |
        ssl.OP_NO_TLSv1_1
    )

    context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
    context.options |= ssl.OP_SINGLE_ECDH_USE
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_NONE

    return context

