import ssl
import ipaddress
import tempfile
import datetime

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization, hashes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa

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

def rsa_setup():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def curve25519_get_shared(private, public):
    return private.exchange(public)


def ed25519_setup():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_cert_and_key_from_ed25519(private_key: ed25519.Ed25519PrivateKey):
    """原始的Ed25519证书生成函数"""
    public_key = private_key.public_key()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Haidian"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"OnionNode"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
    ])

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
    ).sign(private_key, algorithm=None)

    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".crt", mode='wb')
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".key", mode='wb')

    cert_file.write(cert.public_bytes(serialization.Encoding.PEM))
    cert_file.close()

    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_file.close()

    return cert_file.name, key_file.name

def generate_cert_from_ed25519(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Generate a throw-away X.509 cert (only to mimic the *-cert* section)."""
    pub = private_key.public_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Haidian"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OnionNode"),
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(private_key, algorithm=None)          # fake self-sign
    )
    return cert.public_bytes(serialization.Encoding.DER)

def create_server_context(certfile, keyfile):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ALL:@SECLEVEL=0")          # 允许自签 RSA-PKCS1
    ctx.verify_mode = ssl.CERT_NONE
    return ctx




def generate_cert_and_key_from_rsa(key: rsa.RSAPrivateKey):
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    crt = tempfile.NamedTemporaryFile(delete=False, suffix=".crt", mode="wb")
    keyf = tempfile.NamedTemporaryFile(delete=False, suffix=".key", mode="wb")
    crt.write(cert.public_bytes(serialization.Encoding.PEM)); crt.close()
    keyf.write(key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())); keyf.close()
    return crt.name, keyf.name