from tools.json_reader import JSONReader
from datetime import datetime

import ssl
import datetime
import os
import time
import struct
import random
import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from typing import Tuple
import nacl.signing

# 参考了tor 0.4.8.14版本的代码进行实现
# 定义 RSA 公钥指数（与 TOR_RSA_EXPONENT 相同）
TOR_RSA_EXPONENT = 65537
# 定义 RSA 密钥位数（与 PK_BYTES*8 相同，默认 1024，但推荐 2048 以上）
RSA_BITS = 2048


class Cryptp_Tor():

    def __init__(self):
        self.jsonReader = JSONReader(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config.json'))


    def generate_rsa_key(self, bits=RSA_BITS):
        """
        生成 RSA 密钥对，Tor 的 crypto_pk_generate_key_with_bits()
        作为客户端的身份密钥
        """
        # 生成 RSA 私钥
        private_key = rsa.generate_private_key(
            public_exponent=TOR_RSA_EXPONENT,
            key_size=bits
        )

        return private_key

    def save_keys_to_pem(self, private_key, private_key_file="private_key.pem", public_key_file="public_key.pem"):
        """
        将 RSA 私钥和公钥保存为 PEM 文件
        """
        # 保存私钥（PEM 格式）
        with open(private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()  # 不加密
            ))

        # 获取并保存公钥
        public_key = private_key.public_key()
        with open(public_key_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

class TorTLSContext:
    """
    用于模拟 Tor 中的 TLS 上下文初始化逻辑的示例类。

    - 生成客户端 / 服务端 RSA 密钥对
    - 生成自签名证书（演示）
    - 使用 ssl.SSLContext 作为实际的 TLS Context

    """

    def __init__(self, is_public_server=False):
        #设定节点类型
        self.is_public_server = is_public_server

        # 在 Tor 中，这里类似 client_tls_context 和 server_tls_context 全局变量
        self.client_tls_context = None
        self.server_tls_context = None

        # 模拟 Tor 的 client/server identity key
        self.client_identity_key = None
        self.server_identity_key = None

    def init_tls_client(self, identity_key):

        self.client_identity_key = identity_key
        self.router_initialize_tls_context()


    def router_initialize_tls_context(self, key_lifetime=365):
        """
        对应 Tor 中的 router_initialize_tls_context():
        - 如果 is_public_server = True，则初始化 server_tls_context，并令 client_tls_context 与其相同
        - 否则根据是否提供 server_identity 生成或释放 server_tls_context
        - 最后初始化 client_tls_context
        - 返回 MIN(rv1, rv2) 之类的结果（此示例简化处理）

        参数:
            is_public_server: 是否作为公开的服务器（Tor中用于区分public server / client等）
            key_lifetime: 证书的有效期天数（只是演示）
        """
        rv1 = 0
        rv2 = 0

        # 如果是公共服务器，必须已经存在 server_identity_key
        if self.is_public_server:
            if not self.server_identity_key:
                # 如果没有 server key，就自动生成一个
                self.server_identity_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )

            # 初始化 server_tls_context
            rv1 = self._tls_context_init_one(
                ppcontext_attr='server_tls_context',  # 要更新的属性
                identity_key=self.server_identity_key,
                key_lifetime=key_lifetime,
                flags=0,
                is_client=False
            )

            # 如果成功，则让 client_tls_context 也指向同一个
            if rv1 >= 0 and self.server_tls_context:
                old_ctx = self.client_tls_context
                self.client_tls_context = self.server_tls_context
                # 释放旧的 client_tls_context（Tor中有引用计数；此处直接覆盖即可）
                if old_ctx:
                    # 如果需要可以手动做一些 clean up
                    pass

        else:
            # is_public_server = False
            # 如果需要 server_identity_key，就初始化，否则就释放 server_tls_context
            if self.server_identity_key:
                rv1 = self._tls_context_init_one(
                    ppcontext_attr='server_tls_context',
                    identity_key=self.server_identity_key,
                    key_lifetime=key_lifetime,
                    flags=0,
                    is_client=False
                )
            else:
                # 释放旧的 server_tls_context
                self.server_tls_context = None

            # 初始化 client context
            rv2 = self._tls_context_init_one(
                ppcontext_attr='client_tls_context',
                identity_key=self.client_identity_key,
                key_lifetime=key_lifetime,
                flags=0,
                is_client=True
            )

        # 返回 MIN(rv1, rv2)
        return min(rv1, rv2)

    def _tls_context_init_one(self, ppcontext_attr, identity_key, key_lifetime, flags, is_client):
        """
        对应 Tor 中的 tor_tls_context_init_one()：
        - 调用 _tls_context_new() 创建新的 TLS Context
        - 如果成功，则替换 self.*_tls_context 并释放旧的 context
        - 返回 0 或 -1
        """
        new_ctx = self._tls_context_new(
            identity_key=identity_key,
            key_lifetime=key_lifetime,
            flags=flags,
            is_client=is_client
        )
        old_ctx = getattr(self, ppcontext_attr)

        if new_ctx is not None:
            setattr(self, ppcontext_attr, new_ctx)
            # 这里模拟释放 old_ctx
            if old_ctx is not None:
                # Tor 里是 tor_tls_context_decref(old_ctx)
                # 我们就简单地打印或 pass
                pass
            return 0
        else:
            return -1

    def _tls_context_new(self, identity_key, key_lifetime, flags, is_client):
        """
        对应 Tor 中的 tor_tls_context_new():
        - 初始化 SSLContext (client / server)
        - 调用 _tls_context_init_certificates() 生成并加载证书
        - 返回这个新的 SSLContext 对象
        """
        if not identity_key:
            return None

        # 1. 创建对应的 SSLContext
        #    根据 is_client 选择 PROTOCOL_TLS_CLIENT 还是 PROTOCOL_TLS_SERVER
        if is_client:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # 示例中不做验证
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # 2. 调用 _tls_context_init_certificates() 来生成/加载证书
        rv = self._tls_context_init_certificates(context, identity_key, key_lifetime, flags)
        if rv < 0:
            return None

    def _tls_context_init_certificates(self, context, identity_key, key_lifetime, flags):
        """
        对应 Tor 中的 tor_tls_context_init_certificates():
        - 基于 identity_key 生成自签名证书
        - 将证书和私钥加载到 context 中
        - 如果成功返回 0，否则返回 -1
        """
        import tempfile
        from cryptography.hazmat.primitives import serialization

        try:
            # 构造证书主题信息
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Some-State"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Some-City"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Tor Demo"),
                x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
            ])

            # 构造自签名证书
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(identity_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=key_lifetime)
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                    critical=False,
                )
                .sign(identity_key, hashes.SHA256())
            )

            # 写到临时 PEM 文件
            temp_cert = tempfile.NamedTemporaryFile(delete=False, suffix=".crt")
            temp_key = tempfile.NamedTemporaryFile(delete=False, suffix=".key")

            # 证书 PEM
            temp_cert.write(cert.public_bytes(serialization.Encoding.PEM))
            temp_cert.flush()
            temp_cert.close()

            # 私钥 PEM
            key_pem_bytes = identity_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            temp_key.write(key_pem_bytes)
            temp_key.flush()
            temp_key.close()

            # 将证书加载进 context
            context.load_cert_chain(
                certfile=temp_cert.name,
                keyfile=temp_key.name
            )

        except Exception as e:
            print("Failed to initialize certificates:", e)
            return -1

        return 0

class Ed25519Crypto:
    # 证书标志
    CERT_FLAG_INCLUDE_SIGNING_KEY = 1

    def __init__(self, extra_strong=False):
        """
        初始化 Ed25519 加密工具
        :param extra_strong: 是否使用更强的随机性生成种子
        """
        self.extra_strong = extra_strong

    def _generate_seed(self):
        """
        生成32字节种子
        :return: 32字节种子
        """
        if not self.extra_strong:
            return os.urandom(32)

        # 强随机性模式
        dlen = hashlib.sha512().digest_size  # 64字节
        entropy_sources = [
            os.urandom(dlen),
            random.getrandbits(dlen * 8).to_bytes(dlen, 'big')
        ]

        # 尝试读取 /dev/urandom
        try:
            with open("/dev/urandom", "rb") as f:
                entropy_sources.append(f.read(dlen))
        except FileNotFoundError:
            pass

        # 混合熵源并生成种子
        entropy_mix = b"".join(entropy_sources)
        return hashlib.sha512(entropy_mix).digest()[:32]

    def generate_keypair(self):
        """
        生成 Ed25519 密钥对
        :return: (私钥, 公钥) 元组，私钥为64字节 Tor 格式，公钥为32字节
        """
        seed = self._generate_seed()
        private_key = nacl.signing.SigningKey(seed)
        public_key = private_key.verify_key
        # Tor 格式的 64 字节私钥
        expanded_secret = seed + hashlib.sha512(seed).digest()[:32]
        return expanded_secret, public_key.encode()

    def create_certificate(self, signing_key, cert_type, signed_key, lifetime, flags=0):
        """
        创建并签署 Ed25519 证书
        :param signing_key: 用于签名的私钥 (cryptography 的 Ed25519PrivateKey)
        :param cert_type: 证书类型
        :param signed_key: 被认证的公钥 (32字节)
        :param lifetime: 有效时间 (秒)
        :param flags: 证书标志
        :return: 编码并签名的证书字节
        """
        now = int(time.time())
        version = 1
        exp_field = (now + lifetime) // 3600  # 到期时间 (小时)
        cert_key_type = 1  # Ed25519 密钥类型
        extensions = [signing_key.public_key().public_bytes_raw()] if flags & self.CERT_FLAG_INCLUDE_SIGNING_KEY else []

        # 编码证书主体
        cert_data = struct.pack(
            ">BBIB32s",
            version,
            cert_type,
            exp_field,
            cert_key_type,
            signed_key
        )
        # 添加扩展
        cert_data += struct.pack(">B", len(extensions))
        for ext in extensions:
            cert_data += struct.pack(">B", len(ext)) + ext

        # 签名
        signature = signing_key.sign(cert_data)  # 直接获取签名字节
        return cert_data + signature  # 直接拼接签名字节

    def verify_certificate(self, verify_key, cert_data):
        """
        验证 Ed25519 证书
        :param verify_key: 用于验证的公钥 (cryptography 的 Ed25519PublicKey)
        :param cert_data: 证书字节数据
        :return: True if valid, raises exception if invalid
        """
        signature_idx = len(cert_data) - 64  # Ed25519 签名长度为64字节
        body = cert_data[:signature_idx]
        signature = cert_data[signature_idx:]
        verify_key.verify(signature, body)
        return True

class Curve25519KeyPair:
    """
    一个实现Tor风格Curve25519密钥生成的类，与Tor的功能一致。
    使用cryptography库，支持普通和强随机源。
    """

    # Curve25519密钥长度固定为32字节
    CURVE25519_KEY_LEN = 32

    def __init__(self, extra_strong: bool = False):
        """
        初始化密钥对生成器。

        :param extra_strong: 是否使用强随机源（模拟crypto_strongest_rand）
        """
        self.extra_strong = extra_strong
        self.private_key = None
        self.public_key = None

    def generate(self) -> Tuple[bytes, bytes]:
        """
        生成Curve25519密钥对。

        :return: (private_key_bytes, public_key_bytes) - 私钥和公钥的字节表示
        """
        # 生成私钥
        private_key_bytes = self._generate_secret_key()

        # 从私钥字节构造X25519私钥对象
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        # 生成公钥
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        self.private_key = private_key_bytes
        self.public_key = public_key_bytes

        return private_key_bytes, public_key_bytes

    def _generate_secret_key(self) -> bytes:
        """
        生成符合Tor要求的Curve25519私钥字节。

        :return: 32字节的私钥
        """
        # 生成随机字节
        if self.extra_strong:
            # 使用os.urandom模拟强随机源（在实际生产中可以用更强的随机源）
            secret_key = bytearray(os.urandom(self.CURVE25519_KEY_LEN))
        else:
            # 使用普通随机源
            secret_key = bytearray(os.urandom(self.CURVE25519_KEY_LEN))

        # 应用Tor的掩码规则，使其符合Curve25519私钥格式
        secret_key[0] &= 248  # 清除最低3位
        secret_key[31] &= 127  # 清除最高位
        secret_key[31] |= 64  # 设置第6位

        return bytes(secret_key)

    def get_private_key(self) -> bytes:
        """
        获取私钥字节。

        :return: 32字节私钥
        """
        if self.private_key is None:
            self.generate()
        return self.private_key

    def get_public_key(self) -> bytes:
        """
        获取公钥字节。

        :return: 32字节公钥
        """
        if self.public_key is None:
            self.generate()
        return self.public_key



# 测试代码
def est_ed25519_crypto():
    # 初始化加密工具
    crypto = Ed25519Crypto(extra_strong=True)

    # 测试密钥生成
    print("测试密钥生成...")
    secret_key, public_key = crypto.generate_keypair()
    assert len(secret_key) == 64, "私钥长度应为64字节"
    assert len(public_key) == 32, "公钥长度应为32字节"
    print(f"生成密钥对成功: 私钥长度={len(secret_key)}, 公钥长度={len(public_key)}")

    # 将密钥转换为 cryptography 格式以测试证书
    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(secret_key[:32])  # 只用前32字节
    signed_key = public_key

    # 测试证书生成
    print("\n测试证书生成...")
    cert_type = 1  # 示例证书类型
    lifetime = 24 * 3600  # 24小时
    cert_data = crypto.create_certificate(signing_key, cert_type, signed_key, lifetime,
                                        flags=Ed25519Crypto.CERT_FLAG_INCLUDE_SIGNING_KEY)
    print(f"证书生成成功: 长度={len(cert_data)}字节")

    # 测试证书验证
    print("\n测试证书验证...")
    public_key_obj = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    try:
        crypto.verify_certificate(public_key_obj, cert_data)
        print("证书验证成功!")
    except Exception as e:
        print(f"证书验证失败: {e}")


def curve25519_test():
    # 创建普通随机密钥对
    keypair_normal = Curve25519KeyPair(extra_strong=False)
    priv_key_normal, pub_key_normal = keypair_normal.generate()
    print(f"Normal Private Key: {priv_key_normal.hex()}")
    print(f"Normal Public Key: {pub_key_normal.hex()}")

    # 创建强随机密钥对
    keypair_strong = Curve25519KeyPair(extra_strong=True)
    priv_key_strong, pub_key_strong = keypair_strong.generate()
    print(f"Strong Private Key: {priv_key_strong.hex()}")
    print(f"Strong Public Key: {pub_key_strong.hex()}")

# 测试代码
def test_tor_crypto():
    """测试 TorCrypto 类的功能"""
    crypto = Cryptp_Tor()

    # 测试密钥生成
    print("测试 RSA 密钥生成...")
    private_key = crypto.generate_rsa_key()
    assert private_key.key_size == RSA_BITS, f"密钥大小应为 {RSA_BITS}"
    print(f"密钥生成成功: 大小={private_key.key_size}位")

    # 测试 TLS 上下文（客户端）
    print("\n测试客户端 TLS 上下文...")
    client_context = crypto.create_tls_context(private_key, is_client=True)
    assert isinstance(client_context, ssl.SSLContext), "客户端上下文创建失败"
    print("客户端 TLS 上下文创建成功!")

    # 测试 TLS 上下文（服务器）
    print("\n测试服务器 TLS 上下文...")
    server_context = crypto.create_tls_context(private_key, is_client=False, is_public_server=True)
    assert isinstance(server_context, ssl.SSLContext), "服务器上下文创建失败"
    print("服务器 TLS 上下文创建成功!")

    # 清理测试文件
    for file in ["test_private_key.pem", "test_public_key.pem"]:
        if os.path.exists(file):
            os.remove(file)

if __name__ == "__main__":
    test_tor_crypto()
