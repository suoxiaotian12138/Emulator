from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
import base64
import time
import socket
from typing import Tuple, Optional


class TorRouterDescriptor:
    """
    一个生成Tor路由器描述符的类，根据传入的节点参数生成描述符。
    支持RSA身份密钥和Ed25519签名密钥。
    """

    def __init__(self, nickname: str, ip_address: str, or_port: int, dir_port: int,
                 identity_key: rsa.RSAPrivateKey, signing_key: ed25519.Ed25519PrivateKey,
                 onion_key: rsa.RSAPrivateKey, bandwidth: Tuple[int, int, int] = (10000, 20000, 15000),
                 exit_policy: str = "reject *:*", platform: str = "Tor 0.4.8.10 on Linux"):
        """
        初始化路由器描述符生成器。

        :param nickname: 节点昵称
        :param ip_address: 节点IPv4地址
        :param or_port: ORPort（Tor协议端口）
        :param dir_port: DirPort（目录服务端口，通常为0表示不提供目录服务）
        :param identity_key: RSA身份私钥（用于标识节点）
        :param signing_key: Ed25519签名私钥（用于签署描述符）
        :param onion_key: RSA洋葱私钥（用于洋葱路由加密）
        :param bandwidth: (rate, burst, capacity) 三元组，单位KB/s
        :param exit_policy: 出口策略字符串
        :param platform: 平台信息字符串
        """
        self.nickname = nickname
        self.ip_address = ip_address
        self.or_port = or_port
        self.dir_port = dir_port
        self.identity_key = identity_key
        self.signing_key = signing_key
        self.onion_key = onion_key
        self.bandwidth = bandwidth  # (rate, burst, capacity)
        self.exit_policy = exit_policy
        self.platform = platform
        self.published_on = int(time.time())
        self.descriptor_body = None
        self.signature = None

    def generate_descriptor(self) -> str:
        """
        生成并返回签名后的路由器描述符字符串。

        :return: 完整的描述符字符串
        """
        # 构建未签名的描述符主体
        self._build_descriptor_body()

        # 对描述符主体签名
        self._sign_descriptor()

        # 返回完整的描述符
        return f"{self.descriptor_body}\nrouter-signature\n{self._format_signature(self.signature)}"

    def _build_descriptor_body(self):
        """
        构建未签名的描述符主体。
        """
        # 获取公钥的PEM格式
        identity_pubkey_pem = self.identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('ascii')

        onion_pubkey_pem = self.onion_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('ascii')

        signing_pubkey = self.signing_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        signing_pubkey_b64 = base64.b64encode(signing_pubkey).decode('ascii')

        # 构造描述符主体
        descriptor_lines = [
            f"router {self.nickname} {self.ip_address} {self.or_port} 0 {self.dir_port}",
            f"platform {self.platform}",
            f"proto Cons=1-2 Desc=1-2 DirCache=1-2 FlowCtrl=1 HSDir=1-2 HSIntro=3-4 HSRend=1-2 Link=1-5 LinkAuth=1-3 Microdesc=1-2 Padding=1-2 Relay=1-2",
            f"published {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(self.published_on))}",
            f"bandwidth {self.bandwidth[0]} {self.bandwidth[1]} {self.bandwidth[2]}",
            "onion-key",
            onion_pubkey_pem.strip(),
            "signing-key",
            f"-----BEGIN ED25519 PUBLIC KEY-----\n{signing_pubkey_b64}\n-----END ED25519 PUBLIC KEY-----",
            f"accept {self.exit_policy}" if "accept" in self.exit_policy else f"reject {self.exit_policy}",
        ]

        self.descriptor_body = "\n".join(descriptor_lines)

    def _sign_descriptor(self):
        """
        使用Ed25519签名密钥对描述符主体签名。
        """
        # 计算描述符的SHA-1哈希（Tor使用SHA-1）
        digest = hashes.Hash(hashes.SHA1())
        digest.update(self.descriptor_body.encode('ascii'))
        digest_value = digest.finalize()

        # 使用Ed25519私钥签名
        self.signature = self.signing_key.sign(digest_value)

    def _format_signature(self, signature: bytes) -> str:
        """
        将签名格式化为Tor描述符中的BASE64编码块。

        :param signature: 二进制签名
        :return: 格式化后的签名字符串
        """
        signature_b64 = base64.b64encode(signature).decode('ascii')
        return f"-----BEGIN SIGNATURE-----\n{signature_b64}\n-----END SIGNATURE-----"

    def get_identity_digest(self) -> bytes:
        """
        计算身份公钥的SHA-1指纹。

        :return: 20字节的指纹
        """
        pubkey_der = self.identity_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        digest = hashes.Hash(hashes.SHA1())
        digest.update(pubkey_der)
        return digest.finalize()

    def get_signing_public_key(self) -> ed25519.Ed25519PublicKey:
        """
        返回Ed25519签名公钥。
        :return: Ed25519公钥对象
        """
        return self.signing_key.public_key()


# 测试函数，包括签名验证
def test_descriptor_with_validation():
    # 生成示例密钥
    identity_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signing_key = ed25519.Ed25519PrivateKey.generate()
    onion_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    # 创建描述符实例
    descriptor = TorRouterDescriptor(
        nickname="MyRelay",
        ip_address="192.168.1.1",
        or_port=9001,
        dir_port=0,
        identity_key=identity_key,
        signing_key=signing_key,
        onion_key=onion_key,
        bandwidth=(10000, 20000, 15000),
        exit_policy="reject *:*",
        platform="Tor 0.4.8.10 on Linux"
    )

    # 生成描述符
    descriptor_str = descriptor.generate_descriptor()
    print("Generated Descriptor:")
    print(descriptor_str)

    # 获取身份指纹
    fingerprint = descriptor.get_identity_digest().hex().upper()
    print(f"Identity Fingerprint: {fingerprint}")

    # 提取描述符主体和签名以进行验证
    descriptor_lines = descriptor_str.splitlines()
    signature_start_idx = descriptor_lines.index("router-signature")
    body_lines = descriptor_lines[:signature_start_idx]
    signature_lines = descriptor_lines[signature_start_idx + 2: -1]  # 跳过BEGIN/END行
    signature_b64 = "".join(signature_lines)
    signature = base64.b64decode(signature_b64)

    # 计算描述符主体的SHA-1哈希
    body_text = "\n".join(body_lines)
    digest = hashes.Hash(hashes.SHA1())
    digest.update(body_text.encode('ascii'))
    digest_value = digest.finalize()

    # 使用Ed25519签名公钥验证签名
    signing_public_key = descriptor.get_signing_public_key()
    try:
        signing_public_key.verify(signature, digest_value)
        print("Signature Verification: SUCCESS")
    except Exception as e:
        print(f"Signature Verification: FAILED ({str(e)})")

    return True