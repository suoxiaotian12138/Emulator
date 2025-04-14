import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


def encode(data):
    """使用 JSON + 更高效的序列化方式处理数据"""

    def encode_bytes(obj):
        # 如果是字节类型，直接进行 Base64 编码
        if isinstance(obj, bytes):
            return {"type": "bytes", "data": base64.b64encode(obj).decode("utf-8")}

        # 如果是 ECPublicKey 类型，使用压缩点格式序列化为字节
        elif isinstance(obj, ec.EllipticCurvePublicKey):
            return {"type": "ECPublicKey", "data": base64.b64encode(obj.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.CompressedPoint
            )).decode("utf-8")}

        # 如果是 ECPrivateKey 类型，使用更紧凑的DER和PKCS8格式
        elif isinstance(obj, ec.EllipticCurvePrivateKey):
            return {"type": "ECPrivateKey", "data": base64.b64encode(obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )).decode("utf-8")}

        raise TypeError(f"Type {type(obj)} not serializable")

    # 序列化为JSON字符串
    return json.dumps(data, default=encode_bytes).encode("utf-8")


def decode(encoded_data):
    """将序列化的数据反序列化回原始对象"""

    def decode_bytes(obj):
        # 解析存储的字典对象
        if isinstance(obj, dict) and "type" in obj and "data" in obj:
            raw_data = base64.b64decode(obj["data"])

            if obj["type"] == "bytes":
                return raw_data  # 直接返回原始 bytes

            elif obj["type"] == "ECPublicKey":
                # 从压缩点格式解析公钥
                return ec.EllipticCurvePublicKey.from_encoded_point(
                    ec.SECP256R1(),
                    raw_data
                )

            elif obj["type"] == "ECPrivateKey":
                # 从DER格式解析私钥
                return serialization.load_der_private_key(
                    raw_data,
                    password=None
                )

        return obj  # 其他类型的内容直接返回

    return json.loads(encoded_data.decode("utf-8"), object_hook=decode_bytes)