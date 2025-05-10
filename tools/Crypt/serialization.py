import json
import base64
from typing import Any, Union
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import asyncio



def encode(data: Any) -> bytes:
    """Serialize complex Python objects to JSON-encoded bytes."""

    def encode_object(obj: Any) -> Any:
        # JSON-native types: pass through directly
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj

        # Encode bytes via base64
        if isinstance(obj, bytes):
            return {"_type": "bytes", "data": base64.b64encode(obj).decode("utf-8")}

        # Encode elliptic curve public key (compressed)
        if isinstance(obj, ec.EllipticCurvePublicKey):
            # 存储曲线信息
            curve_name = obj.curve.name
            return {
                "_type": "ECPublicKey",
                "curve": curve_name,
                "data": base64.b64encode(obj.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.CompressedPoint
                )).decode("utf-8")
            }

        # Encode elliptic curve private key (DER format)
        if isinstance(obj, ec.EllipticCurvePrivateKey):
            curve_name = obj.curve.name
            return {
                "_type": "ECPrivateKey",
                "curve": curve_name,
                "data": base64.b64encode(obj.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )).decode("utf-8")
            }

        # Recursively encode lists or tuples - 直接序列化为基本列表类型
        if isinstance(obj, (list, tuple)):
            return [encode_object(x) for x in obj]

        # Recursively encode dictionaries - 直接序列化为基本字典类型
        if isinstance(obj, dict):
            # 检查是否有与我们的特殊前缀冲突的键
            for key in obj:
                if isinstance(key, str) and key.startswith('_type'):
                    # 处理冲突情况，在用户数据前添加标记
                    return {
                        "_type": "dict",
                        "data": {k: encode_object(v) for k, v in obj.items()}
                    }
            # 无冲突时直接编码
            return {k: encode_object(v) for k, v in obj.items()}

        raise TypeError(f"Unsupported type for serialization: {type(obj)}")

    try:
        return json.dumps(encode_object(data)).encode("utf-8")
    except Exception as e:
        print(f"[Encode Error] {e}")
        raise  # 仍然抛出，防止 silent fail


def decode(encoded_data: Union[str, bytes]) -> Any:
    """Deserialize JSON-encoded bytes back into original Python objects."""

    def decode_object(obj: Any) -> Any:
        if isinstance(obj, dict) and "_type" in obj:
            t = obj["_type"]

            if t == "bytes" and "data" in obj:
                return base64.b64decode(obj["data"])

            if t == "ECPublicKey" and "data" in obj and "curve" in obj:
                # 使用存储的曲线信息
                curve_name = obj["curve"]
                curve = get_curve_by_name(curve_name)
                return ec.EllipticCurvePublicKey.from_encoded_point(
                    curve, base64.b64decode(obj["data"])
                )

            if t == "ECPrivateKey" and "data" in obj and "curve" in obj:
                decoded = base64.b64decode(obj["data"])
                key = serialization.load_der_private_key(decoded, password=None)
                if not isinstance(key, ec.EllipticCurvePrivateKey):
                    raise ValueError("Decoded key is not an EC private key")
                return key

            if t == "dict" and "data" in obj:
                return {k: decode_object(v) for k, v in obj["data"].items()}

        # 处理列表
        if isinstance(obj, list):
            return [decode_object(x) for x in obj]

        # 处理普通字典
        if isinstance(obj, dict):
            return {k: decode_object(v) for k, v in obj.items()}

        return obj

    def get_curve_by_name(name: str) -> ec.EllipticCurve:
        """根据名称获取相应的椭圆曲线。"""
        curves = {
            "secp256r1": ec.SECP256R1(),
            "secp384r1": ec.SECP384R1(),
            "secp521r1": ec.SECP521R1(),
            "secp256k1": ec.SECP256K1()
        }
        if name.lower() in curves:
            return curves[name.lower()]
        raise ValueError(f"Unsupported curve: {name}")

    try:
        if isinstance(encoded_data, bytes):
            encoded_data = encoded_data.decode("utf-8")

        return decode_object(json.loads(encoded_data))
    except Exception as e:
        print("encoded_data",encoded_data)
        print("========================================")
        print(f"[Decode Error] Invalid encoded data: {e}")
        raise  # 改为重新抛出异常，便于调试