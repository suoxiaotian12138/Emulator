import msgpack
from typing import Any, Union, Sequence
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ---------- fast‑path markers ----------
_RAW_BYTES_MARK = b'\xC1'        # Reserved in MsgPack, never used → safe sentinel
_BYTES_SEQ_MARK = b'\xC2'        # We hijack 0xC2 (boolean false in MsgPack) before unpacking

_LEN_FIELD_SIZE = 4              # 4‑byte big‑endian length fields for byte‑sequences

# ---------- EC curve id maps ----------
CURVE_ID = {
    'secp256r1': 1,
    'secp384r1': 2,
    'secp521r1': 3,
    'secp256k1': 4,
}
_CURVE_OBJ = {
    1: ec.SECP256R1(),
    2: ec.SECP384R1(),
    3: ec.SECP521R1(),
    4: ec.SECP256K1(),
}

# ---------- public helpers ----------
def encode(data: Any) -> bytes:
    """
    Serialize *data* as compact as possible.
    * bytes         → 0xC1 | raw‑bytes         (overhead 1)
    * seq<bytes>    → 0xC2 | N | [len|chunk]   (overhead 1 + 1 + 4*N)
    * everything else → MessagePack
    """
    # --- zero‑copy fast path for raw bytes ---
    if isinstance(data, bytes):
        return _RAW_BYTES_MARK + data

    # --- optimized path for list / tuple of bytes ---
    if _is_bytes_sequence(data):
        if len(data) > 255:
            raise ValueError("Byte‑sequence too long (max 255 items)")
        buf = bytearray()
        buf += _BYTES_SEQ_MARK
        buf += bytes([len(data)])            # 1‑byte count
        for chunk in data:
            buf += len(chunk).to_bytes(_LEN_FIELD_SIZE, 'big')
            buf += chunk
        return bytes(buf)

    # --- fallback: MessagePack with custom object encoder ---
    return msgpack.packb(_encode_obj(data), use_bin_type=True)


def decode(blob: bytes) -> Any:
    """
    Reverse *encode*().
    """
    if not blob:
        raise ValueError("Empty input")

    # fast markers first
    if blob.startswith(_RAW_BYTES_MARK):
        return blob[1:]

    if blob.startswith(_BYTES_SEQ_MARK):
        count = blob[1]
        idx   = 2
        items = []
        for _ in range(count):
            if idx + _LEN_FIELD_SIZE > len(blob):
                raise ValueError("Corrupted byte‑sequence header")
            ln   = int.from_bytes(blob[idx:idx + _LEN_FIELD_SIZE], 'big')
            idx += _LEN_FIELD_SIZE
            items.append(blob[idx:idx + ln])
            idx += ln
        if idx != len(blob):
            raise ValueError("Trailing bytes detected")
        return tuple(items)

    # otherwise treat as MessagePack
    unpacked = msgpack.unpackb(blob, raw=False)
    return _decode_obj(unpacked)

# ---------- internal helpers ----------
def _is_bytes_sequence(obj: Any) -> bool:
    return isinstance(obj, (list, tuple)) and all(isinstance(x, bytes) for x in obj)

def _encode_obj(obj: Any) -> Any:
    """
    Recursively convert Python objects to MsgPack‑friendly structure,
    keeping it as small as possible.
    """
    # native MsgPack scalars
    if isinstance(obj, (int, float, bool, str)) or obj is None:
        return obj

    # bytes inside nested structures → keep raw
    if isinstance(obj, bytes):
        return obj

    # EC public key → tiny dict {b't':1, b'c':id, b'd':bytes}
    if isinstance(obj, ec.EllipticCurvePublicKey):
        cid = CURVE_ID.get(obj.curve.name)
        if cid is None:
            raise ValueError(f"Unsupported curve: {obj.curve.name}")
        data = obj.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint,
        )
        return {b't': 1, b'c': cid, b'd': data}

    # EC private key → tiny dict {b't':2, b'c':id, b'd':DER}
    if isinstance(obj, ec.EllipticCurvePrivateKey):
        cid = CURVE_ID.get(obj.curve.name)
        if cid is None:
            raise ValueError(f"Unsupported curve: {obj.curve.name}")
        data = obj.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        return {b't': 2, b'c': cid, b'd': data}

    # containers
    if isinstance(obj, (list, tuple)):
        return [_encode_obj(x) for x in obj]

    if isinstance(obj, dict):
        # encode keys as bytes if possible to save space
        return { _encode_key(k): _encode_obj(v) for k, v in obj.items() }

    raise TypeError(f"Unsupported type: {type(obj)}")

def _decode_obj(obj: Any) -> Any:
    """
    Reverse of *_encode_obj()* after MsgPack unpacking.
    """
    if isinstance(obj, dict) and b't' in obj and b'd' in obj:
        tcode = obj[b't']
        if tcode == 1:   # EC public
            curve = _CURVE_OBJ[obj[b'c']]
            return ec.EllipticCurvePublicKey.from_encoded_point(curve, obj[b'd'])
        if tcode == 2:   # EC private
            key = serialization.load_der_private_key(obj[b'd'], password=None)
            return key

    if isinstance(obj, list):
        return [_decode_obj(x) for x in obj]

    if isinstance(obj, dict):
        return { _decode_key(k): _decode_obj(v) for k, v in obj.items() }

    # raw bytes stay bytes; str already str
    return obj

def _encode_key(k: Any) -> Any:
    return k.encode('utf-8') if isinstance(k, str) else k

def _decode_key(k: Any) -> Any:
    return k.decode('utf-8') if isinstance(k, bytes) else k
