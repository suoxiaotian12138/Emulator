import re, base64, struct, hashlib, time
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, rsa
from cryptography.hazmat.primitives import serialization
from examples.Tor_simplified.Tor_Descriptor import TorDescriptor_build

# ====== 这里 import 你的类和辅助函数 ======
# from your_module import TorDescriptor_build, _ext_signed_with, _b64_no_padding, _rsa_pkcs1_v1_5_sign_raw, _rsa_pkcs1_v1_5_sign_blob
# 如果就在同一文件中，上面那行不用。

P = 2**255 - 19

def inv(x): return pow(x, P-2, P)

def mont_to_edwards(u: int, sign_bit: int):
    y = ((u - 1) * inv(u + 1)) % P
    num = (y + 1) % P
    den = (1 - y) % P
    x_sq = (num * inv(den)) % P
    x = pow(x_sq, (P + 3) // 8, P)
    if (x * x - x_sq) % P != 0:
        x = (x * pow(2, (P - 1)//4, P)) % P
    if x & 1 != sign_bit:
        x = (-x) % P
    return x, y

def encode_edwards_point(x: int, y: int) -> bytes:
    y_bytes = int.to_bytes(y, 32, 'little')
    y_list = bytearray(y_bytes)
    y_list[31] &= 0x7F
    if x & 1:
        y_list[31] |= 0x80
    return bytes(y_list)

def curve25519_pub_to_ed25519_pub(curve_pub_bytes: bytes, sign_bit: int) -> bytes:
    u = int.from_bytes(curve_pub_bytes, 'little')
    x, y = mont_to_edwards(u, sign_bit)
    return encode_edwards_point(x, y)

def b64fix(s: str) -> bytes:
    return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4))

def extract_block(desc: str, begin: str, end: str, idx=0) -> bytes:
    patt = re.compile(re.escape(begin) + r"\s+(.*?)\s+" + re.escape(end), re.S)
    m = patt.findall(desc)
    if not m or idx >= len(m):
        raise ValueError(f"block {begin} not found index {idx}")
    text = "".join(line.strip() for line in m[idx].splitlines())
    return b64fix(text)

def find_line(desc: str, token: str) -> str:
    m = re.search(rf"^{re.escape(token)}(?: .*)?$", desc, re.M)
    if not m:
        raise ValueError(f"line '{token}' not found")
    return m.group(0)

@dataclass
class EdCert:
    version: int
    cert_type: int
    exp_hr: int
    keytype: int
    signed_key: bytes
    signature: bytes
    body: bytes

def parse_ed_cert(raw: bytes) -> EdCert:
    off = 0
    version, cert_type, exp_hr, keytype = struct.unpack(">BBIB", raw[off:off+7])
    off += 7
    signed_key = raw[off:off+32]; off += 32
    n_ext = raw[off]; off += 1
    for _ in range(n_ext):
        l, typ, flags = struct.unpack(">HBB", raw[off:off+4]); off += 4
        off += l  # skip data
    body = raw[:off]
    signature = raw[off:off+64]
    return EdCert(version, cert_type, exp_hr, keytype, signed_key, signature, body)

def ed_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
        return True
    except Exception:
        return False

def calc_router_digest(desc: str):
    start = desc.find("router ")
    if start < 0:
        raise ValueError("no router line")
    end_marker = "\nrouter-sig-ed25519"
    end = desc.find(end_marker)
    if end < 0:
        raise ValueError("no router-sig-ed25519 line")
    signed_part = desc[start:end].encode()
    digest = hashlib.sha256(b"Tor router descriptor signature v1" + signed_part).digest()
    sig_line = find_line(desc, "router-sig-ed25519")
    sig = b64fix(sig_line.split()[1])
    return digest, sig

if __name__ == "__main__":
    # 1. 随机密钥
    master_ed_sk = ed25519.Ed25519PrivateKey.generate()
    master_ed_pk = master_ed_sk.public_key()
    curve_sk = x25519.X25519PrivateKey.generate()
    curve_pk = curve_sk.public_key()
    rsa_id_sk = rsa.generate_private_key(65537, 1024)
    rsa_onion_sk = rsa.generate_private_key(65537, 1024)

    # 2. 生成描述符
    builder = TorDescriptor_build(
        nickname="RelayX",
        ip="127.0.0.1",
        master_ed_sk=master_ed_sk,
        ed_pk=master_ed_pk,
        curve_sk=curve_sk,
        curve_pk=curve_pk,
        rsa_sk=rsa_id_sk,        # 未用
        rsa_id_sk=rsa_id_sk,
        rsa_onion_sk=rsa_onion_sk,
    )
    desc = builder.build()

    # 3. 解析两个 ED25519 CERT
    id_raw  = extract_block(desc, "-----BEGIN ED25519 CERT-----", "-----END ED25519 CERT-----", 0)
    ntor_raw= extract_block(desc, "-----BEGIN ED25519 CERT-----", "-----END ED25519 CERT-----", 1)

    id_cert   = parse_ed_cert(id_raw)
    ntor_cert = parse_ed_cert(ntor_raw)

    CERT_TYPE_ONION_ID = 0x0A  # Tor 源码里就是 0x0A

    # 1) 类型
    if ntor_cert.cert_type != CERT_TYPE_ONION_ID:
        print("FAIL: cert_type =", ntor_cert.cert_type)
    else:
        print("cert_type OK")

    # 2) cert->signed_key == identity cert的 signing_key
    signing_pk = builder.signing_ed_pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if ntor_cert.signed_key != signing_pk:
        print("FAIL: signed_key mismatch")
        print("ntor_cert.signed_key :", ntor_cert.signed_key.hex())
        print("signing_pk           :", signing_pk.hex())
    else:
        print("signed_key == signing_pk OK")


    # 3) 扩展内容必须是 “signed-with-ed25519-key” (len=32, type=4, flags=0)
    def parse_ntor_ext(body: bytes):
        off = 7 + 32  # hdr(7) + signed_key(32)
        n_ext = body[off];
        off += 1
        if n_ext != 1:
            raise AssertionError(f"n_ext={n_ext}")
        ext_len, ext_type, ext_flags = struct.unpack(">HBB", body[off:off + 4]);
        off += 4
        ext_data = body[off:off + ext_len];
        off += ext_len
        return ext_len, ext_type, ext_flags, ext_data


    ext_len, ext_type, ext_flags, ext_data = parse_ntor_ext(ntor_cert.body)
    if not (ext_len == 32 and ext_type == 4 and ext_flags == 0):
        print("FAIL: ntor ext header", ext_len, ext_type, ext_flags)
    else:
        print("ntor ext header OK")

    # 4) ext_data == 由 ntor-onion-key 转换得到的 ed 公钥
    sign_bit = int(find_line(desc, "ntor-onion-key-crosscert").split()[1])
    curve_pub = b64fix(find_line(desc, "ntor-onion-key").split()[1])
    ed_from_curve = curve25519_pub_to_ed25519_pub(curve_pub, sign_bit)
    if ext_data != ed_from_curve:
        print("FAIL: ext_data != ed_from_curve")
        print("ext_data      :", ext_data.hex())
        print("ed_from_curve :", ed_from_curve.hex())
    else:
        print("ext_data == ed_from_curve OK")

    # 5) 用 ext_data 作公钥验证 ntor_cert 的签名
    ok_ntor_sig = ed_verify(ed_from_curve, ntor_cert.body, ntor_cert.signature)
    print("ntor cert signature :", "OK" if ok_ntor_sig else "FAIL")
    # === 原先的 ok1a/ok1b 可以用上述断言替掉，或者保留打印 ===

    # 在你已有的 parse 之后
    id_cert = parse_ed_cert(id_raw)
    ntor_cert = parse_ed_cert(ntor_raw)

    # 目录端的那个 cert->signing_key 就是 id_cert.signed_key
    signing_key_from_identity = id_cert.signed_key

    # 1) 类型
    print("ntor cert_type:", hex(ntor_cert.cert_type))
    print("expect 0x0A   :", hex(0x0A))

    # 2) signed_key 一致性（严格用 identity cert 里的）
    ok_signed = (ntor_cert.signed_key == signing_key_from_identity)
    print("signed_key == identity.signing_key :", "OK" if ok_signed else "FAIL")
    if not ok_signed:
        print("ntor_cert.signed_key :", ntor_cert.signed_key.hex())
        print("identity.signing_key :", signing_key_from_identity.hex())

    # 解析扩展
    ext_len, ext_type, ext_flags, ext_data = parse_ntor_ext(ntor_cert.body)

    # Tor 预期：32,4,0
    print("ext header:", ext_len, ext_type, ext_flags)

    # 用 ext_data 验证签名
    ok_ntor_sig = ed_verify(ext_data, ntor_cert.body, ntor_cert.signature)
    print("ntor cert signature (with ext_data pk):", "OK" if ok_ntor_sig else "FAIL")

    signing_pk = builder.signing_ed_pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    master_pk  = master_ed_pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    # check[0]
    ok0 = ed_verify(master_pk, id_cert.body, id_cert.signature)
    print("check[0] identity cert signature :", "OK" if ok0 else "FAIL")

    # master-key-ed25519
    mk_line = find_line(desc, "master-key-ed25519")
    mk = b64fix(mk_line.split()[1])
    print("master-key-ed25519 == master_pk   :", "OK" if mk == master_pk else "FAIL")

    # check[1]
    ntor_line = find_line(desc, "ntor-onion-key-crosscert")
    sign_bit = int(ntor_line.split()[1])
    curve_pub = b64fix(find_line(desc, "ntor-onion-key").split()[1])
    ntor_ed_from_curve = curve25519_pub_to_ed25519_pub(curve_pub, sign_bit)



    ok1a = (ntor_cert.signed_key == signing_pk)   # Tor 要求 == cert->signing_key
    ok1b = ed_verify(ntor_ed_from_curve, ntor_cert.body, ntor_cert.signature)
    print("check[1] signed_key==signing_pk   :", "OK" if ok1a else "FAIL")
    print("check[1] ntor cert signature      :", "OK" if ok1b else "FAIL")



    # check[2]
    digest, sig = calc_router_digest(desc)
    ok2 = ed_verify(signing_pk, digest, sig)
    print("check[2] router-sig-ed25519       :", "OK" if ok2 else "FAIL")

    if not ok1a or not ok1b:
        print("\n--- ntor cert debug ---")
        print("signed_key (cert) :", ntor_cert.signed_key.hex())
        print("signing_pk        :", signing_pk.hex())
        print("ntor_ed_from_curve:", ntor_ed_from_curve.hex())

    if not ok2:
        print("\n--- router-sig debug ---")
        print("digest:", digest.hex())
        print("sig   :", sig.hex())

    if ok0 and ok1a and ok1b and ok2:
        print("\n=== ALL THREE CHECKS PASS ===")

