from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
import base64
import hashlib
import re

# === 加载整个证书文本 ===
with open("cert.txt", "r", encoding="utf-8") as f:
    content = f.read()

lines = content.strip().splitlines()

# === 提取公钥段 ===
def extract_pem_block(lines, begin_marker, end_marker):
    begin = None
    end = None
    for idx, line in enumerate(lines):
        if line.strip() == begin_marker:
            begin = idx
        if line.strip() == end_marker:
            end = idx
            break
    if begin is None or end is None:
        raise ValueError(f"PEM block not found: {begin_marker} to {end_marker}")
    return "\n".join(lines[begin:end+1])

identity_pem = extract_pem_block(lines, "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----")
signing_start = lines.index("dir-signing-key") + 1
signing_pem = extract_pem_block(lines[signing_start:], "-----BEGIN RSA PUBLIC KEY-----", "-----END RSA PUBLIC KEY-----")

identity_pub = serialization.load_pem_public_key(identity_pem.encode())
signing_pub = serialization.load_pem_public_key(signing_pem.encode())

# === 验证 crosscert ===
crosscert_start = lines.index("dir-key-crosscert")
crosscert_base64 = lines[crosscert_start + 2 : lines.index("-----END ID SIGNATURE-----", crosscert_start)]
crosscert_bytes = base64.b64decode("".join(crosscert_base64))

identity_der = identity_pub.public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.PKCS1
)
identity_digest = hashlib.sha1(identity_der).digest()

try:
    signing_pub.verify(
        crosscert_bytes,
        identity_digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA1())
    )
    print("[✓] crosscert 签名验证通过")
except Exception as e:
    print("[✗] crosscert 签名失败：", e)

# === 验证 certification 签名 ===
certification_start = lines.index("dir-key-certification")
cert_base64 = lines[certification_start + 2 : lines.index("-----END SIGNATURE-----", certification_start)]
cert_sig = base64.b64decode("".join(cert_base64))

# 认证签名前的正文部分（直到 crosscert 之前）
cert_body_lines = lines[:crosscert_start]
cert_body = "\n".join(cert_body_lines) + "\n"

try:
    identity_pub.verify(
        cert_sig,
        hashlib.sha1(cert_body.encode()).digest(),
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA1())
    )
    print("[✓] certification 签名验证通过")
except Exception as e:
    print("[✗] certification 签名失败：", repr(e))


