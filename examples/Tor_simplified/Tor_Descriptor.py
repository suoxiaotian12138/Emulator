from __future__ import annotations

import base64, textwrap, time
import datetime, struct
import hashlib
from textwrap import wrap
from tools.Crypt.key_generator import generate_cert_from_ed25519

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization

EXT_SIGNED_KEY = 4
CERT_TYPE_ONION_ID = 0x0A

class TorDescriptor_build:
    """Minimal Tor relay descriptor generator (no old proto / HS / Conflux)."""

    def __init__(self,
                 nickname: str,
                 ip: str,
                 start_time: float,
                 curve_sk: x25519.X25519PrivateKey,
                 rsa_sk: rsa.RSAPrivateKey,
                 rsa_id_sk: rsa.RSAPrivateKey,
                 rsa_onion_sk: rsa.RSAPrivateKey,
                 master_ed_sk: ed25519.Ed25519PrivateKey,
                 signing_ed_sk: ed25519.Ed25519PrivateKey,
                 or_port: int = 9001,
                 dir_port: int = 0,
                 socks_port: int = 0,
                 exit_policy: str = "reject *:*",
                 ipv6_policy: str | None = None,  # ← 新增
                 sim_flag: str = "sim-flags",
                 sim_ip: str = "8.8.8.8",
                 protocols: str = "Cons=2 Desc=2 DirCache=2 FlowCtrl=2 Link=4-5 LinkAuth=3 Microdesc=2 Padding=2 Relay=4"
                 ):
        self.nickname = nickname
        self.ip = ip
        self.or_port = or_port
        self.dir_port = dir_port
        self.socks_port = socks_port
        self.process_start_time = start_time
        # keys
        self.master_ed_sk = master_ed_sk
        self.master_ed_pk = self.master_ed_sk.public_key()
        self.signing_ed_sk = signing_ed_sk
        self.signing_ed_pk = self.signing_ed_sk.public_key()
        self.curve_sk = curve_sk
        self.curve_pk = self.curve_sk.public_key()
        self.rsa_sk = rsa_sk
        self.rsa_id_sk = rsa_id_sk
        self.rsa_onion_sk = rsa_onion_sk

        self.reject_rules, self.accept_rules = parse_exit_policy(exit_policy)
        self.ipv6_policy = ipv6_policy
        self.protocols = protocols
        self.sim_flag = sim_flag
        self.sim_ip = f"opt sim-ip {sim_ip}"
        self.last_sign_bit = None


    # ----------------- public API -----------------
    def build(self, variant: str = "AUTO") -> str:
        # ---------- static fields ----------
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        identity_crt = self._make_ed_cert_block()
        master_key = base64.b64encode(
            self.master_ed_pk.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw)
        ).decode().rstrip('=')
        fingerprint = self._sha1_fingerprint(self.rsa_id_sk)

        ntor_onion_key = base64.b64encode(
            self.curve_pk.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw)
        ).decode().rstrip('=')

        extra_info = self._make_extra_info(ts)
        sha1 = hashlib.sha1(extra_info).hexdigest().upper()
        sha256b = hashlib.sha256(extra_info).digest()
        sha256 = base64.b64encode(sha256b).decode().rstrip('=')
        extra_digest_line = f"extra-info-digest {sha1} {sha256}"

        # ---------- core lines (到 ntor-onion-key) ----------
        lines = [
            f"router {self.nickname} {self.ip} {self.or_port} {self.socks_port} {self.dir_port}",
            "identity-ed25519",
            identity_crt,
            f"master-key-ed25519 {master_key}",
            "platform Tor 0.4.8.17 on Linux",
            f"proto {self.protocols}",
            f"published {ts}",
            f"fingerprint {fingerprint}",
            f"uptime {int(time.time() - self.process_start_time)}",
            f"bandwidth 52428800 78643200 31457280",
            extra_digest_line,
            *self._make_rsa_key_block("onion-key", self.rsa_onion_sk),
            *self._make_rsa_key_block("signing-key", self.rsa_id_sk),
            "onion-key-crosscert",
            self._make_crosscert_block(),
            f"ntor-onion-key {ntor_onion_key}",
            *self._make_ntor_crosscert_block(),
            "contact youremail@example.com",
        ]

        # ---------- exit policy ----------
        for r in self.reject_rules:
            lines.append(f"reject {r}")
        for a in self.accept_rules:
            lines.append(f"accept *:{a}")
        if not self.reject_rules or self.reject_rules[-1] != "*:*":
            lines.append("reject *:*")

        # ---------- IPv6 policy ----------
        if self.ipv6_policy:
            lines.append(f"ipv6-policy {self.ipv6_policy}")

        lines.append(f"opt sim-flags {self.sim_flag }")

        # ---------- signatures ----------
        prefix = b"Tor router descriptor signature v1"

        # ① 先把到目前为止的所有行拼好，并在末尾加上占位串："router-sig-ed25519 "
        desc_head = "\n".join(lines) + "\nrouter-sig-ed25519 "  # 注意结尾有空格
        signed_part_bytes = desc_head.encode("ascii")

        digest = hashlib.sha256(prefix + signed_part_bytes).digest()
        sig_ed = base64.b64encode(self.signing_ed_sk.sign(digest)).decode().rstrip("=")

        # ② 真正写入 router-sig-ed25519 行
        lines.append(f"router-sig-ed25519 {sig_ed}")

        # ③ RSA 块
        lines.append("router-signature")
        signed_part_for_rsa = "\n".join(lines) + "\n"
        digest20 = hashlib.sha1(signed_part_for_rsa.encode("ascii")).digest()
        rsa_sig = _rsa_pkcs1_v1_5_sign_raw(digest20, self.rsa_id_sk)
        lines += [
            "-----BEGIN SIGNATURE-----",
            self._b64(rsa_sig),
            "-----END SIGNATURE-----",
        ]

        desc = "\n".join(lines) + "\n"
        desc = desc.replace("\r\n", "\n")

        return desc


    def _dump_ntor_vs_id(self, id_raw, ntor_raw):
        def parse(raw):
            off = 0
            v, t, exp, kt = struct.unpack(">BBIB", raw[off:off + 7]);
            off += 7
            signed_key = raw[off:off + 32];
            off += 32
            n_ext = raw[off];
            off += 1
            ln, typ, flg = struct.unpack(">HBB", raw[off:off + 4]);
            off += 4
            ext = raw[off:off + ln];
            off += ln
            body = raw[:off]
            sig = raw[off:off + 64]
            return t, signed_key, (ln, typ, flg), ext, body, sig

        t1, sk1, h1, ext1, _, _ = parse(id_raw)
        t2, sk2, h2, ext2, _, _ = parse(ntor_raw)

        print(f"[ID ] type={t1:#x}, signed={sk1.hex()}, ext={h1}, ext_data={ext1.hex()}")
        print(f"[NTOR] type={t2:#x}, signed={sk2.hex()}, ext={h2}, ext_data={ext2.hex()}")
        print("equal signed_key? ", sk1 == sk2)

    # ----------------- helpers -----------------
    @staticmethod
    def _b64(data: bytes, wrap_len: int = 64) -> str:
        """Return base64‑encoded text wrapped every wrap_len chars."""
        return "\n".join(textwrap.wrap(base64.b64encode(data).decode(), wrap_len))


    def _make_ed_cert_block(self) -> str:
        """Re-label the DER cert as an ED25519 CERT block (spec quirk)."""
        raw = self._build_identity_cert()
        b64 = _b64_no_padding(raw)
        return "-----BEGIN ED25519 CERT-----\n" + \
               "\n".join(textwrap.wrap(b64, 64)) + \
               "\n-----END ED25519 CERT-----"

    def _make_rsa_key_block(self, tag: str, rsa_key) -> list[str]:
        pub_pem = rsa_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1).decode().splitlines()
        # Convert PEM header/footer to spec-style
        pub_pem[0] = "-----BEGIN RSA PUBLIC KEY-----"
        pub_pem[-1] = "-----END RSA PUBLIC KEY-----"
        return [tag] + pub_pem

    @staticmethod
    def _sha1_fingerprint(rsa_key: rsa.RSAPrivateKey) -> str:
        der = rsa_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1)
        digest = hashlib.sha1(der).hexdigest().upper()
        return " ".join(wrap(digest, 4))

    def _make_crosscert_block(self) -> str:
        digest20 = hashlib.sha1(
            self.rsa_id_sk.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.PKCS1)
        ).digest()

        blob = digest20 + self.master_ed_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

        sig = _rsa_pkcs1_v1_5_sign_blob(blob, self.rsa_onion_sk)

        return "\n".join([
            "-----BEGIN CROSSCERT-----",
            self._b64(sig),  # 仍然保留 '=' padding
            "-----END CROSSCERT-----",
        ])
    def _make_extra_info(self, ts: str) -> bytes:
        return (f"extra-info {self.nickname} {self._sha1_fingerprint(self.rsa_id_sk)}\n"
                f"published {ts}\n"
                "opt memusage 0\n\n").encode()  # 最后一行必须换行

    def _make_ntor_crosscert_block(self) -> list[str]:
        # 1) curve25519 keys
        curve_sk_bytes = self.curve_sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption()
        )
        curve_pub_bytes = self.curve_pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )

        # 2) 从 curve_sk 得到 Ed25519 标量和公钥（scalar 法）
        a_scalar = scalar_from_curve_sk(curve_sk_bytes)
        pk_calc = encodepoint(scalarmult(B, a_scalar))  # 32B

        # 3) 从 curve_pub 计算出 ext_data，选择 sign_bit 让它等于 pk_calc
        ed0 = curve_pub_to_ed_pub(curve_pub_bytes, 0)
        ed1 = curve_pub_to_ed_pub(curve_pub_bytes, 1)

        if pk_calc == ed0:
            ext_data = ed0
            sign_bit = 0
        elif pk_calc == ed1:
            ext_data = ed1
            sign_bit = 1
        else:
            # 真不一致再报错；打印调试信息
            raise AssertionError("pk_calc != ed_from_u(bit=0/1)，请检查 curve_pub_to_ed_pub 或 scalar 实现")

        # 4) 证书体
        now_hr = int(time.time() // 3600)
        exp_hr = now_hr + 24 * 7

        body = struct.pack(">BBIB", 1, CERT_TYPE_ONION_ID, exp_hr, 1)
        body += self.master_ed_pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        body += struct.pack(">B", 1)  # N_EXTENSIONS = 1
        body += _ext_signed_with(ext_data)  # LEN=32, TYPE=4, FLAGS=0, DATA

        # 5) 签名：用 a_scalar + ext_data 做标准 Ed25519 签名
        sig = ed_sign_from_scalar(body, a_scalar, ext_data)

        cert_raw = body + sig
        b64 = _b64_no_padding(cert_raw)

        self.last_sign_bit = sign_bit
        return [
            f"ntor-onion-key-crosscert {sign_bit}",
            "-----BEGIN ED25519 CERT-----",
            b64,
            "-----END ED25519 CERT-----",
        ]

    def _make_router_sig(self, lines_before_sig: list[str]) -> str:
        """
        Tor 规范：
          msg = "Tor router descriptor signature v1" || (descriptor_text_up_to_router-sig-ed25519_line + "\n")
        lines_before_sig: 还未包含 router-sig-ed25519 / router-signature 的所有行列表
        """
        prefix = b"Tor router descriptor signature v1"
        signed_part = ("\n".join(lines_before_sig) + "\n").encode("ascii")
        digest = hashlib.sha256(prefix + signed_part).digest()
        sig = self.signing_ed_sk.sign(digest)
        return base64.b64encode(sig).decode().rstrip("=")

    @staticmethod
    def _fake_router_sig() -> str:
        return base64.b64encode(hashlib.sha256(b"router-sig").digest())[:56].decode()

    def _make_rsa_signature_block(self, desc_so_far: str) -> list[str]:
        # ① 计算一次 SHA‑1
        digest = hashlib.sha1(desc_so_far.encode("utf-8")).digest()

        # ② 原始 PKCS#1 v1.5 签名（无 DigestInfo）
        sig = _rsa_pkcs1_v1_5_sign_raw(digest, self.rsa_id_sk)

        return [
            "router-signature",
            "-----BEGIN SIGNATURE-----",
            self._b64(sig),
            "-----END SIGNATURE-----",
        ]

    def _build_identity_cert(self) -> bytes:
        VERSION, CERT_TYPE, KEYTYPE = 1, 4, 1
        now_hr = int(time.time() // 3600)
        exp_hr = now_hr + 24 * 7

        body = struct.pack(">BBIB", VERSION, CERT_TYPE, exp_hr, KEYTYPE)
        body += self.signing_ed_pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        body += struct.pack(">B", 1)  # N_EXTENSIONS = 1
        body += _ext_signed_with(self.master_ed_pk)  # 35 B

        sig = self.master_ed_sk.sign(body)  # 64 B
        return body + sig

def parse_exit_policy(policy_line: str) -> tuple[list[str], list[str]]:
    """
    Parse a single Tor 'p' line (e.g., 'accept 80,443') into accept/reject rule lists.
    """
    policy_line = policy_line.strip()
    if not policy_line:
        return [], []

    if policy_line.startswith("accept"):
        rules = policy_line[len("accept"):].strip().split(",")
        return [], [r.strip() for r in rules]

    elif policy_line.startswith("reject"):
        rules = policy_line[len("reject"):].strip().split(",")
        return [r.strip() for r in rules], []

    else:
        raise ValueError(f"Unsupported exit policy line: {policy_line}")

def _build_ntor_crosscert(curve_sk, master_ed_pk):
    seed = curve_sk.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    ed_sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    ed_pk = ed_sk.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)

    now_hr = int(time.time() // 3600)
    exp_hr = now_hr + 24*7

    body  = struct.pack(">BBIB", 1, 0x0A, exp_hr, 1)  # VERSION,TYPE,EXP,KEYTYPE
    body += master_ed_pk
    body += struct.pack(">B", 1)                # N_EXTENSIONS = 1
    body += _ext_signed_with(ed_pk)             # 35 B

    sig = ed_sk.sign(body)
    return body + sig                           # 139 B


def _ext_signed_with(pubkey) -> bytes:
    """
    signed-with-ed25519-key 扩展：符合 Tor 源码
      LEN(2)=32, TYPE(1)=4, FLAGS(1)=0, DATA(32)=pubkey_raw
    """
    if not isinstance(pubkey, (bytes, bytearray)):
        pubkey = pubkey.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
    assert len(pubkey) == 32
    # LEN → TYPE → FLAGS → DATA
    return struct.pack(">HBB", 32, 4, 0) + pubkey


def _b64_no_padding(data: bytes, wrap_len: int = 64) -> str:
    encoded = base64.b64encode(data).decode()
    encoded = encoded.rstrip("=")          # <- 必须去掉
    return "\n".join(textwrap.wrap(encoded, wrap_len))

def _rsa_pkcs1_v1_5_sign_raw(digest20: bytes,
                             privkey: rsa.RSAPrivateKey) -> bytes:
    """
    replicate RSA_private_encrypt(..., RSA_PKCS1_PADDING)
    :param digest20: already‑hashed 20‑byte SHA‑1 digest
    :return: full PKCS#1 v1.5 signature block
    """
    if len(digest20) != 20:
        raise ValueError("digest must be 20 bytes")

    numbers = privkey.private_numbers()
    n = numbers.public_numbers.n
    d = numbers.d
    k = (n.bit_length() + 7) // 8           # modulus length in bytes

    # EM = 0x00 0x01 PS 0x00 digest
    ps = b'\xff' * (k - len(digest20) - 3)
    em = b'\x00\x01' + ps + b'\x00' + digest20
    sig_int = pow(int.from_bytes(em, 'big'), d, n)
    return sig_int.to_bytes(k, 'big')



def _rsa_pkcs1_v1_5_sign_blob(msg: bytes, priv: rsa.RSAPrivateKey) -> bytes:
    """
    PKCS#1 v1.5 “RAW” 签名：对任意 msg 直接加 padding 后取 d‑exp。
    (等价于 OpenSSL 的 RSA_private_encrypt(..., RSA_PKCS1_PADDING))
    """
    k = (priv.key_size + 7) // 8            # 模长(字节)
    if len(msg) > k - 11:
        raise ValueError("message too long")

    ps = b'\xff' * (k - len(msg) - 3)
    em = b'\x00\x01' + ps + b'\x00' + msg    # EM
    num = int.from_bytes(em, 'big')

    d = priv.private_numbers().d
    n = priv.private_numbers().public_numbers.n
    sig = pow(num, d, n).to_bytes(k, 'big')
    return sig


def scalar_from_curve_sk(curve_sk_bytes: bytes) -> int:
    """
    把 x25519 私钥(32字节, 已 clamp) 当成一个小端整数，直接 mod L 当 Ed25519 标量。
    Tor 的实现就是这么做的（见 crypto_curve25519.c）。
    """
    return int.from_bytes(curve_sk_bytes, "little") % L

def ed_sign_from_scalar(msg: bytes, a_scalar: int, pk_bytes: bytes) -> bytes:
    """
    用已知标量 a_scalar 和对应的 pk_bytes 做标准 Ed25519 签名。
    参照 RFC8032 算法，只是 seed->a 我们已给出。
    r = H( a_bytes[0:32? 任意常量] || msg ) —— 我们用 a_scalar 的 32 字节编码当作“secret prefix”
    """
    a_bytes = a_scalar.to_bytes(32, "little")
    r = int.from_bytes(hashlib.sha512(a_bytes + msg).digest(), "little") % L
    R = scalarmult(B, r)
    R_enc = encodepoint(R)
    h = int.from_bytes(hashlib.sha512(R_enc + pk_bytes + msg).digest(), "little") % L
    s = (r + h * a_scalar) % L
    return R_enc + s.to_bytes(32, "little")


# ===== helpers for curve<->ed conversions =====

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # Ed25519 subgroup order

b = 256
q = 2**255-19
d = -121665 * pow(121666, q-2, q) % q
I = pow(2, (q-1)//4, q)

def inv(z):  # modular inverse mod P
    return pow(z, P-2, P)

def xrecover(y):
    xx = (y*y-1) * pow(d*y*y+1, q-2, q)
    x = pow(xx, (q+3)//8, q)
    if (x*x - xx) % q != 0:
        x = (x*I) % q
    if x % 2 != 0:
        x = q-x
    return x

def edwards_add(P, Q):
    (x1,y1,z1,t1) = P
    (x2,y2,z2,t2) = Q
    a = (y1-x1)*(y2-x2) % q
    b = (y1+x1)*(y2+x2) % q
    c = t1*2*d*t2 % q
    dd = z1*2*z2 % q
    e = b-a
    f = dd-c
    g = dd+c
    h = b+a
    x3 = e*f % q
    y3 = g*h % q
    t3 = e*h % q
    z3 = f*g % q
    return (x3,y3,z3,t3)

def edwards_double(P):
    (x1,y1,z1,t1) = P
    a = x1*x1 % q
    b = y1*y1 % q
    c = 2*z1*z1 % q
    d_ = -a
    e = ((x1+y1)*(x1+y1)-a-b) % q
    g = d_+b
    f = g-c
    h = d_-b
    x3 = e*f % q
    y3 = g*h % q
    t3 = e*h % q
    z3 = f*g % q
    return (x3,y3,z3,t3)

def scalarmult(P, e):
    Q = (0,1,1,0)
    while e > 0:
        if e & 1:
            Q = edwards_add(Q,P)
        P = edwards_double(P)
        e >>= 1
    return Q

def encodepoint(P):
    (x,y,z,t) = P
    zi = pow(z, q-2, q)
    x = (x*zi) % q
    y = (y*zi) % q
    bits = y.to_bytes(32, "little")
    bits = bytearray(bits)
    bits[31] ^= (x & 1) << 7
    return bytes(bits)


B = (xrecover(4*inv(5) % q), 4*inv(5) % q, 1, (xrecover(4*inv(5) % q)*4*inv(5)) % q)


def curve_pub_to_ed_pub(curve_pub_bytes: bytes, sign_bit: int) -> bytes:
    """
    u(Montgomery) -> y(Edwards): y = (u - 1)/(u + 1) mod p
    """
    u = int.from_bytes(curve_pub_bytes, "little") % P
    num = (u - 1) % P
    den = (u + 1) % P
    y = (num * inv(den)) % P
    y_bytes = bytearray(y.to_bytes(32, "little"))
    y_bytes[31] = (y_bytes[31] & 0x7F) | ((sign_bit & 1) << 7)
    return bytes(y_bytes)








