from __future__ import annotations

import base64, textwrap,time
import datetime, struct
import hashlib
from textwrap import wrap
from tools.Crypt.key_generator import generate_cert_from_ed25519

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes

CERT_TYPE_NTOR = 0x0A
CERT_LIFETIME  = 7 * 24 * 3600
class TorDescriptor_build:
    """Minimal Tor relay descriptor generator (no old proto / HS / Conflux)."""

    def __init__(self,
                 nickname: str,
                 ip: str,
                 ed_sk,
                 ed_pk,
                 curve_sk,
                 curve_pk,
                 rsa_sk,
                 rsa_id_sk: rsa.RSAPrivateKey,
                 rsa_onion_sk: rsa.RSAPrivateKey,
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
        self.process_start_time = time.time()
        # keys
        self.ed_sk, self.ed_pk = ed_sk, ed_pk
        self.curve_sk, self.curve_pk = curve_sk, curve_pk
        self.rsa_sk = rsa_sk
        self.rsa_id_sk = rsa_id_sk
        self.rsa_onion_sk = rsa_onion_sk

        self.reject_rules, self.accept_rules = parse_exit_policy(exit_policy)
        self.ipv6_policy = ipv6_policy
        self.protocols = protocols
        self.sim_flag = sim_flag
        self.sim_ip = f"opt sim-ip {sim_ip}"

    # ----------------- public API -----------------
    def build(self) -> str:
        # ---------- static fields ----------
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        identity_crt = self._make_ed_cert_block()
        master_key = self._b64(self.ed_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        fingerprint = self._sha1_fingerprint(self.rsa_id_sk)

        ntor_onion_key = base64.b64encode(
            self.curve_pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        ).decode().rstrip('=')

        extra_info = self._make_extra_info(ts)  # ➊ 先生成一份 extra‑info
        sha1 = hashlib.sha1(extra_info).hexdigest().upper()
        sha256b = hashlib.sha256(extra_info).digest()
        sha256 = base64.b64encode(sha256b).decode().rstrip('=')
        extra_digest_line = f"extra-info-digest {sha1} {sha256}"

        # ---------- core lines (至 ntor-onion-key) ----------
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
            *self._make_rsa_key_block("onion-key",  self.rsa_onion_sk),
            *self._make_rsa_key_block("signing-key", self.rsa_id_sk),
            "onion-key-crosscert",
            self._make_crosscert_block(),
            f"ntor-onion-key {ntor_onion_key}",
            *self._make_ntor_crosscert_block(),
            "contact youremail@example.com",
        ]


        # ---------- exit policy (IPv4) ----------
        for r in self.reject_rules:
            lines.append(f"reject {r}")
        for a in self.accept_rules:
            lines.append(f"accept *:{a}")
        # 若最后一条不是 *:*，补一个兜底
        if not self.reject_rules or self.reject_rules[-1] != "*:*":
            lines.append("reject *:*")

        # ---------- IPv6 policy ----------
        if self.ipv6_policy:
            lines.append(f"ipv6-policy {self.ipv6_policy}")

        # ---------- sim info ----------
        lines.append(self.sim_flag)
        lines.append(self.sim_ip)

        # ---------- signatures ----------
        signed_text = "\n".join(lines) + "\n"
        sig_ed = self._make_router_sig(signed_text)
        lines.append(f"router-sig-ed25519 {sig_ed}")
        lines += self._make_rsa_signature_block(signed_text)

        return "\n".join(lines) + "\n"

    # ----------------- helpers -----------------
    @staticmethod
    def _b64(data: bytes, wrap_len: int = 64) -> str:
        """Return base64‑encoded text wrapped every wrap_len chars."""
        return "\n".join(textwrap.wrap(base64.b64encode(data).decode(), wrap_len))

    def _make_ed_cert_block(self) -> str:
        """Re-label the DER cert as an ED25519 CERT block (spec quirk)."""
        der = generate_cert_from_ed25519(self.ed_sk)
        b64_body = self._b64(der)
        return "\n".join([
            "-----BEGIN ED25519 CERT-----",
            b64_body,
            "-----END ED25519 CERT-----",
        ])

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
            serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashlib.sha1(der).hexdigest().upper()
        grouped = " ".join(wrap(digest, 4))
        return grouped



    def _make_crosscert_block(self) -> str:
    # ④ 依据规范签名 sha1(id_rsa) || master_ed25519

        id_der = self.rsa_id_sk.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1)
        digest20 = hashlib.sha1(id_der).digest()
        signed = digest20 + self.ed_pk.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        sig = self.rsa_onion_sk.sign(signed, padding.PKCS1v15(), hashes.SHA1())
        body = self._b64(sig)
        return "\n".join(["-----BEGIN CROSSCERT-----", body,
                          "-----END CROSSCERT-----"])

    def _make_extra_info(self, ts: str) -> bytes:
        return (f"extra-info {self.nickname} {self._sha1_fingerprint(self.rsa_id_sk)}\n"
                f"published {ts}\n"
                "opt memusage 0\n\n").encode()  # 最后一行必须换行

    def _make_ntor_crosscert_block(self) -> list[str]:
        return ["ntor-onion-key-crosscert 0"]

    def _make_router_sig(self, desc_so_far: str) -> str:
        prefix = b"Tor router descriptor signature v1"
        # 取到 router-sig-ed25519 后的第一个空格
        temp = (desc_so_far + "router-sig-ed25519 ").encode()
        digest = hashlib.sha256(prefix + temp).digest()
        sig = self.ed_sk.sign(digest)
        return base64.b64encode(sig).decode().rstrip("=")

    @staticmethod
    def _fake_router_sig() -> str:
        return base64.b64encode(hashlib.sha256(b"router-sig").digest())[:56].decode()

    def _make_rsa_signature_block(self, desc_so_far: str) -> list[str]:
        sig = self.rsa_id_sk.sign(
            desc_so_far.encode(),
            padding.PKCS1v15(),
            hashes.SHA1())
        return [
            "router-signature",
            "-----BEGIN SIGNATURE-----",
            self._b64(sig),
            "-----END SIGNATURE-----",
        ]


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

def build_ntor_crosscert(curve_sk: x25519.X25519PrivateKey,
                         master_ed_pk_bytes: bytes) -> bytes:
    """
    给定 ntor‑onion‑key (curve_sk) 和 master‑ed25519‑public‑key，
    生成 tor-spec §4.3.3 NTOR cross‑cert (type 10).
    """
    # 1) curve25519 私钥 → 32B 原始 seed
    seed32 = curve_sk.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption())
    ed_sk  = ed25519.Ed25519PrivateKey.from_private_bytes(seed32)

    now  = int(time.time())
    exp  = now + CERT_LIFETIME

    body = struct.pack(">BII", CERT_TYPE_NTOR, now, exp) + master_ed_pk_bytes
    sig  = ed_sk.sign(body)          # 64 B

    return body + sig