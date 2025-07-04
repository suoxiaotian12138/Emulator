from __future__ import annotations

import base64
import datetime
import hashlib
from textwrap import wrap
from typing import Iterable
from tools.Crypt.key_generator import generate_cert_from_ed25519

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding


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
        # keys
        self.ed_sk, self.ed_pk = ed_sk, ed_pk
        self.curve_sk, self.curve_pk = curve_sk, curve_pk
        self.rsa_sk = rsa_sk

        self.reject_rules, self.accept_rules = parse_exit_policy(exit_policy)
        self.ipv6_policy = ipv6_policy
        self.protocols = protocols
        self.sim_flag = sim_flag
        self.sim_ip = 'sim-ip' + sim_ip

    # ----------------- public API -----------------
    def build(self) -> str:
        # ---------- static fields ----------
        ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        identity_crt = self._make_ed_cert_block()
        master_key = self._b64(self.ed_pk.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        fingerprint = self._sha1_fingerprint(self.rsa_sk)

        # ---------- core lines (至 ntor-onion-key) ----------
        lines = [
            f"router {self.nickname} {self.ip} {self.or_port} {self.dir_port} {self.socks_port}",
            "identity-ed25519",
            identity_crt,
            f"master-key-ed25519 {master_key}",
            "platform Tor 0.4.8.x on Python",
            f"proto {self.protocols}",
            f"published {ts}",
            f"fingerprint {fingerprint}",
            "uptime 0",
            "bandwidth 1073741824 1073741824 131072",
            f"extra-info-digest {self._fake_digest()}",
            *self._make_rsa_key_block("onion-key"),
            *self._make_rsa_key_block("signing-key"),
            "onion-key-crosscert",
            self._fake_crosscert_block(),
            f"ntor-onion-key {self._b64(self.curve_pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))}",
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

        # ---------- signatures ----------
        lines.append(f"router-sig-ed25519 {self._fake_router_sig()}")
        lines.extend(self._make_rsa_signature_block())
        lines.append(self.sim_flag)

        return "\n".join(lines) + "\n"

    # ----------------- helpers -----------------
    @staticmethod
    def _b64(data: bytes) -> str:
        """Base64, 64-col soft-wrap per spec."""
        return "".join(wrap(base64.b64encode(data).decode(), 64))

    def _make_ed_cert_block(self) -> str:
        """Re-label the DER cert as an ED25519 CERT block (spec quirk)."""
        der = generate_cert_from_ed25519(self.ed_sk)
        b64_body = self._b64(der)
        return "\n".join([
            "-----BEGIN ED25519 CERT-----",
            b64_body,
            "-----END ED25519 CERT-----",
        ])

    def _make_rsa_key_block(self, tag: str) -> list[str]:
        pub_pem = self.rsa_sk.public_key().public_bytes(
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

    @staticmethod
    def _fake_digest() -> str:
        return hashlib.sha1(b"extra-info").hexdigest().upper() + " " + \
            base64.b64encode(hashlib.sha256(b"extra-info").digest()).decode()[:27]

    @staticmethod
    def _fake_crosscert_block() -> str:
        body = base64.b64encode(b"crosscert").decode()
        return "\n".join([
            "-----BEGIN CROSSCERT-----",
            body,
            "-----END CROSSCERT-----",
        ])

    @staticmethod
    def _fake_router_sig() -> str:
        return base64.b64encode(hashlib.sha256(b"router-sig").digest())[:56].decode()

    def _make_rsa_signature_block(self) -> list[str]:
        # 用 RSA 身份私钥对整个描述符做 PKCS#1 v1.5 + SHA‑1 签名
        sig_bin = self.rsa_sk.sign(
            b"router-descriptor",
            padding.PKCS1v15(),  # ← 必须指定 padding
            hashes.SHA1()  # ← 哈希算法
        )
        sig_b64 = self._b64(sig_bin)
        return [
            "router-signature",
            "-----BEGIN SIGNATURE-----",
            sig_b64,
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