from __future__ import annotations

import base64
import datetime
import hashlib
from textwrap import wrap
from typing import Iterable
from tools.Crypt.key_generator import ed25519_setup, generate_cert_from_ed25519, curve25519_setup

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
                 reject_rules: Iterable[str] | None = None,  # ← 新增
                 accept_rules: Iterable[str] | None = None,  # ← 新增
                 ipv6_policy: str | None = None  # ← 新增

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

        self.reject_rules = list(reject_rules or [])
        self.accept_rules = list(accept_rules or [])
        self.ipv6_policy = ipv6_policy

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
            "proto Cons=2 Desc=2 DirCache=2 FlowCtrl=2 Link=4-5 LinkAuth=3 Microdesc=2 Padding=2 Relay=4",
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
            lines.append(f"accept {a}")
        # 若最后一条不是 *:*，补一个兜底
        if not self.reject_rules or self.reject_rules[-1] != "*:*":
            lines.append("reject *:*")

        # ---------- IPv6 policy ----------
        if self.ipv6_policy:
            lines.append(f"ipv6-policy {self.ipv6_policy}")

        # ---------- signatures ----------
        lines.append(f"router-sig-ed25519 {self._fake_router_sig()}")
        lines.extend(self._make_rsa_signature_block())
        lines.append("sim-flags Guard Exit")

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

from torpy.parsers import RouterDescriptorParser
from torpy.consesus import Descriptor


# ---------------- example usage ----------------
if __name__ == "__main__":
    builder = TorDescriptor_build("mynode", "192.0.2.10")
    descriptor_txt = builder.build()
    print(descriptor_txt)
    descriptor_info = RouterDescriptorParser.parse(descriptor_txt)
    aas = Descriptor(**descriptor_info)
    print(aas)
    print(aas.onion_key)
    print(aas.ntor_key)
    print(aas.signing_key)