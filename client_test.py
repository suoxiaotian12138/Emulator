#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Async Tor directory server (aiohttp version)
"""
import asyncio, argparse, base64, hashlib, json, os, secrets, shutil, tempfile, zlib
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path

from aiohttp import web
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding

KEY_DIR = Path("./tor_keys")
KEY_DIR.mkdir(exist_ok=True)


class TorDirectoryServer:
    # --------------------------------------------------------------------- #
    # lifecycle
    # --------------------------------------------------------------------- #
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port

        # dynamic state
        self._descriptor_dir_obj = tempfile.TemporaryDirectory(prefix="tor_desc_")
        self._descriptor_dir = Path(self._descriptor_dir_obj.name)
        self._descriptor_cache = {}
        self._cached_consensus_map = {}
        self._cached_microdesc_map = {}
        self._cached_key_cert: str | None = None

        # static config
        self._server_cfg = {
            "nickname": "tordir",
            "address": host,
            "or_port": 9001,
            "dir_port": port,
            "contact": "test@local.net",
            "tor_version": "0.4.8.17",
        }

        # keys
        (
            self._authority_key,
            self._signing_key,
            self._authority_fp,
            self._signing_fp,
        ) = self._init_keys()

        # aiohttp app
        self.app = web.Application()
        self._setup_routes()

    # --------------------------------------------------------------------- #
    # key handling
    # --------------------------------------------------------------------- #
    def _init_keys(self):
        auth_file = KEY_DIR / "authority_key.pem"
        sign_file = KEY_DIR / "signing_key.pem"

        if auth_file.exists() and sign_file.exists():
            with open(auth_file, "rb") as f:
                authority_key = serialization.load_pem_private_key(f.read(), None)
            with open(sign_file, "rb") as f:
                signing_key = serialization.load_pem_private_key(f.read(), None)
        else:
            print("[*] generate fresh RSA key-pairs")
            authority_key = rsa.generate_private_key(65537, 2048)
            signing_key = rsa.generate_private_key(65537, 2048)
            auth_file.write_bytes(
                authority_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
            sign_file.write_bytes(
                signing_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

        def fp(priv):
            der = priv.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.PKCS1
            )
            return hashlib.sha1(der).hexdigest().upper()

        return authority_key, signing_key, fp(authority_key), fp(signing_key)

    # --------------------------------------------------------------------- #
    # helpers
    # --------------------------------------------------------------------- #
    @staticmethod
    def _raw_pkcs1_sign(privkey, digest: bytes) -> bytes:
        k = privkey.key_size >> 3
        padded = b"\x00\x01" + b"\xFF" * (k - len(digest) - 3) + b"\x00" + digest
        n, d = (
            privkey.private_numbers().public_numbers.n,
            privkey.private_numbers().d,
        )
        return pow(int.from_bytes(padded, "big"), d, n).to_bytes(k, "big")

    @staticmethod
    def _rounded(t: datetime | None = None, minutes: int = 1) -> datetime:
        t = t or datetime.utcnow()
        return t.replace(minute=(t.minute // minutes) * minutes, second=0, microsecond=0)

    def _get_base64_digest_of_pubkey(self, private_key):
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        )
        return base64.b64encode(hashlib.sha1(pub_der).digest()).decode()

    # --------------------------------------------------------------------- #
    # consensus / microdesc / certificate builders  —— 与原实现一致，略去注释
    # --------------------------------------------------------------------- #
    def _build_authority_block(self, vote_digest_hex: str) -> str:
        cfg = self._server_cfg
        return (
            f"dir-source {cfg['nickname']} {self._authority_fp} "
            f"{cfg['address']} {cfg['address']} {cfg['dir_port']} {cfg['or_port']}\n"
            f"contact {cfg['contact']}\n"
            f"vote-digest {vote_digest_hex}"
        )

    def _b64_pubkey_digest(self, priv) -> str:
        der = priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
        return base64.b64encode(hashlib.sha1(der).digest()).decode()

    def _generate_consensus_content(self):
        now = datetime.utcnow()
        valid_after = self._rounded(now)
        fresh_until = valid_after + timedelta(minutes=1)
        valid_until = valid_after + timedelta(minutes=3)

        # ---------- header ----------
        header = f"""network-status-version 3
vote-status consensus
consensus-method 33
valid-after {valid_after:%Y-%m-%d %H:%M:%S}
fresh-until {fresh_until:%Y-%m-%d %H:%M:%S}
valid-until {valid_until:%Y-%m-%d %H:%M:%S}
voting-delay 20 20
client-versions 
server-versions 
known-flags Authority Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-client-protocols Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
params AuthDirMaxServersPerAddr=2 CircuitPriorityHalflifeMsec=30000 NumDirectoryGuards=3 NumEntryGuards=1 NumNTorsPerTAP=100 Support022HiddenServices=0 UseNTorHandshake=1
{self._build_authority_block("0" * 40)}
"""

        parts = [header]

        # ---------- authority itself ----------
        ident_self = self._get_base64_digest_of_pubkey(self._authority_key)
        desc_self = base64.b64encode(secrets.token_bytes(20)).decode()
        published_self = (now - timedelta(minutes=18)).strftime('%Y-%m-%d %H:%M:%S')

        parts.append(
            f"r {self._server_cfg['nickname']} {ident_self} {desc_self} {published_self} "
            f"{self._server_cfg['address']} {self._server_cfg['or_port']} {self._server_cfg['dir_port']}\n"
            "s Authority Fast Guard HSDir Running Stable V2Dir Valid\n"
            f"v Tor {self._server_cfg['tor_version']}\n"
            "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
            "w Bandwidth=1000 Measured=1000\n"
            "p reject 1-65535\n"
        )

        # ---------- cached relays ----------
        for fp, info in self._descriptor_cache.items():
            parts.append(
                f"r {info['nick']} {info['ident_b64']} {info['desc_b64']} {info['published']} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                "s Running Valid\n"
                "v Tor 0.4.8.x\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
                "p reject 1-65535\n"
            )
        # ---------- footer ----------
        parts.append("""directory-footer
bandwidth-weights Wbd=3333 Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 Web=10000 Wed=3333 Wee=10000 Weg=3333 Wem=10000
""")

        consensus = "".join(parts)

        # ---------- vote-digest ----------
        digest_hex = hashlib.sha1(consensus.encode()).hexdigest().upper()
        consensus = consensus.replace("0" * 40, digest_hex, 1)

        return consensus

    def _generate_microdesc_content(self):
        now = datetime.utcnow()
        valid_after = self._rounded(now)
        fresh_until = valid_after + timedelta(minutes=1)
        valid_until = valid_after + timedelta(minutes=3)

        header = f"""network-status-version 3 microdesc
vote-status consensus
consensus-method 33
valid-after {valid_after:%Y-%m-%d %H:%M:%S}
fresh-until {fresh_until:%Y-%m-%d %H:%M:%S}
valid-until {valid_until:%Y-%m-%d %H:%M:%S}
voting-delay 20 20
client-versions 
server-versions 
known-flags Authority Exit Fast Guard HSDir NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-client-protocols Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
params AuthDirMaxServersPerAddr=2 CircuitPriorityHalflifeMsec=30000
{self._build_authority_block("0" * 40)}
"""

        parts = [header]

        # authority itself
        ident_self = self._get_base64_digest_of_pubkey(self._authority_key)
        published_self = (now - timedelta(minutes=18)).strftime('%Y-%m-%d %H:%M:%S')

        parts.append(
            f"r {self._server_cfg['nickname']} {ident_self} {published_self} "
            f"{self._server_cfg['address']} {self._server_cfg['or_port']} {self._server_cfg['dir_port']}\n"
            f"m {base64.b64encode(secrets.token_bytes(32)).decode()}\n"
            "s Authority Fast Guard HSDir Running Stable V2Dir Valid\n"
            "v Tor 0.4.8.x\n"
            "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
            "w Bandwidth=1000 Measured=1000\n"
        )

        # other relays
        for fp, info in self._descriptor_cache.items():
            parts.append(
                f"r {info['nick']} {info['ident_b64']} {info['published']} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                f"m {info['desc_b64']}\n"
                "s Running Valid\n"
                "v Tor 0.4.8.x\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
            )

        parts.append("directory-footer\n")

        micro = "".join(parts)
        digest_hex = hashlib.sha1(micro.encode()).hexdigest().upper()
        micro = micro.replace("0" * 40, digest_hex, 1)
        return micro

    def _add_signature(self, content: str) -> str:
        """
            为 v3 共识/投票添加 Tor 规范的 directory-signature 块
              • 签名算法：裸 PKCS#1 v1.5 + 20 字节 SHA-1（无 DigestInfo）
              • directory-signature 行 **单独一行**，后跟 BEGIN/END 包裹的 base64，
                每行最多 64 个字符
        """

        if not content.endswith('\n'):
            content += '\n'
        signed_prefix = content + "directory-signature "
        doc_digest = hashlib.sha1(signed_prefix.encode('utf-8')).digest()

        sig_raw = self._raw_pkcs1_sign(self._signing_key, doc_digest)
        sig_b64 = base64.b64encode(sig_raw).decode()
        sig_lines = "\n".join(sig_b64[i:i + 64] for i in range(0, len(sig_b64), 64))

        return (
            f"{content}"
            f"directory-signature {self._authority_fp} {self._signing_fp}\n"
            "-----BEGIN SIGNATURE-----\n"
            f"{sig_lines}\n"
            "-----END SIGNATURE-----\n"
        )

    def _add_signature_micro(self, content: str) -> str:
        """
            为 v3 共识/投票添加 Tor 规范的 directory-signature 块
              • 签名算法：裸 PKCS#1 v1.5 + 20 字节 SHA-1（无 DigestInfo）
              • directory-signature 行 **单独一行**，后跟 BEGIN/END 包裹的 base64，
                每行最多 64 个字符
        """
        if not content.endswith('\n'):
            content += '\n'
        signed_prefix = content + "directory-signature "
        doc_digest = hashlib.sha1(signed_prefix.encode('utf-8')).digest()

        sig_raw = self._raw_pkcs1_sign(self._signing_key, doc_digest)
        sig_b64 = base64.b64encode(sig_raw).decode()
        sig_lines = "\n".join(sig_b64[i:i + 64] for i in range(0, len(sig_b64), 64))

        return (
            f"{content}"
            f"directory-signature sha256 {self._authority_fp} {self._signing_fp}\n"
            "-----BEGIN SIGNATURE-----\n"
            f"{sig_lines}\n"
            "-----END SIGNATURE-----\n"
        )

    def _build_key_certificate(self) -> str:
        utc_now = datetime.utcnow()
        published = utc_now.strftime('%Y-%m-%d %H:%M:%S')
        expires = (utc_now + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')

        # 公钥 PEM 拆成行，保持尾部换行
        # ---------- 生成公钥 PEM 行 ----------
        id_pem_lines = self._authority_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1
        ).decode().strip('\n').splitlines()  # ← 按行拆开，保留最后换行

        sign_pem_lines = self._signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1
        ).decode().strip('\n').splitlines()

        # ---------- 组装正文 ----------
        lines = [
            "dir-key-certificate-version 3",
            f"fingerprint {self._authority_fp}",
            f"dir-key-published {published}",
            f"dir-key-expires {expires}",
            "dir-identity-key",
            *id_pem_lines,
            "dir-signing-key",
            *sign_pem_lines,
        ]

        id_key_der = self._authority_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1  # ← 必须是 PKCS1
        )
        id_digest = hashlib.sha1(id_key_der).digest()

        cross_sig = self._raw_pkcs1_sign(self._signing_key, id_digest)
        cross_b64 = base64.b64encode(cross_sig).decode()
        cross_blk = "\n".join(cross_b64[i:i + 64] for i in range(0, len(cross_b64), 64))

        lines += [
            "dir-key-crosscert",
            "-----BEGIN ID SIGNATURE-----",
            cross_blk,
            "-----END ID SIGNATURE-----",
            "dir-key-certification",
        ]

        # ---------- certification 签名：只到 crosscert 块为止 ----------
        cert_body_only = "\n".join(lines) + "\n"
        cert_body_only = cert_body_only.replace('\r', '')  # 强制消除 CR

        doc_digest = hashlib.sha1(cert_body_only.encode()).digest()
        cert_sig = self._raw_pkcs1_sign(self._authority_key, doc_digest)
        cert_b64 = base64.b64encode(cert_sig).decode()
        cert_blk = "\n".join(cert_b64[i:i + 64] for i in range(0, len(cert_b64), 64))

        lines += [
            "-----BEGIN SIGNATURE-----",
            cert_blk,
            "-----END SIGNATURE-----",
        ]

        return "\n".join(lines) + "\n"

    # --------------------------------------------------------------------- #
    # GET handlers
    # --------------------------------------------------------------------- #
    async def _handle_consensus(self, request: web.Request) -> web.Response:
        z = request.path.endswith(".z")
        rounded = self._rounded()
        if rounded not in self._cached_consensus_map:
            raw = self._generate_consensus_content()
            self._cached_consensus_map[rounded] = self._add_signature(raw)
        data = self._cached_consensus_map[rounded].encode()
        if z:
            data = zlib.compress(data)
            return web.Response(body=data, headers={"Content-Encoding": "deflate"})
        return web.Response(text=self._cached_consensus_map[rounded])

    async def _handle_micro(self, request: web.Request) -> web.Response:
        z = request.path.endswith(".z")
        rounded = self._rounded()
        if rounded not in self._cached_microdesc_map:
            raw = self._generate_microdesc_content()
            self._cached_microdesc_map[rounded] = self._add_signature_micro(raw)
        data = self._cached_microdesc_map[rounded].encode()
        if z:
            data = zlib.compress(data)
            return web.Response(body=data, headers={"Content-Encoding": "deflate"})
        return web.Response(text=self._cached_microdesc_map[rounded])

    async def _handle_key_cert(self, request: web.Request) -> web.Response:
        if not self._cached_key_cert:
            self._cached_key_cert = self._build_key_certificate()
        txt = self._cached_key_cert
        z = request.path.endswith(".z")
        if z:
            return web.Response(
                body=zlib.compress(txt.encode()),
                headers={"Content-Encoding": "deflate"},
            )
        return web.Response(text=txt)

    async def _handle_authority_meta(self, _request: web.Request) -> web.Response:
        return web.json_response(
            {
                "authority_fingerprint": self._authority_fp,
                "signing_fingerprint": self._signing_fp,
                **self._server_cfg,
            }
        )

    async def _handle_root(self, request: web.Request) -> web.Response:
        params = request.rel_url.query
        if request.path == "/hello":
            name = params.get("name", "World")
            return web.json_response({"message": f"Hello, {name}!"})
        if request.path == "/time":
            return web.json_response(
                {"current_time": datetime.utcnow().strftime("%F %T")}
            )
        # default index
        return web.json_response(
            {
                "message": "Tor directory (async) ok",
                "authority_fp": self._authority_fp,
                "signing_fp": self._signing_fp,
            }
        )

    # --------------------------------------------------------------------- #
    # POST handler  —— 上传节点描述符
    # --------------------------------------------------------------------- #
    async def _handle_descriptor_upload(self, request: web.Request) -> web.Response:
        raw = (await request.read()).decode()
        print(">>> descriptor received\n", raw.splitlines()[:6], "...\n")

        fp_hex = nick = or_addr = or_port = dir_port = published = None
        for ln in raw.splitlines():
            if ln.startswith("router "):
                _, nick, or_addr, or_port, *_ = ln.split()
            elif ln.startswith("fingerprint "):
                fp_hex = ln.split(None, 1)[1].replace(" ", "")
            elif ln.startswith("published "):
                published = ln.split(None, 1)[1]
            elif ln.startswith("or-address ") and "[" not in ln:
                or_addr, or_port = ln.split()[1].rsplit(":", 1)
            elif ln.startswith("dir-port "):
                dir_port = ln.split()[1]
        if not fp_hex:
            raise web.HTTPBadRequest(text="missing fingerprint")

        desc_b64 = base64.b64encode(hashlib.sha1(raw.encode()).digest()).decode()
        ident_b64 = base64.b64encode(bytes.fromhex(fp_hex)).decode()
        self._descriptor_cache[fp_hex] = {
            "text": raw,
            "desc_b64": desc_b64,
            "ident_b64": ident_b64,
            "published": published,
            "or_addr": or_addr or request.remote,
            "or_port": or_port or "9001",
            "dir_port": dir_port or "0",
            "nick": nick or "Unnamed",
        }
        # persist to tmp file
        (self._descriptor_dir / f"{fp_hex}.desc").write_text(raw, "utf-8")
        return web.Response(text="OK")

    # --------------------------------------------------------------------- #
    # routing
    # --------------------------------------------------------------------- #
    def _setup_routes(self):
        r = self.app.router
        # GET
        r.add_get("/", self._handle_root)
        r.add_get("/hello", self._handle_root)
        r.add_get("/time", self._handle_root)
        r.add_get("/tor/status-vote/current/consensus/{rest:.*}", self._handle_consensus)
        r.add_get("/tor/status-vote/current/consensus-microdesc/{rest:.*}", self._handle_micro)
        r.add_get("/tor/keys/authority", self._handle_authority_meta)
        r.add_get(r"/tor/keys/{_:(fp/.*|fp-sk/.*)}", self._handle_key_cert)
        r.add_get(r"/tor/keys/{_:(fp/.*|fp-sk/.*)}.z", self._handle_key_cert)
        # POST
        r.add_post("/tor/", self._handle_descriptor_upload)

    # --------------------------------------------------------------------- #
    # run
    # --------------------------------------------------------------------- #
    def run(self):
        web.run_app(
            self.app,
            host=self.host,
            port=self.port,
            print=lambda *a: None,  # mute aiohttp banner
        )


# ------------------------------------------------------------------------- #
# entry
# ------------------------------------------------------------------------- #
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.66.241")
    p.add_argument("--port", type=int, default=9030)
    args = p.parse_args()

    srv = TorDirectoryServer(args.host, args.port)
    print(f"[*] async Tor directory running on http://{args.host}:{args.port}")
    try:
        srv.run()
    finally:
        shutil.rmtree(srv._descriptor_dir, ignore_errors=True)
