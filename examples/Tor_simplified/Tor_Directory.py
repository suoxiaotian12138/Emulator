import itertools
import gzip
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import re, binascii
import asyncio, argparse, base64, hashlib, json, os, secrets, shutil, tempfile, zlib
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from base64 import urlsafe_b64encode
import io
from cryptography.hazmat.primitives.asymmetric import ed25519
import struct, time

from aiohttp import web
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import x25519

KEY_DIR = Path("./tor_keys")
KEY_DIR.mkdir(exist_ok=True)
_PORT_RE = re.compile(r"(\d+)(?:-(\d+))?$")

_ED_LINE_RE = re.compile(
    r'^\s*master-key-ed25519\s+([A-Za-z0-9+/=]{43,44})\s*$', re.M)

_CERT_RE = re.compile(
    r'^\s*identity-ed25519\s*\n'
    r'\s*-----BEGIN ED25519 CERT-----\s*\n'
    r'(.+?)'
    r'\n\s*-----END ED25519 CERT-----',
    re.S | re.M)


class TorDirectoryServer:
    # --------------------------------------------------------------------- #
    # lifecycle
    # --------------------------------------------------------------------- #
    def __init__(self, host: str, port: int):
        self.host, self.port = host, port

        # dynamic state
        self._descriptor_dir_obj = tempfile.TemporaryDirectory(prefix="tor_desc_")
        self._descriptor_dir = Path(self._descriptor_dir_obj.name)
        self._micro_dir = self._descriptor_dir / "micro"
        self._micro_dir.mkdir()
        self._descriptor_cache = {}
        self._load_seed_descriptors(Path("./seed_descs"))

        self._cached_consensus_map = {}
        self._cached_microdesc_map = {}
        self._cached_consensus_map_deflate = {}
        self._cached_microdesc_map_deflate = {}
        self._cached_key_cert = None
        self._micro_map = {}
        self._network_ready_flag = False
        self._start_time = time.time()
        self._min_uptime = 0  # seconds, 可改参数

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
        self.app = web.Application(middlewares=[self._log_all_requests])
        self._setup_routes()
        self._consensus_dirty = True
        self._micro_dirty = True
        self._ntor_priv, self._ntor_pub_b64 = get_ntor_keypair()

        self._self_desc, self.base_64, self._self_desc_hex, self._self_micro_text, self._self_micro_b64, self._self_p_line, self._self_is_exit = self._make_self_bundle()

        (self._descriptor_dir / f"{self._self_desc_hex}.desc").write_text(
            self._self_desc, 'utf-8')
        self._descriptor_cache[self._authority_fp] = {
            "text": self._self_desc,
            "desc_hex": self._self_desc_hex,
            "desc_b64": self.base_64,
            "ident_b64": base64.b64encode(bytes.fromhex(self._authority_fp)).decode().rstrip('='),
            "published": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            "or_addr": self._server_cfg['address'],
            "or_port": str(self._server_cfg['or_port']),
            "dir_port": str(self._server_cfg['dir_port']),
            "nick": self._server_cfg['nickname'],
            "micro_b64": self._self_micro_b64,
            "p_line": self._self_p_line,
            "is_exit": self._self_is_exit,
            # self relay 不需要 micro_b64 —— 下一步生成
        }



    @web.middleware
    async def _log_all_requests(self, request, handler):
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        # print(f"[{ts}] \"{request.method} {request.path} HTTP/{request.version.major}.{request.version.minor}\"")
        return await handler(request)

    def _derive_status_line(self, desc_text: str, is_exit) -> str:
        """
        根据服务器描述符内容生成 consensus 里的“s …”行。
        规则：
          1) 如果出现“sim-flags …”行，则直接拿其中的 Guard / Exit / Stable
             等标签（大小写忽略），其余逻辑跳过。
          2) 否则：
             • Exit  : exit-policy 中存在 accept
             • Guard : w Bandwidth=NNNN 且 NNNN ≥ 5000
             • Stable: published 时间早于当前 UTC ≥ 1 小时
        始终含 Running Valid，顺序固定 Running Valid Stable Guard Exit
        """
        base = ["Running", "Valid"]
        order = ['Authority', 'BadExit', 'Exit', 'Fast', 'Guard', 'HSDir', 'MiddleOnly', 'NoEdConsensus', 'Running',
                 'Stable', 'StaleDesc', 'Sybil', 'V2Dir', 'Valid']

        fp_self = self._authority_fp
        if fp_self in desc_text:
            return "s Running Valid\n"

        # ---- 1) 自定义 sim-flags 行 ----
        for ln in desc_text.splitlines():
            if ln.lower().startswith("opt sim-flags "):
                tokens = [t for t in ln.split()[1:]]
                flags = [t for t in tokens
                                if t in order]
                # 保序输出
                return "s " + " ".join([f for f in order if f in flags]) + "\n"

        # ---- 2) Heuristics ----
        lines = desc_text.splitlines()
        m_bw = next((re.search(r"bandwidth (\d+) (\d+) (\d+)", ln)
                     for ln in lines if ln.startswith("bandwidth ")), None)
        # 2-a Exit?
        if is_exit:
            base.append("Exit")
            if m_bw:
                avg_bandwidth = int(m_bw.group(1))  # 这是平均带宽，单位字节/秒
                if avg_bandwidth >= 250_0000:  # 250 KB/s ≈ 2000 Kbps（官方最低要求）
                    base.append("Stable")
                if avg_bandwidth >= 100_000:  # 100 kB/s ≈ Tor 默认 Fast 阈值
                    base.append("Fast")
        else:
            if m_bw:
                avg_bandwidth = int(m_bw.group(1))  # 这是平均带宽，单位字节/秒
                if avg_bandwidth >= 250_0000:  # 250 KB/s ≈ 2000 Kbps（官方最低要求）
                    base.append("Guard")
                    base.append("Stable")
                    base.append("Fast")
                elif avg_bandwidth >= 100_000:  # 100 kB/s ≈ Tor 默认 Fast 阈值
                    base.append("MiddleOnly")
                    base.append("Stable")
                    base.append("Fast")
                else:
                    base.append("MiddleOnly")

            has_tundir = any(ln.startswith("tunnelled-dir-server") for ln in lines)
            if has_tundir:
                base.append("V2Dir")
                base.append("HSDir")

        # 2-c Stable?
        m_pub = next((re.search(
            r"published (\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})", ln)
                      for ln in lines if ln.startswith("published ")), None)

        if m_pub:
            try:
                pub_ts = datetime.strptime(
                    f"{m_pub.group(1)} {m_pub.group(2)}",
                    "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() - pub_ts >= timedelta(hours=1):
                    base.append("Stable")
            except ValueError:
                pass

        # ---- 按固定序输出 ----
        return "s " + " ".join([f for f in order if f in base]) + "\n"


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
    def _rounded(t: datetime = None, minutes: int = 1) -> datetime:
        t = t or datetime.utcnow()
        return t.replace(minute=(t.minute // minutes) * minutes, second=0, microsecond=0)

    def _get_base64_digest_of_pubkey(self, private_key):
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        )
        return base64.b64encode(hashlib.sha1(pub_der).digest()).decode().rstrip('=')

    def _sign_data(self, data: str) -> str:
        """用 _signing_key 对文本做 RSA-PKCS1-SHA1 签名，返回 base64"""
        sig = self._signing_key.sign(
            data.encode('utf-8'),
            PKCS1v15(),
            hashes.SHA1()
        )
        return base64.b64encode(sig).decode('ascii')


    def _build_authority_block(self, vote_digest_hex: str) -> str:
        cfg = self._server_cfg
        return (
            f"dir-source {cfg['nickname']} {self._authority_fp} "
            f"{cfg['address']} {cfg['address']} {cfg['dir_port']} {cfg['or_port']}\n"
            f"contact {cfg['contact']}\n"
            f"vote-digest {vote_digest_hex}"
        )

    def _get_signed_consensus(self) -> str:
        rounded = self._rounded()
        if rounded not in self._cached_consensus_map or self._consensus_dirty:
            # 生成＋签名＋清掉旧轮次
            content = self._generate_consensus_content()
            self._cached_consensus_map.clear()
            self._cached_consensus_map[rounded] = self._add_signature(content)
            self._consensus_dirty = False

            signed = self._add_signature(content)
            self._cached_consensus_map_deflate.clear()
            self._cached_consensus_map_deflate[rounded] = zlib.compress(signed.encode('utf-8'))
            self._consensus_dirty = False

        return self._cached_consensus_map[rounded]

    def _get_signed_microdesc(self) -> str:
        rounded = self._rounded()
        if rounded not in self._cached_microdesc_map or self._micro_dirty:
            content = self._generate_microdesc_content()
            self._cached_microdesc_map.clear()
            self._cached_microdesc_map[rounded] = self._add_signature_micro(content)
            self._micro_dirty = False
        return self._cached_microdesc_map[rounded]

    def _b64_pubkey_digest(self, priv) -> str:
        der = priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.PKCS1
        )
        return base64.b64encode(hashlib.sha1(der).digest()).decode()

    def _fake_microdesc_digest(self, text: str = None) -> str:
        if text is None:
            digest = secrets.token_bytes(32)
        else:
            digest = hashlib.sha256(text.encode()).digest()
        return base64.b64encode(digest).decode("ascii").rstrip("=")

    def exit_policy_extract(self, info):
        pol = "reject 1-65535"
        if any(ln.lower().startswith("accept ") for ln in info["text"].splitlines()):
            pol = "accept 1-65535"

    def _generate_consensus_content(self):
        now = datetime.utcnow()
        valid_after = self._rounded(now)
        fresh_until = valid_after + timedelta(minutes=60)
        valid_until = valid_after + timedelta(minutes=180)

        # ---------- header ----------
        header = f"""network-status-version 3
vote-status consensus
consensus-method 33
valid-after {valid_after:%Y-%m-%d %H:%M:%S}
fresh-until {fresh_until:%Y-%m-%d %H:%M:%S}
valid-until {valid_until:%Y-%m-%d %H:%M:%S}
voting-delay 300 300
client-versions 0.4.8.17,0.4.8.18,0.4.8.19,0.4.8.20,0.4.8.21,0.4.9.3-alpha
server-versions 0.4.8.17,0.4.8.21,0.4.9.3-alpha
known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-client-protocols Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
params AuthDirMaxServersPerAddr=2 CircuitPriorityHalflifeMsec=30000 UseGuardFraction=0
{self._build_authority_block("0" * 40)}
"""

        parts = [header]
        entries = []
        # authority 自己在构造的时候已经填入


        # cached relays

        for fp, info in self._descriptor_cache.items():
            block = (
                f"r {info['nick']} {info['ident_b64']} {info['desc_b64']} {info['published']} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                f"{self._derive_status_line(info['text'], info['is_exit'])}"
                "v Tor 0.4.8.17\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
                f"{info['p_line']}\n"
            )
            entries.append((info['ident_b64'], block))

        # 2) 按 fp_hex 升序排序
        from base64 import b64decode
        entries.sort(key=lambda tpl: b64decode(tpl[0] + '=='))

        # 3) 把排好序的块依次加回 parts
        for _, block in entries:
            parts.append(block)

        # ---------- footer ----------
        parts.append("""directory-footer
bandwidth-weights Wbd=3333 Wbe=3333 Wbg=3333 Wbm=10000 Wdb=10000 Web=10000 Wed=3333 Wee=10000 Weg=3333 Wem=10000
""")

        consensus = "".join(parts)

        # ---------- vote-digest ----------
        digest_hex = hashlib.sha1(consensus.encode()).hexdigest().upper()
        consensus = consensus.replace("0" * 40, digest_hex, 1)

        return consensus

    def _generate_microdesc_content(self):
        now = datetime.utcnow()
        valid_after = self._rounded(now)
        fresh_until = valid_after + timedelta(minutes=60)
        valid_until = valid_after + timedelta(minutes=180)

        header = f"""network-status-version 3 microdesc
vote-status consensus
consensus-method 33
valid-after {valid_after:%Y-%m-%d %H:%M:%S}
fresh-until {fresh_until:%Y-%m-%d %H:%M:%S}
valid-until {valid_until:%Y-%m-%d %H:%M:%S}
voting-delay 300 300
client-versions 0.4.8.17,0.4.8.18,0.4.8.19,0.4.8.20,0.4.8.21,0.4.9.3-alpha
server-versions 0.4.8.17,0.4.8.21,0.4.9.3-alpha
known-flags Authority BadExit Exit Fast Guard HSDir MiddleOnly NoEdConsensus Running Stable StaleDesc Sybil V2Dir Valid
recommended-client-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4 HSRend=2 Link=4-5 Microdesc=2 Relay=2-4
recommended-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
required-client-protocols Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2
required-relay-protocols Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4
params AuthDirMaxServersPerAddr=2 CircuitPriorityHalflifeMsec=30000 UseGuardFraction=0
{self._build_authority_block("0" * 40)}
"""

        parts = [header]
        entries = []

        ident_self = self._get_base64_digest_of_pubkey(self._authority_key)
        published_self = (now - timedelta(minutes=18)).strftime('%Y-%m-%d %H:%M:%S')

        self_micro_text = self._self_micro_text
        self_micro_b64 = self._self_micro_b64

        # 保存到映射，供 /tor/micro/d/… 命中
        self._micro_map[self_micro_b64] = self_micro_text

        micro_published = "2038-01-01 00:00:00"
        for fp, info in self._descriptor_cache.items():
            block = (
                f"r {info['nick']} {info['ident_b64']} {micro_published} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                f"m {info['micro_b64']}\n"
                f"{self._derive_status_line(info['text'], info['is_exit'])}"
                "v Tor 0.4.8.17\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000\n"
            )
            entries.append((info['ident_b64'], block))

        # 2) 按 fp_hex 升序排序
        from base64 import b64decode
        entries.sort(key=lambda tpl: b64decode(tpl[0] + '=='))
        # 3) 把排好序的块依次加回 parts
        for _, block in entries:
            parts.append(block)

        # ---------- footer ----------
        parts.append("""directory-footer
bandwidth-weights Wbd=3333 Wbe=3333 Wbg=3333 Wbm=10000 Wdb=10000 Web=10000 Wed=3333 Wee=10000 Weg=3333 Wem=10000""")
        micro = "".join(parts)
        digest_hex = hashlib.sha1(micro.encode('utf-8')).hexdigest().upper()
        # 3) 替换 header 里的 “0"*40” 占位 vote-digest
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
        doc_digest = hashlib.sha1(signed_prefix.encode()).digest()

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
        doc_digest = hashlib.sha256(signed_prefix.encode()).digest()

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

    def _make_self_bundle(self):
        """
        构造 (descriptor_text, desc_hex, micro_text, micro_b64)
        — 都严格可复现，供客户端下载校验
        """
        fp_hex = self._authority_fp
        onion_priv = rsa.generate_private_key(
            public_exponent = 65537,
            key_size = 1024)
        pub_pem = onion_priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.PKCS1).decode().strip()

        published = (datetime.utcnow() - timedelta(minutes=20)).strftime('%Y-%m-%d %H:%M:%S')

        ntor_b64 = self._ntor_pub_b64

        self.ed_priv, ed_pub_raw, ed_b64_43 = _make_ed25519_identity()
        ed_cert_block = _make_ed25519_cert(self.ed_priv, ed_pub_raw)

        desc = (
                f"router {self._server_cfg['nickname']} {self._server_cfg['address']} "
                f"{self._server_cfg['or_port']} 0 0\n"
                f"platform Tor 0.4.8.17\n"
                f"fingerprint {' '.join(fp_hex[i:i + 4] for i in range(0, 40, 4))}\n"
                f"published {published}\n"
                f"master-key-ed25519 {ed_b64_43}\n"
                f"{ed_cert_block}"
                "onion-key\n"
                + "\n".join(pub_pem.splitlines()) + "\n"
                f"ntor-onion-key {ntor_b64}\n"
                "router-signature\n-----BEGIN SIGNATURE-----\n"
                + "A" * 256 + "\n-----END SIGNATURE-----\n"
        )

        # desc_hex = hashlib.sha1(desc.encode()).hexdigest().upper()

        signed_part = self._get_signed_payload(desc)
        desc_digest = hashlib.sha1(signed_part).digest()
        desc_b64 = base64.b64encode(desc_digest).decode().rstrip("=")
        desc_hex = desc_digest.hex().upper()

        p_line, is_exit = _policy_summary(desc)
        micro_text = self._extract_microdescriptor(desc, p_line)
        micro_b64 = base64.b64encode(
            hashlib.sha256(micro_text.encode()).digest()
        ).decode().rstrip('=')

        return desc,desc_b64 , desc_hex, micro_text, micro_b64, p_line, is_exit

    # --------------------------------------------------------------------- #
    # GET handlers
    # --------------------------------------------------------------------- #
    async def _handle_root(self, request: web.Request) -> web.Response:
        print(f"[DIR] ROOT  {request.method} {request.path} match={dict(request.match_info)}")
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


    async def _handle_key_cert(self, request: web.Request) -> web.Response:
        if not self._cached_key_cert:
            self._cached_key_cert = self._build_key_certificate()

        txt = self._cached_key_cert
        data = txt.encode("utf-8")
        z = request.path.endswith(".z")

        if z:
            gz = gzip.compress(data)
            return web.Response(
                body=gz,
                headers={"Content-Encoding": "gzip"},
            )

        return web.Response(
            body=data,
            content_type="text/plain"
        )

    async def _handle_authority_meta(self, _request: web.Request) -> web.Response:
        return web.json_response(
            {
                "authority_fingerprint": self._authority_fp,
                "signing_fingerprint": self._signing_fp,
                **self._server_cfg,
            }
        )

    async def _handle_consensus(self, request: web.Request) -> web.Response:
        print(f"[DIR] CONSENSUS {request.method} {request.path} match={dict(request.match_info)}")
        now = time.time()

        if (not self._network_ready_flag) or (now - self._start_time < self._min_uptime):
            return web.Response(
                status=503,
                text="Consensus not ready (waiting for network or warmup).",
                headers={"Retry-After": "5"}
            )

        z = request.path.endswith(".z")

        signed = self._get_signed_consensus()
        data = signed.encode("utf-8")  # 原始字节，不让 aiohttp 修改

        if z:
            gz = gzip.compress(data)
            return web.Response(
                body=gz,
                headers={"Content-Encoding": "gzip"},
            )

        return web.Response(
            body=data,
            content_type="text/plain"
        )

    async def _handle_micro(self, request: web.Request) -> web.Response:
        print(f"[DIR] MICRO {request.method} {request.path} match={dict(request.match_info)}")
        now = time.time()

        if not self._network_ready_flag or (now - self._start_time < self._min_uptime):
            return web.Response(
                status=503,
                text="Consensus not ready, insufficient relays.",
                headers={"Retry-After": "5"}
            )

        z = request.path.endswith(".z")
        signed = self._get_signed_microdesc()
        data = signed.encode("utf-8")

        if z:
            gz = gzip.compress(data)
            return web.Response(
                body=gz,
                headers={"Content-Encoding": "gzip"},
            )

        return web.Response(
            body=data,
            content_type="text/plain"
        )


    async def _handle_server_descriptor(self, request):
        print(f"[DIR] SERVER/D {request.method} {request.path} match={dict(request.match_info)}")

        """
        兼容 2 种 URL 形式：
          • /tor/server/d/<DIG+.>.z   → deflate 压缩
          • /tor/server/d/<DIG+.>     → 原文
        多个 digest 仍用 “+” 连接
        """
        z = request.path.endswith(".z")
        raw = request.match_info["fps"]

        # Strip .z suffix
        if raw.endswith(".z"):
            raw = raw[:-2]

        # Multiple digests are separated by "+"
        digests = raw.split("+")

        buf = bytearray()

        for d in digests:
            # disk → 缓存 → 404
            path = self._descriptor_dir / f"{d}.desc"
            found = None
            if path.exists():
                found = path.read_bytes()
            else:
                for info in self._descriptor_cache.values():
                    if info.get("desc_hex", "").lower() == d.lower():
                        found = info["text"].encode()
                        break
            if not found:
                raise web.HTTPNotFound(text=f"Server descriptor {d} not found")
            buf.extend(found)


        if z:
            gz = gzip.compress(buf)
            return web.Response(
                body=gz,
                headers={"Content-Encoding": "gzip"},
            )

        return web.Response(
            body=buf,
            content_type="text/plain"
        )



    async def _handle_micro_descriptor(self, request):
        print(f"[DIR] MICRO/D {request.method} {request.path} match={dict(request.match_info)}")

        # Determine whether .z is requested
        z = request.path.endswith(".z")

        raw_digests = request.match_info['digests']

        # Strip trailing ".z" from the digest string BEFORE splitting
        if raw_digests.endswith(".z"):
            raw_digests = raw_digests[:-2]  # remove .z suffix

        digests = raw_digests.split('-')
        print(f"[REQ /micro/d] digests = {digests}")

        buf = bytearray()

        for d in digests:
            # 1) Lookup microdesc text by digest directly
            md = self._micro_map.get(d)
            if md:
                buf.extend(md.encode('utf-8'))
                continue

            # 2) Lookup by scanning descriptors
            found = False
            for info in self._descriptor_cache.values():
                if info.get('micro_b64') == d:
                    buf.extend(info['micro_text'].encode('utf-8'))
                    found = True
                    break

            if not found:
                raise web.HTTPNotFound(text=f"Microdesc {d} not found")

        # Convert to bytes
        raw_bytes = bytes(buf)

        # ====================================================
        # MUST gzip ONLY if .z suffix exists
        # ====================================================
        if z:
            gz = gzip.compress(buf)
            return web.Response(
                body=gz,
                headers={"Content-Encoding": "gzip"},
            )

        return web.Response(
            body=buf,
            content_type="text/plain"
        )

    async def _handle_server_by_fp(self, request):
        print(f"[DIR] SERVER/FP {request.method} {request.path} match={dict(request.match_info)}")

        z = request.path.endswith(".z")

        fps_part = request.match_info["fps"]
        if z:
            fps_part = fps_part[:-2]  # 剪掉尾部 ".z"

        fps_b64 = [s for s in fps_part.split("-") if s]  # 只按 ‘-’ 切

        buf = bytearray()
        for fp_b64 in fps_b64:
            # 补 padding, 解码 → 40 位 hex
            padded = fp_b64 + "=" * (-len(fp_b64) % 4)
            try:
                fp_hex = base64.b64decode(padded).hex().upper()
            except Exception:
                raise web.HTTPBadRequest(text=f"Bad fingerprint {fp_b64}")

            desc = self._descriptor_cache.get(fp_hex, {}).get("text")
            if not desc:
                raise web.HTTPNotFound(text=f"Descriptor for FP {fp_b64} not found")
            buf.extend(desc.encode())

        if z:
            gz = gzip.compress(buf)
            return web.Response(
                body=gz,
                headers={"Content-Encoding": "gzip"},
            )

        return web.Response(
            body=buf,
            content_type="text/plain"
        )

    # --------------------------------------------------------------------- #
    # POST handler  —— 上传节点描述符
    # --------------------------------------------------------------------- #
    async def _handle_descriptor_upload(self, request: web.Request) -> web.Response:
        print(f"[DIR] DESCRIPTOR-UPLOAD {request.method} {request.path} match={dict(request.match_info)}")

        raw = (await request.read()).decode()
        print(">>> descriptor received\n", raw.splitlines(), "...\n")

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

        signed_part = self._get_signed_payload(raw)
        desc_digest = hashlib.sha1(signed_part).digest()
        desc_b64 = base64.b64encode(desc_digest).decode().rstrip("=")
        desc_hex = desc_digest.hex().upper()
        (self._descriptor_dir / f"{desc_hex}.desc").write_text(raw, "utf-8")

        ident_b64 = base64.b64encode(bytes.fromhex(fp_hex)).decode().rstrip('=')
        p_line, is_exit = _policy_summary(raw)
        micro_text = self._extract_microdescriptor(raw, p_line)

        if micro_text is None:
            print("[WARN] reject descriptor: missing or bad onion/ntor key")
            raise web.HTTPBadRequest(text="descriptor lacks valid onion/ntor key")

        micro_b64 = base64.b64encode(hashlib.sha256(micro_text.encode('utf-8')).digest()) \
            .decode('ascii').rstrip('=')
        self._micro_map[micro_b64] = micro_text
        self._descriptor_cache[fp_hex] = {
            "text": raw,
            "desc_b64": desc_b64,
            "micro_b64": micro_b64,
            "micro_text": micro_text,
            "p_line": p_line,
            "is_exit": is_exit,
            "ident_b64": ident_b64,
            "published": published,
            "or_addr": or_addr or request.remote,
            "or_port": or_port or "9001",
            "dir_port": dir_port or "0",
            "nick": nick or "Unnamed",
        }
        # persist to tmp file
        (self._descriptor_dir / f"{fp_hex}.desc").write_text(raw, "utf-8")
        self._consensus_dirty = True
        self._micro_dirty = True

        print(f"[UPLOAD] fp={fp_hex}  desc_hex={desc_hex}  "
              f"desc_b64={desc_b64[:8]}…  micro_b64={micro_b64[:8]}…")

        if not self._network_ready_flag:
            self._network_ready()

        return web.Response(text="OK")

    # --------------------------------------------------------------------- #
    # consensus / microdesc / certificate builders  —— 与原实现一致，略去注释
    # --------------------------------------------------------------------- #
    def _load_seed_descriptors(self, seed_dir: Path):
        for f in seed_dir.glob("*.desc"):
            raw = f.read_text(encoding="utf-8")
            p_line, is_exit = _policy_summary(raw)
            # 从 raw 里提取 fingerprint（hex）
            fp = None
            for ln in raw.splitlines():
                if ln.startswith("fingerprint "):
                    fp = ln.split(None,1)[1].replace(" ", "")
                    break
            if not fp:
                continue

            # 计算 URL-safe SHA256-digest（去掉 "="）
            digest32 = hashlib.sha256(raw.encode()).digest()
            micro_b64 = base64.b64encode(digest32).decode("ascii").rstrip("=")

            # 写到临时目录
            (self._descriptor_dir / f"{fp}.desc").write_text(raw, encoding="utf-8")
            ident_b64 = base64.b64encode(bytes.fromhex(fp)).decode().rstrip('=')
            signed_part = self._get_signed_payload(raw)
            desc_digest = hashlib.sha1(signed_part).digest()
            desc_b64 = base64.b64encode(desc_digest).decode().rstrip("=")
            desc_hex = desc_digest.hex().upper()            # 缓存到内存
            self._descriptor_cache[fp] = {
                "text": raw,
                "desc_b64": desc_b64,
                "micro_b64": micro_b64,
                "ident_b64": ident_b64,
                "p_line": p_line,
                "is_exit": is_exit,
                # … 你还可以继续填 published/or_addr/or_port/nick 等字段
            }

            micro_text = self._extract_microdescriptor(raw, p_line)
            if not micro_text:
                continue
            self._micro_map[micro_b64] = micro_text

    def _get_signed_payload(self, descriptor_text: str) -> bytes:
        # Normalize line endings (very important)
        t = descriptor_text.replace("\r\n", "\n").replace("\r", "\n")

        lines = t.split("\n")
        out = []
        for ln in lines:
            out.append(ln)
            if ln.strip().lower() == "router-signature":
                break

        # Join back with '\n' and ensure trailing newline
        signed_part = "\n".join(out) + "\n"
        return signed_part.encode("utf-8")

    def _extract_microdescriptor(self, router_desc: str, p_summary: str) -> str:
        md_lines = []
        in_okey = False
        have_ntor = False
        ed_b64 = ed25519_from_descriptor(router_desc)

        for ln in router_desc.splitlines():
            l = ln.strip()

            # onion-key 行（忽略大小写 & 前后空白）
            if l.lower() == "onion-key":
                in_okey = True
                md_lines.append("onion-key")
                continue

            if in_okey:
                md_lines.append(ln)
                if l.startswith("-----END "):  # END RSA PUBLIC KEY line
                    in_okey = False
                continue

            # ntor-onion-key
            if ln.startswith("ntor-onion-key "):
                key = ln.split()[1].rstrip("=")
                if len(key) != 43: return None
                md_lines.append(f"ntor-onion-key {key}");
                have_ntor = True
                continue

        if in_okey or not md_lines or not have_ntor:
            return None

        md_lines.append(p_summary)
        md_lines.append(f"id ed25519 {ed_b64}")
        md = "\n".join(md_lines) + "\n"  # newline‑terminated

        if len(md.encode()) > 2048:
            return None
        return md
    # --------------------------------------------------------------------- #
    # routing
    # --------------------------------------------------------------------- #
    def _setup_routes(self):
        r = self.app.router
        # GET
        r.add_get("/", self._handle_root)
        r.add_get("/hello", self._handle_root)
        r.add_get("/time", self._handle_root)
        r.add_get("/tor/status-vote/current/consensus-microdesc{rest:.*}", self._handle_micro)
        r.add_get("/tor/status-vote/current/consensus{rest:.*}", self._handle_consensus)
        r.add_get("/tor/keys/authority", self._handle_authority_meta)
        r.add_get(r"/tor/keys/{_:(fp/.*|fp-sk/.*)}", self._handle_key_cert)
        r.add_get(r"/tor/keys/{_:(fp/.*|fp-sk/.*)}.z", self._handle_key_cert)
        # r.add_get("/tor/server/d/{fps:.*}.z", self._handle_server_descriptor)
        r.add_get("/tor/server/d/{fps:.*}", self._handle_server_descriptor)
        # r.add_get("/tor/micro/d/{digests:.*}.z", self._handle_micro_descriptor)
        r.add_get("/tor/micro/d/{digests:.*}", self._handle_micro_descriptor)
        # r.add_get("/tor/server/fp/{fps:.*}.z", self._handle_server_by_fp)
        r.add_get("/tor/server/fp/{fps:.*}", self._handle_server_by_fp)
        # POST
        r.add_post("/tor/", self._handle_descriptor_upload)

    # --------------------------------------------------------------------- #
    # run
    # --------------------------------------------------------------------- #
    def run(self):
        web.run_app(self.app,
                    host=self.host,
                    port=self.port,
                    backlog=2048,  # ↑
                    print=lambda *a: None)


    def _network_ready(self) -> bool:
        """Check only once. After becoming ready, always return True."""
        # If already ready, skip all checks
        if self._network_ready_flag:
            return True

        guards = 0
        middles = 0
        exits = 0

        # Fast scan: return early when conditions met
        for fp, info in self._descriptor_cache.items():
            status_line = self._derive_status_line(info["text"], info["is_exit"])
            flags = status_line.split()[1:]  # ["Running","Valid","Guard",...]

            if "Guard" in flags:
                guards += 1
                if guards >= 1 and middles >= 1 and exits >= 1:
                    self._network_ready_flag = True
                    return True

            elif "Exit" in flags:
                exits += 1
                if guards >= 1 and middles >= 1 and exits >= 1:
                    self._network_ready_flag = True
                    return True

                # middle
            elif "MiddleOnly" in flags:
                middles += 1
                if guards >= 1 and middles >= 1 and exits >= 1:
                    self._network_ready_flag = True
                    return True

        return False

def _parse_policy_line(line: str):
    """
    解析 'accept|reject addr:ports'，仅关心 “对所有地址”的策略。
    返回 (is_accept, set_of_ports)；遇到 '*' 端口或缺省端口 => 全部 1-65535。
    """
    try:
        typ, spec = line.split(None, 1)
    except ValueError:
        return None                                    # 行格式错误

    # 拆 addr 与 ports（addr:* / addr / *:80,443）
    if ":" in spec:
        addr, ports = spec.split(":", 1)
    else:
        addr, ports = spec, "*"                       # 兼容 “accept *”
    addr = addr.strip()

    # 只统计 “全网地址” 的出站策略（Tor 计算 Exit-Flag 也是如此）
    if addr not in ("*", "0.0.0.0/0", "[::]/0", "[::]"):
        return None

    # '*' 或空 => 全端口
    if ports.strip() in ("", "*"):
        ports_set = set(range(1, 65536))
    else:
        ports_set = set()
        for part in ports.split(","):
            m = _PORT_RE.fullmatch(part.strip())
            if not m:
                continue                             # 忽略非法片段
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            ports_set.update(range(a, b + 1))

    return (typ.lower() == "accept", ports_set)

def _summarise_ports(port_set):
    """
    把 {80,81,443,6660..6669} 压缩成 '80,81,443,6660-6669'
    """
    rngs = []
    for k, g in itertools.groupby(enumerate(sorted(port_set)),
                                  lambda kv: kv[1] - kv[0]):
        group = list(g)
        start, end = group[0][1], group[-1][1]
        rngs.append(f"{start}-{end}" if start != end else f"{start}")
    return ",".join(rngs)

def _policy_summary(desc_text: str):
    """
    读取原始 server-descriptor，返回两项：
      * summary_line : 'p accept …' / 'p reject …'
      * is_exit      : bool, 是否应给予 Exit 标志
    """
    accept_ports, reject_ports = set(), set()

    for ln in desc_text.splitlines():
        if ln.startswith(("accept ", "reject ")):
            parsed = _parse_policy_line(ln.lower())
            if not parsed:
                continue
            is_acc, ports = parsed
            (accept_ports if is_acc else reject_ports).update(ports)

    # 未显式声明 => 全拒
    if not accept_ports and not reject_ports:
        return "p reject 1-65535", False

    # allow-all / deny-all 快捷
    if accept_ports == set(range(1, 65536)):
        return "p accept 1-65535", True
    if not accept_ports:
        return "p reject 1-65535", False

    # 计算互补集
    all_ports = set(range(1, 65536))
    reject_ports = all_ports - accept_ports

    acc_txt = _summarise_ports(accept_ports)
    rej_txt = _summarise_ports(reject_ports)
    if len(acc_txt) <= len(rej_txt):
        return f"p accept {acc_txt}", True
    else:
        return f"p reject {rej_txt}", True


def get_ntor_keypair():
    """
    生成（或加载已有的）Curve25519 ntor 密钥对
    返回 (priv_obj, pub_b64_str_without_padding)
    """
    ntor_file = KEY_DIR / "ntor_key.raw"      # 32‑byte private key, 原始格式

    # --- ① 生成或加载私钥 ---
    if ntor_file.exists():
        priv_raw = ntor_file.read_bytes()     # 32 bytes
        priv = x25519.X25519PrivateKey.from_private_bytes(priv_raw)
    else:
        priv = x25519.X25519PrivateKey.generate()
        ntor_file.write_bytes(
            priv.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # --- ② 导出公钥并转成 43 字符的 Base64 ---
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,      # 32 bytes
        format=serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_raw).decode("ascii").rstrip("=")  # 去掉 '='

    assert len(pub_b64) == 43          # Tor 规范要求 43 字符
    return priv, pub_b64

def ed25519_from_descriptor(desc_text: str) -> str | None:
    """
    提取 Ed25519 主身份公钥（43‑char, 无 '='）。
    优先级：master-key-ed25519 > identity-ed25519 证书
    """
    # ① master-key-ed25519
    m = _ED_LINE_RE.search(desc_text)
    if m:
        key = m.group(1).strip()
        key = key.rstrip('=')          # 去掉 1～2 个 '='
        return key if len(key) == 43 else None

    # ② identity-ed25519 证书（可能多段，逐段查找）
    for m in _CERT_RE.finditer(desc_text):
        b64_blob = re.sub(r'\s+', '', m.group(1))      # 去换行
        try:
            cert_bin = base64.b64decode(b64_blob, validate=True)
            print("cert_bin is :", cert_bin)
            if len(cert_bin) < 39:          # header32 + pub32
                continue
            pub_raw = cert_bin[7:39]
            key = base64.b64encode(pub_raw).decode().rstrip('=')
            if len(key) == 43:
                return key
        except Exception:
            continue

    return None


def _make_ed25519_identity():
    """
    生成或加载目录服务器自己的 Ed25519 身份密钥对。
    返回 (priv, pub_raw, pub_b64_43)
    """
    path = KEY_DIR / "ed25519_id.key"

    if path.exists():
        raw = path.read_bytes()
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(raw)
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        path.write_bytes(
            priv.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption()
            )
        )
    pub = priv.public_key()
    pub_raw = pub.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    pub_b64 = base64.b64encode(pub_raw).decode().rstrip("=")
    assert len(pub_b64) == 43
    return priv, pub_raw, pub_b64

def _make_ed25519_cert(ed_priv, ed_pub_raw):
    """
    生成 identity-ed25519 证书（Tor v3），返回 PEM 块文本。
    """
    version = 1
    cert_type = 4      # SIGNING KEY
    expire = int(time.time()) + 86400 * 30  # 30 天有效
    key_type = 1       # Ed25519
    n_ext = 0

    body = bytearray()
    body += struct.pack("!B", version)
    body += struct.pack("!B", cert_type)
    body += struct.pack("!I", expire)
    body += struct.pack("!B", key_type)
    body += ed_pub_raw                           # 32 bytes
    body += struct.pack("!B", n_ext)

    # 签名覆盖前面所有内容
    sig = ed_priv.sign(bytes(body))
    body += sig

    b64 = base64.b64encode(body).decode()
    # 按 tor 格式换行（可选，不换也能过）
    wrapped = "\n".join(b64[i:i+64] for i in range(0, len(b64), 64))

    return (
        "identity-ed25519\n"
        "-----BEGIN ED25519 CERT-----\n"
        f"{wrapped}\n"
        "-----END ED25519 CERT-----\n"
    )

# ------------------------------------------------------------------------- #
# entry
# ------------------------------------------------------------------------- #
if __name__ == "__main__":
    #save
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