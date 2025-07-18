import itertools

from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
import re
import asyncio, argparse, base64, hashlib, json, os, secrets, shutil, tempfile, zlib
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from base64 import urlsafe_b64encode

from aiohttp import web
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import x25519

KEY_DIR = Path("./tor_keys")
KEY_DIR.mkdir(exist_ok=True)
_PORT_RE = re.compile(r"(\d+)(?:-(\d+))?$")
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
        self._cached_key_cert = None
        self._micro_map = {}
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

        self._self_desc, self._self_desc_hex, self._self_micro_text, self._self_micro_b64, self._self_p_line, self._self_is_exit = self._make_self_bundle()

        (self._descriptor_dir / f"{self._self_desc_hex}.desc").write_text(
            self._self_desc, 'utf-8')
        self._descriptor_cache[self._authority_fp] = {
            "text": self._self_desc,
            "desc_hex": self._self_desc_hex,
            "desc_b64": base64.b64encode(bytes.fromhex(self._self_desc_hex)).decode(),
            "ident_b64": base64.b64encode(bytes.fromhex(self._authority_fp)).decode(),
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
        print(f"[{ts}] \"{request.method} {request.path} HTTP/{request.version.major}.{request.version.minor}\"")
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

        # ---- 1) 自定义 sim-flags 行 ----
        for ln in desc_text.splitlines():
            if ln.lower().startswith("sim-flags "):
                tokens = [t.capitalize() for t in ln.split()[1:]]
                flags = base + [t for t in tokens
                                if t in {"Exit", "Guard", "Stable"}]
                # 保序输出
                order = ["Running", "Valid", "Stable", "Guard", "Exit"]
                return "s " + " ".join([f for f in order if f in flags]) + "\n"

        # ---- 2) Heuristics ----
        lines = desc_text.splitlines()

        # 2-a Exit?
        if is_exit:
            base.append("Exit")
        else:
            # 2-b Guard?
            m_bw = next((re.search(r"bandwidth (\d+) (\d+) (\d+)", ln)
                         for ln in lines if ln.startswith("bandwidth ")), None)
            if m_bw:
                avg_bandwidth = int(m_bw.group(1))  # 这是平均带宽，单位字节/秒
                if avg_bandwidth >= 250_0000:  # 250 KB/s ≈ 2000 Kbps（官方最低要求）
                    base.append("Guard")
                    base.append("Stable")
                if avg_bandwidth >= 100_000:  # 100 kB/s ≈ Tor 默认 Fast 阈值
                    base.append("Fast")

            has_tundir = any(ln.startswith("tunnelled-dir-server") for ln in lines)
            if has_tundir:
                base.append("V2Dir")
                if "Exit" not in base:
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
        order = ["Running", "Valid", "Stable", "Guard", "Exit", "Fast", "V2Dir", "HSDir"]
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
            desc_b64 = base64.b64encode(hashlib.sha1(raw.encode()).digest()).decode().rstrip('=')
            # 缓存到内存
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



        for fp, info in self._descriptor_cache.items():
            block = (
                f"r {info['nick']} {info['ident_b64']} {info['published']} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                f"m {info['micro_b64']}\n"
                f"{self._derive_status_line(info['text'], info['is_exit'])}"
                "v Tor 0.4.8.17\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
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
bandwidth-weights Wbd=3333 Wbe=0 Wbg=0 Wbm=10000 Wdb=10000 Web=10000 Wed=3333 Wee=10000 Weg=3333 Wem=10000""")
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

        desc = (f"router {self._server_cfg['nickname']} {self._server_cfg['address']} "
                f"{self._server_cfg['or_port']} 0 0\n"
                f"platform Tor 0.4.8.17\n"
                f"fingerprint {' '.join(fp_hex[i:i + 4] for i in range(0, 40, 4))}\n"
                f"published {published}\n"
                "onion-key\n"
                + "\n".join(pub_pem.splitlines()) + "\n"
                f"ntor-onion-key {ntor_b64}\n"
                "router-signature\n-----BEGIN SIGNATURE-----\n" + "A" * 256 + "\n-----END SIGNATURE-----\n")

        desc_hex = hashlib.sha1(desc.encode()).hexdigest().upper()

        p_line, is_exit = _policy_summary(desc)
        micro_text = self._extract_microdescriptor(desc, p_line)
        micro_b64 = base64.b64encode(
            hashlib.sha256(micro_text.encode()).digest()
        ).decode().rstrip('=')

        return desc, desc_hex, micro_text, micro_b64, p_line, is_exit

    # --------------------------------------------------------------------- #
    # GET handlers
    # --------------------------------------------------------------------- #
    async def _handle_consensus(self, request: web.Request) -> web.Response:
        z = request.path.endswith(".z")
        # 直接获取已缓存或新生成的签名共识文本
        signed = self._get_signed_consensus()
        data = signed.encode('utf-8')
        if z:
            data = zlib.compress(data)
            return web.Response(body=data, headers={"Content-Encoding": "deflate"})
        # 直接返回签名好的共识
        return web.Response(text=signed)

    async def _handle_micro(self, request: web.Request) -> web.Response:
        z = request.path.endswith(".z")
        # 直接获取已缓存或新生成的签名微描述符文本
        signed = self._get_signed_microdesc()
        data = signed.encode('utf-8')
        if z:
            data = zlib.compress(data)
            return web.Response(body=data, headers={"Content-Encoding": "deflate"})
        # 直接返回签名好的微描述符共识
        return web.Response(text=signed)

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

    def _extract_microdescriptor(self, router_desc: str, p_summary: str) -> str:
        md_lines = []
        in_okey = False
        have_ntor = False
        ed_b64 = extract_ed25519_key(router_desc)

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
        md_lines.append("")  # terminator
        md = "\n".join(md_lines) + "\n"  # newline‑terminated

        if len(md.encode()) > 2048:
            return None
        return md

    async def _handle_server_descriptor(self, request):
        """
        兼容 2 种 URL 形式：
          • /tor/server/d/<DIG+.>.z   → deflate 压缩
          • /tor/server/d/<DIG+.>     → 原文
        多个 digest 仍用 “+” 连接
        """
        want_deflate = request.path.endswith(".z")
        digests = request.match_info["fps"].split("+")
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

        body = zlib.compress(bytes(buf)) if want_deflate else bytes(buf)
        hdr = {"Content-Encoding": "deflate"} if want_deflate else {}
        return web.Response(body=body, headers=hdr)


    async def _handle_micro_descriptor(self, request):
        # e.g. GET /tor/micro/d/DIG1+DIG2.z
        digs = request.match_info['digests'].split('-')
        print(f"[REQ  /micro/d] {digs}")

        buf = bytearray()

        for d in digs:
            # 1) maybe you stored the raw text by digest?
            md = self._micro_map.get(d)
            if md:
                buf.extend(md.encode('utf-8'))
                continue

            # 2) else scan your descriptor cache for matching micro_b64
            found = False
            for info in self._descriptor_cache.values():
                if info.get('micro_b64') == d:
                    buf.extend(info['micro_text'].encode('utf-8'))
                    found = True
                    break
            if found:
                continue

            raise web.HTTPNotFound(text=f"Microdesc {d} not found")

        compressed = zlib.compress(bytes(buf))
        print("micro-desc:")
        print(buf)
        return web.Response(body=compressed, headers={"Content-Encoding": "deflate"})

    # --------------------------------------------------------------------- #
    # POST handler  —— 上传节点描述符
    # --------------------------------------------------------------------- #
    async def _handle_descriptor_upload(self, request: web.Request) -> web.Response:
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


        desc_digest = hashlib.sha1(raw.encode()).digest()
        desc_b64 = base64.b64encode(desc_digest).decode().rstrip('=')
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
        r.add_get("/tor/status-vote/current/consensus-microdesc{rest:.*}", self._handle_micro)
        r.add_get("/tor/status-vote/current/consensus{rest:.*}", self._handle_consensus)
        r.add_get("/tor/keys/authority", self._handle_authority_meta)
        r.add_get(r"/tor/keys/{_:(fp/.*|fp-sk/.*)}", self._handle_key_cert)
        r.add_get(r"/tor/keys/{_:(fp/.*|fp-sk/.*)}.z", self._handle_key_cert)
        r.add_get("/tor/server/d/{fps:.*}.z", self._handle_server_descriptor)
        r.add_get("/tor/server/d/{fps:.*}", self._handle_server_descriptor)
        r.add_get("/tor/micro/d/{digests:.*}.z", self._handle_micro_descriptor)
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
def extract_ed25519_key(desc_text: str) -> str | None:
    # 若有 master-key-ed25519 行，优先用它
    m = re.search(r'^master-key-ed25519 ([A-Za-z0-9+/]{43,44}=?)',
                  desc_text, re.M)
    if m:
        key_b64 = m.group(1).rstrip('=')
        return key_b64 if len(key_b64) == 43 else None

    # 否则解析 identity-ed25519 证书（略复杂）
    m = re.search(r'^identity-ed25519\\s*\\n-----BEGIN ED25519 CERT-----(.*?)-----END',
                  desc_text, re.S|re.M)
    if not m:
        return None
    cert_bin = base64.b64decode(re.sub(r'\\s+', '', m.group(1)))
    if len(cert_bin) < 64:
        return None
    pub_raw = cert_bin[ 32 : 64 ]          # 证书格式: 32B 版本/expiry/flags + 32B pubkey
    return base64.b64encode(pub_raw).decode('ascii').rstrip('=')
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