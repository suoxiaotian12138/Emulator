#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse as urlparse
import pathlib
from datetime import datetime, timedelta
import hashlib
import base64
import zlib
import tempfile, shutil, atexit
import os
import secrets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric import rsa, padding as padding, utils

KEY_DIR = pathlib.Path("./tor_keys")
KEY_DIR.mkdir(exist_ok=True)


class TorDirectoryServer(BaseHTTPRequestHandler):
    # 类变量用于存储密钥和配置
    _authority_key = None
    _signing_key = None
    _authority_fingerprint = None
    _signing_fingerprint = None
    _server_config = {
        'nickname': 'tordir',
        'address': '192.168.66.241',
        'or_port': 9001,
        'dir_port': 9030,
        'contact': 'test@local.net',
        'tor_version': '0.4.8.17'
    }
    _cached_consensus_map = {}  # key: valid_after datetime, value: signed consensus
    _cached_microdesc_map = {}
    _cached_key_cert = None
    _descriptor_cache = {}
    _descriptor_dir = tempfile.mkdtemp(prefix="tor_desc_")
    atexit.register(shutil.rmtree, _descriptor_dir, ignore_errors=True)

    @classmethod
    def _load_or_generate_keys(cls):
        authority_key_file = KEY_DIR / "authority_key.pem"
        signing_key_file = KEY_DIR / "signing_key.pem"

        if authority_key_file.exists() and signing_key_file.exists():
            with open(authority_key_file, "rb") as f:
                cls._authority_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open(signing_key_file, "rb") as f:
                cls._signing_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
        else:
            print("[*] 生成新的RSA密钥对...")
            cls._authority_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048  # ← 1024 → 2048
            )
            cls._signing_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            with open(authority_key_file, "wb") as f:
                f.write(cls._authority_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(signing_key_file, "wb") as f:
                f.write(cls._signing_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

        cls._authority_fingerprint = cls._calculate_key_fingerprint(cls._authority_key)
        cls._signing_fingerprint = cls._calculate_key_fingerprint(cls._signing_key)

        print(f"[启动] Authority Fingerprint: {cls._authority_fingerprint}")
        print(f"[启动] Signing Fingerprint  : {cls._signing_fingerprint}")

    @classmethod
    def generate_keys(cls):
        cls._load_or_generate_keys()

    @classmethod
    def _calculate_key_fingerprint(cls, private_key):
        """返回 40 位大写十六进制 fingerprint, 计算规则同 Tor 实现"""
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1  # ← 关键：PKCS#1 而非 SubjectPublicKeyInfo
        )
        return hashlib.sha1(pub_der).hexdigest().upper()

    def _get_base64_digest_of_pubkey(self, private_key):
        pub_der = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1
        )
        return base64.b64encode(hashlib.sha1(pub_der).digest()).decode()

    @classmethod
    def _sign_data(cls, data: str) -> str:
        """用 _signing_key 对文本做 RSA-PKCS1-SHA1 签名，返回 base64"""
        sig = cls._signing_key.sign(
            data.encode('utf-8'),
            PKCS1v15(),
            hashes.SHA1()
        )
        return base64.b64encode(sig).decode('ascii')

    def _build_authority_block(self, vote_digest_hex: str) -> str:
        cfg = self._server_config

        return (
                f"dir-source {cfg['nickname']} {self._authority_fingerprint} "
                f"{cfg['address']} {cfg['address']} {cfg['dir_port']} {cfg['or_port']}\n"
                f"contact {cfg['contact']}\n"
                f"vote-digest {vote_digest_hex}"
                )

    def _generate_consensus_content(self):
        now = datetime.utcnow()
        valid_after = self._get_rounded_time(now)
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
params AuthDirMaxServersPerAddr=2 CircuitPriorityHalflifeMsec=30000
{self._build_authority_block("0" * 40)}
"""


        parts = [header]
        entries = []
        # authority 自己
        ident_self = self._get_base64_digest_of_pubkey(self._authority_key)
        desc_self = base64.b64encode(secrets.token_bytes(20)).decode()
        published_self = (now - timedelta(minutes=18)).strftime('%Y-%m-%d %H:%M:%S')
        auth_block = (
                f"r {self._server_config['nickname']} {ident_self} {desc_self} {published_self} "
                f"{self._server_config['address']} {self._server_config['or_port']} {self._server_config['dir_port']}\n"
                "s Authority Fast Guard HSDir Running Stable V2Dir Valid\n"
                f"v Tor {self._server_config['tor_version']}\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
                "p reject 1-65535\n"
        )
        entries.append((self._authority_fingerprint, auth_block))

        # cached relays

        for fp, info in self._descriptor_cache.items():
            block = (
                f"r {info['nick']} {info['ident_b64']} {info['desc_b64']} {info['published']} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                "s Running Valid\n"
                "v Tor 0.4.8.x\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
                "p reject 1-65535\n"
            )
            entries.append((fp, block))

        # 2) 按 fp_hex 升序排序
        entries.sort(key=lambda tpl: tpl[0])

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
        valid_after = self._get_rounded_time(now)
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
        entries = []

        ident_self = self._get_base64_digest_of_pubkey(self._authority_key)
        published_self = (now - timedelta(minutes=18)).strftime('%Y-%m-%d %H:%M:%S')
        auth_block = (
            f"r {self._server_config['nickname']} {ident_self} {published_self} "
            f"{self._server_config['address']} {self._server_config['or_port']} {self._server_config['dir_port']}\n"
            f"m {self._fake_microdesc_digest()}\n"
            "s Authority Fast Guard HSDir Running Stable V2Dir Valid\n"
            "v Tor 0.4.8.x\n"
            "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
            "w Bandwidth=1000 Measured=1000\n"
        )
        entries.append((self._authority_fingerprint, auth_block))

        # cached relays

        for fp, info in self._descriptor_cache.items():
            block = (
                f"r {info['nick']} {info['ident_b64']} {info['published']} "
                f"{info['or_addr']} {info['or_port']} {info['dir_port']}\n"
                f"m {info['desc_b64']}\n"
                "s Running Valid\n"
                "v Tor 0.4.8.x\n"
                "pr Conflux=1 Cons=1-2 Desc=1-2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=1-2 Link=1-5 LinkAuth=1,3 Microdesc=1-2 Padding=2 Relay=1-4\n"
                "w Bandwidth=1000 Measured=1000\n"
            )
            entries.append((fp, block))

        # 2) 按 fp_hex 升序排序
        entries.sort(key=lambda tpl: tpl[0])

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

    def _fake_microdesc_digest(self, text: str | None = None) -> str:
        if text is None:
            return base64.b64encode(secrets.token_bytes(32)).decode()
        return base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()

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
            f"directory-signature {self._authority_fingerprint} {self._signing_fingerprint}\n"
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
        doc_digest = hashlib.sha256(signed_prefix.encode('utf-8')).digest()

        sig_raw = self._raw_pkcs1_sign(self._signing_key, doc_digest)
        sig_b64 = base64.b64encode(sig_raw).decode()
        sig_lines = "\n".join(sig_b64[i:i + 64] for i in range(0, len(sig_b64), 64))

        return (
            f"{content}"
            f"directory-signature sha256 {self._authority_fingerprint} {self._signing_fingerprint}\n"
            "-----BEGIN SIGNATURE-----\n"
            f"{sig_lines}\n"
            "-----END SIGNATURE-----\n"
            )

    def do_GET(self):
        """处理GET请求"""
        # 确保密钥已生成
        self.generate_keys()

        # 解析URL路径
        parsed_path = urlparse.urlparse(self.path)
        path = parsed_path.path
        query_params = urlparse.parse_qs(parsed_path.query)

        if path.startswith('/tor/status-vote/current/consensus-microdesc'):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # 生成带签名的微描述符共识文档
            signed_microdesc = self._get_signed_microdesc()
            self.wfile.write(signed_microdesc.encode('utf-8'))
            return
        # 处理Tor目录服务请求
        elif path.startswith('/tor/status-vote/current/consensus'):
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # 生成带签名的共识文档
            signed_consensus = self._get_signed_consensus()
            self.wfile.write(signed_consensus.encode('utf-8'))
            return

        elif path == '/tor/keys/authority':
            # 返回权威密钥信息
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            key_info = {
                'authority_fingerprint': self._authority_fingerprint,
                'signing_fingerprint': self._signing_fingerprint,
                'nickname': self._server_config['nickname'],
                'address': self._server_config['address'],
                'or_port': self._server_config['or_port'],
                'dir_port': self._server_config['dir_port']
            }

            self.wfile.write(json.dumps(key_info, indent=2).encode('utf-8'))
            return

        elif path == '/tor/debug/consensus':
            # 返回调试信息
            self.send_response(200)
            self.send_header('Content-type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()

            # 生成共识内容但不签名，用于调试
            consensus_content = self._generate_consensus_content()
            debug_info = f"=== 未签名的共识内容 ===\n{consensus_content}\n\n"
            debug_info += f"=== 内容长度 ===\n{len(consensus_content)} 字节\n\n"
            debug_info += f"=== 密钥指纹 ===\n权威: {self._authority_fingerprint}\n签名: {self._signing_fingerprint}\n\n"

            # 生成签名版本
            signed_consensus = self._add_signature(consensus_content)
            debug_info += f"=== 完整签名文档 ===\n{signed_consensus}\n"

            self.wfile.write(debug_info.encode('utf-8'))
            return
        elif path.startswith('/tor/keys/fp/'):
            cert_data = self._get_cached_certificate().encode('utf-8')
            print("[调试] 返回的证书内容如下：\n", cert_data)

            if path.endswith('.z'):
                compressed = zlib.compress(cert_data)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Encoding', 'deflate')
                self.send_header('Content-Length', str(len(compressed)))
                self.end_headers()
                self.wfile.write(compressed)
                return
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(cert_data)))
                self.end_headers()
                self.wfile.write(cert_data)
                return

        elif path.startswith('/tor/keys/fp-sk/'):
            cert_data = self._get_cached_certificate().encode('utf-8')

            if path.endswith('.z'):
                compressed = zlib.compress(cert_data)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Encoding', 'deflate')
                self.send_header('Content-Length', str(len(compressed)))
                self.end_headers()
                self.wfile.write(compressed)
                return
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(cert_data)))
                self.end_headers()
                self.wfile.write(cert_data)
                return

        # 其他请求返回JSON格式
        self.send_response(200)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        # 根据不同路径返回不同内容
        if path == '/':
            response_data = {
                'message': '欢迎使用Tor目录服务器！',
                'timestamp': datetime.utcnow().isoformat(),
                'method': 'GET',
                'available_endpoints': [
                    '/hello', '/time', '/echo',
                    '/tor/status-vote/current/consensus.z',
                    '/tor/status-vote/current/consensus-microdesc.z',
                    '/tor/keys/authority',
                    '/tor/debug/consensus'
                ],
                'authority_fingerprint': self._authority_fingerprint,
                'signing_fingerprint': self._signing_fingerprint
            }
        elif path == '/hello':
            name = query_params.get('name', ['World'])[0]
            response_data = {
                'message': f'Hello, {name}!',
                'timestamp': datetime.utcnow().isoformat()
            }
        elif path == '/time':
            response_data = {
                'current_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                'timestamp': datetime.utcnow().isoformat()
            }
        elif path == '/echo':
            response_data = {
                'path': path,
                'query_params': query_params,
                'method': 'GET',
                'headers': dict(self.headers),
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            response_data = {
                'error': '404 Not Found',
                'message': f'路径 {path} 不存在',
                'timestamp': datetime.utcnow().isoformat()
            }

        # 返回JSON响应
        response_json = json.dumps(response_data, ensure_ascii=False, indent=2)
        self.wfile.write(response_json.encode('utf-8'))

    def do_POST(self):
        """处理POST请求"""
        if self.path != "/tor/":
            self.send_error(404)
            return
        # 获取请求体长度
        raw = self.rfile.read(int(self.headers["Content-Length"])).decode()
        print(">>> 收到描述符\n", raw.splitlines(), "...\n")
        # 读取请求体

        fp_hex = None
        nick = None
        or_addr = None
        or_port = None
        dir_port = None
        published = None

        for line in raw.splitlines():
            if line.startswith("router "):
                _, nick, or_addr, or_port, *_ = line.split()
            elif line.startswith("fingerprint "):
                fp_hex = line.split(None, 1)[1].replace(" ", "")
            elif line.startswith("published "):
                published = line.split(None, 1)[1]
            elif line.startswith("or-address ") and "[" not in line:  # 仅 IPv4
                or_addr, or_port = line.split()[1].rsplit(":", 1)
            elif line.startswith("dir-port "):
                dir_port = line.split()[1]

        if not fp_hex:
            self.send_error(400, "missing fingerprint")
            return

        # --- 计算描述符 SHA-1(文本) → base64 ---
        desc_digest_b64 = base64.b64encode(hashlib.sha1(raw.encode()).digest()).decode()
        ident_b64 = base64.b64encode(bytes.fromhex(fp_hex)).decode()
        micro_b64 = base64.b64encode(hashlib.sha256(raw.encode()).digest()).decode()

        # --- 落盘 ---
        desc_path = pathlib.Path(self._descriptor_dir, f"{fp_hex}.desc")
        desc_path.write_text(raw, encoding="utf-8")

        # --- 缓存到内存 ---
        self._descriptor_cache[fp_hex] = {
            "text": raw, "desc_b64": desc_digest_b64, "ident_b64": ident_b64,
            "published": published, "or_addr": or_addr or self.client_address[0],
            "or_port": or_port or "9001", "dir_port": dir_port or "0", "nick": nick or "Unnamed",
            "micro_b64": micro_b64,
        }

        # 回复 200
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        """自定义日志格式"""
        print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

    def _get_rounded_time(self, now=None, interval=1):
        now = now or datetime.utcnow()
        return now.replace(minute=(now.minute // interval) * interval, second=0, microsecond=0)

    def _get_signed_consensus(self):
        rounded = self._get_rounded_time()
        if rounded not in self._cached_consensus_map:
            content = self._generate_consensus_content()
            signed = self._add_signature(content)
            self._cached_consensus_map[rounded] = signed
        return self._cached_consensus_map[rounded]

    def _get_signed_microdesc(self):
        rounded = self._get_rounded_time()
        if rounded not in self._cached_microdesc_map:
            content = self._generate_microdesc_content()
            signed = self._add_signature_micro(content)
            self._cached_microdesc_map[rounded] = signed
        return self._cached_microdesc_map[rounded]

    @classmethod
    def _build_key_certificate(cls) -> str:
        utc_now = datetime.utcnow()
        published = utc_now.strftime('%Y-%m-%d %H:%M:%S')
        expires = (utc_now + timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')

        # 公钥 PEM 拆成行，保持尾部换行
        # ---------- 生成公钥 PEM 行 ----------
        id_pem_lines = cls._authority_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1
        ).decode().strip('\n').splitlines()  # ← 按行拆开，保留最后换行

        sign_pem_lines = cls._signing_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.PKCS1
        ).decode().strip('\n').splitlines()

        # ---------- 组装正文 ----------
        lines = [
            "dir-key-certificate-version 3",
            f"fingerprint {cls._authority_fingerprint}",
            f"dir-key-published {published}",
            f"dir-key-expires {expires}",
            "dir-identity-key",
            *id_pem_lines,
            "dir-signing-key",
            *sign_pem_lines,
        ]

        id_key_der = cls._authority_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.PKCS1  # ← 必须是 PKCS1
        )
        id_digest = hashlib.sha1(id_key_der).digest()

        cross_sig = cls._raw_pkcs1_sign(cls._signing_key, id_digest)
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
        cert_sig = cls._raw_pkcs1_sign(cls._authority_key, doc_digest)
        cert_b64 = base64.b64encode(cert_sig).decode()
        cert_blk = "\n".join(cert_b64[i:i + 64] for i in range(0, len(cert_b64), 64))

        lines += [
            "-----BEGIN SIGNATURE-----",
            cert_blk,
            "-----END SIGNATURE-----",
        ]

        return "\n".join(lines) + "\n"

    @staticmethod
    def _raw_pkcs1_sign(privkey, digest: bytes) -> bytes:
        """Tor 所用的 PKCS1-pad-hash 签名（无 ASN.1 DigestInfo）"""
        k = privkey.key_size // 8
        ps_len = k - len(digest) - 3
        padded = b"\x00\x01" + b"\xFF" * ps_len + b"\x00" + digest
        n = privkey.private_numbers().public_numbers.n
        d = privkey.private_numbers().d
        sig_int = pow(int.from_bytes(padded, "big"), d, n)
        return sig_int.to_bytes(k, "big")

    @classmethod
    def _get_cached_certificate(cls):
        """返回符合规范的 authority key certificate（缓存一天）"""
        if cls._cached_key_cert:
            return cls._cached_key_cert
        cls._cached_key_cert = cls._build_key_certificate()
        return cls._cached_key_cert


def run_server(host='192.168.66.241', port=9030):
    """启动HTTP服务器"""
    server_address = (host, port)
    httpd = HTTPServer(server_address, TorDirectoryServer)

    print(f"Tor目录服务器启动成功！")
    print(f"访问地址: http://{host}:{port}")
    print(f"可用的端点:")
    print(f"  GET  /        - 主页")
    print(f"  GET  /hello   - 问候 (可选参数: ?name=你的名字)")
    print(f"  GET  /time    - 当前时间")
    print(f"  GET  /echo    - 回显请求信息")
    print(f"  GET  /tor/status-vote/current/consensus.z - Tor共识文档 (带真实签名)")
    print(f"  GET  /tor/status-vote/current/consensus-microdesc.z - Tor微描述符共识文档 (带真实签名)")
    print(f"  GET  /tor/keys/authority - 权威密钥信息")
    print(f"  POST /        - 接收POST数据")
    print(f"按 Ctrl+C 停止服务器")
    print("-" * 50)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n服务器已停止")
        httpd.server_close()



if __name__ == '__main__':
    # 检查是否安装了必要的库


    # 启动服务器，默认监听 192.168.66.241:9030
    run_server()

    # 如果需要修改主机和端口，可以这样调用：
    # run_server(host='0.0.0.0', port=8080)