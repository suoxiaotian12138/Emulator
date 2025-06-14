# directory.py (修复版本)
from __future__ import annotations

import asyncio
import aiofiles
import aiofiles.os
import hashlib
import tempfile
import base64

from pathlib import Path
from aiohttp import web
import re

_FPRINT_RE = re.compile(r'^fingerprint\s+([A-F0-9 ]+)$',
                        re.MULTILINE | re.IGNORECASE)


class TorDirectoryServer:
    def __init__(self, host='127.0.0.1', port=9030):
        self.host = host
        self.port = port
        self._tempdir_obj = tempfile.TemporaryDirectory()
        self.storage_dir = Path(self._tempdir_obj.name)
        self.app = web.Application()
        # 添加锁来防止并发问题
        self._file_locks = {}
        self._locks_lock = asyncio.Lock()
        # 内存缓存来减少文件I/O
        self._descriptor_cache = {}
        # 共识文件专用锁
        self._consensus_lock = asyncio.Lock()
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_post("/tor/post/dir", self.handle_descriptor_upload)
        self.app.router.add_get("/tor/server/desc/{fingerprint}", self.handle_descriptor_query)
        self.app.router.add_get("/tor/status-vote/current/consensus", self.handle_consensus_query)

    async def _get_file_lock(self, safe_filename: str) -> asyncio.Lock:
        """获取文件专用的锁，避免同一文件的并发操作"""
        async with self._locks_lock:
            if safe_filename not in self._file_locks:
                self._file_locks[safe_filename] = asyncio.Lock()
            return self._file_locks[safe_filename]

    async def handle_descriptor_upload(self, request):
        descriptor = await request.text()
        result = await self._handle_descriptor_upload(descriptor)
        if isinstance(result, web.Response):
            return result
        return web.Response(text="Descriptor received.")

    async def handle_descriptor_query(self, request):
        # fingerprint = request.match_info['fingerprint']
        b64_fp = request.match_info['fingerprint']
        fingerprint = parse_urlsafe_fingerprint(b64_fp)
        print(f"[+] Received descriptor query for fingerprint: {fingerprint}")
        return await self._handle_descriptor_query(fingerprint)

    async def handle_consensus_query(self, request):
        print("[+] Received consensus request")
        return await self._handle_consensus_query()

    @staticmethod
    def extract_fingerprint(descriptor: str) -> str:
        """
        从 server-descriptor 提取 fingerprint，返回 **Base64(20 bytes) 无填充**。
        例：'cEDB9XKHRsX7XhKEUQGibuhjbX4'  (27 chars)
        """
        m = _FPRINT_RE.search(descriptor)
        if not m:
            raise ValueError("Missing 'fingerprint' line in descriptor")

        hex40 = m.group(1).replace(" ", "").upper()
        if len(hex40) != 40 or not re.fullmatch(r'[A-F0-9]{40}', hex40):
            raise ValueError(f"Malformed fingerprint line: {m.group(0)}")

        raw20 = bytes.fromhex(hex40)  # 20-byte binary
        b64 = base64.b64encode(raw20).decode('ascii')  # 28 chars, '==' padded
        return b64.rstrip('=')

    def _fingerprint_to_safe_filename(self, fingerprint: str) -> str:
        """
        将fingerprint转换为安全的文件名
        使用SHA256哈希确保文件名安全且唯一
        """
        return hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()

    async def _safe_atomic_move(self, temp_path: Path, target_path: Path):
        """
        在Windows上安全地进行原子文件移动操作
        """
        try:
            # 在Windows上，如果目标文件存在，需要先删除
            if target_path.exists():
                await aiofiles.os.unlink(str(target_path))

            # 执行重命名操作
            await aiofiles.os.rename(str(temp_path), str(target_path))

        except Exception as e:
            print(f"[!] Failed to move {temp_path} to {target_path}: {e}")
            # 清理临时文件
            if temp_path.exists():
                try:
                    await aiofiles.os.unlink(str(temp_path))
                    print(f"[+] Cleaned up temporary file: {temp_path}")
                except Exception as cleanup_e:
                    print(f"[!] Failed to clean up temp file: {cleanup_e}")
            raise

    async def _handle_descriptor_upload(self, descriptor):
        try:
            consensus_lines = await self.try_extract_consensus_line(descriptor)
            if not consensus_lines:
                return web.Response(text="Descriptor dropped: missing fields", status=400)

            fingerprint = self.extract_fingerprint(descriptor)

            safe_filename = self._fingerprint_to_safe_filename(fingerprint)

            # 获取文件专用锁
            file_lock = await self._get_file_lock(safe_filename)

            async with file_lock:
                file_path = self.storage_dir / f"{safe_filename}.desc"
                mapping_path = self.storage_dir / f"{safe_filename}.mapping"
                temp_desc_path = self.storage_dir / f"{safe_filename}.desc.tmp"
                temp_mapping_path = self.storage_dir / f"{safe_filename}.mapping.tmp"


                # 使用临时文件 + 原子操作避免部分写入问题
                async with aiofiles.open(temp_desc_path, "w", encoding="utf-8") as f:
                    await f.write(descriptor)

                async with aiofiles.open(temp_mapping_path, "w", encoding="utf-8") as f:
                    await f.write(fingerprint)

                # 使用修复的原子移动操作
                await self._safe_atomic_move(temp_desc_path, file_path)
                await self._safe_atomic_move(temp_mapping_path, mapping_path)

                # 更新内存缓存
                self._descriptor_cache[fingerprint] = {
                    'descriptor': descriptor,
                    'safe_filename': safe_filename,
                    'timestamp': asyncio.get_event_loop().time()
                }


            # 写入共识文件（使用专用锁和改进的错误处理）
            await self._append_to_consensus_file(consensus_lines, fingerprint)

            return web.Response(text="Descriptor uploaded successfully", status=200)

        except Exception as e:
            print(f"[!] Error in descriptor upload: {e}")
            import traceback
            traceback.print_exc()
            return web.Response(text=f"Error processing descriptor: {str(e)}", status=500)

    async def _append_to_consensus_file(self, consensus_lines, fingerprint):
        """专门处理共识文件追加的方法，增强错误处理和调试信息"""
        try:


            # 使用共识文件专用锁
            async with self._consensus_lock:
                consensus_dir = self.storage_dir / "consensus"

                # 确保目录存在
                try:
                    consensus_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    print(f"[!] Failed to create consensus directory: {e}")
                    raise

                consensus_path = consensus_dir / "consensus.txt"
                temp_consensus_path = consensus_dir / "consensus.txt.tmp"



                # 准备要写入的内容
                content_to_append = consensus_lines + "\n\n"

                try:
                    # 如果原文件存在，先读取现有内容
                    existing_content = ""
                    if consensus_path.exists():
                        async with aiofiles.open(consensus_path, "r", encoding="utf-8") as f:
                            existing_content = await f.read()
                    else:
                        print(f"[+] Consensus file doesn't exist, will create new one")

                    # 写入临时文件
                    async with aiofiles.open(temp_consensus_path, "w", encoding="utf-8") as f:
                        await f.write(existing_content)
                        await f.write(content_to_append)
                        await f.flush()  # 强制刷新缓冲区


                    # 使用修复的原子移动操作
                    await self._safe_atomic_move(temp_consensus_path, consensus_path)

                    # 验证写入结果
                    if consensus_path.exists():
                        stat_result = await aiofiles.os.stat(str(consensus_path))

                        # 读取并验证内容
                        async with aiofiles.open(consensus_path, "r", encoding="utf-8") as f:
                            final_content = await f.read()
                    else:
                        print(f"[!] WARNING: Consensus file doesn't exist after write operation!")

                except Exception as e:
                    print(f"[!] Error during consensus file write: {e}")
                    import traceback
                    traceback.print_exc()
                    raise

        except Exception as e:
            print(f"[!] Critical error in _append_to_consensus_file: {e}")
            import traceback
            traceback.print_exc()
            raise

    async def _handle_descriptor_query(self, fingerprint):
        """修复：接收fingerprint字符串参数，而不是request对象"""
        try:
            # 首先检查内存缓存
            if fingerprint in self._descriptor_cache:
                cached_data = self._descriptor_cache[fingerprint]
                return web.Response(text=cached_data['descriptor'], content_type='text/plain')

            safe_filename = self._fingerprint_to_safe_filename(fingerprint)

            # 获取文件专用锁
            file_lock = await self._get_file_lock(safe_filename)

            async with file_lock:
                file_path = self.storage_dir / f"{safe_filename}.desc"
                mapping_path = self.storage_dir / f"{safe_filename}.mapping"


                # 使用异步文件检查
                try:
                    await aiofiles.os.stat(str(file_path))
                    file_exists = True
                except FileNotFoundError:
                    file_exists = False


                if file_exists:
                    # 验证映射文件
                    try:
                        await aiofiles.os.stat(str(mapping_path))
                        async with aiofiles.open(mapping_path, "r", encoding="utf-8") as f:
                            stored_fingerprint = (await f.read()).strip()

                        if stored_fingerprint != fingerprint:
                            raise web.HTTPNotFound(text="Descriptor not found")
                    except FileNotFoundError:
                        print(f"[!] Mapping file not found, but descriptor exists")

                    # 读取描述符
                    async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                        desc = await f.read()

                    # 更新缓存
                    self._descriptor_cache[fingerprint] = {
                        'descriptor': desc,
                        'safe_filename': safe_filename,
                        'timestamp': asyncio.get_event_loop().time()
                    }

                    return web.Response(text=desc, content_type='text/plain')
                else:
                    # 调试：列出存储目录中的所有文件
                    if self.storage_dir.exists():
                        files = list(self.storage_dir.glob("*.desc"))
                    raise web.HTTPNotFound(text="Descriptor not found")

        except web.HTTPNotFound:
            raise
        except Exception as e:
            print(f"[!] Error in descriptor query: {e}")
            raise web.HTTPInternalServerError(text=f"Error retrieving descriptor: {str(e)}")

    async def _handle_consensus_query(self):
        """
        响应 GET /tor/status-vote/current/consensus 请求
        返回当前共识文件内容（纯文本）
        """
        try:
            consensus_path = self.storage_dir / "consensus" / "consensus.txt"

            if not consensus_path.exists():
                # 列出consensus目录内容进行调试
                consensus_dir = self.storage_dir / "consensus"
                if consensus_dir.exists():
                    files = list(consensus_dir.glob("*"))
                    print(f"[!] Files in consensus directory: {[f.name for f in files]}")
                else:
                    print(f"[!] Consensus directory doesn't exist: {consensus_dir}")
                raise web.HTTPNotFound(text="Consensus file not found.")

            async with aiofiles.open(consensus_path, "r", encoding="utf-8") as f:
                content = await f.read()


            if not content.strip():
                raise web.HTTPNotFound(text="Consensus file is empty.")

            return web.Response(text=content, content_type="text/plain")

        except web.HTTPNotFound:
            raise
        except Exception as e:
            print(f"[!] Error in consensus query: {e}")
            import traceback
            traceback.print_exc()
            raise web.HTTPInternalServerError(text=f"Error retrieving consensus: {str(e)}")

    async def try_extract_consensus_line(self, descriptor: str) -> str:
        """提取并返回共识条目字符串，失败时返回空字符串"""

        def extract(pattern, name):
            match = re.search(pattern, descriptor, re.MULTILINE)
            if not match:
                raise ValueError(f"Missing field: {name}")
            return match.group(1)

        try:

            nickname = extract(r'^router\s+(\S+)', "nickname")
            ip = extract(r'^router\s+\S+\s+(\S+)', "ip")
            or_port = extract(r'^router\s+\S+\s+\S+\s+(\d+)', "or_port")
            dir_port = extract(r'^router\s+\S+\s+\S+\s+\d+\s+(\d+)', "dir_port")
            published = extract(r'^published\s+(.+)', "published")


            sim_flag_match = re.search(r'^sim-flags\s+(.+)', descriptor, re.MULTILINE)

            fingerprint_match = re.search(r'^fingerprint\s+([A-F0-9 ]+)', descriptor, re.MULTILINE)
            if not fingerprint_match:
                raise ValueError("Missing field: fingerprint")
            fingerprint = self.extract_fingerprint(descriptor)
            digest = compute_descriptor_digest(descriptor)


            flags = "Valid Running Stable"
            # 可选扩展自动分析 bandwidth → 添加 Fast
            bw_match = re.search(r'^bandwidth\s+(\d+)', descriptor, re.MULTILINE)
            if bw_match:
                bw = int(bw_match.group(1))
                if bw > 50000:
                    flags += " Fast"

            if sim_flag_match:
                user_flags = sim_flag_match.group(1).split()
                for f in user_flags:
                    if f not in flags:
                        flags += f" {f}"

            version = extract(r'^platform\s+(.*)', "version")
            proto = extract(r'^proto\s+(.*)', "proto")
            bandwidth = extract(r'^bandwidth\s+(\d+)', "bandwidth")

            policy_match = re.search(r'^(reject|accept)\s+(.+)', descriptor, re.MULTILINE)
            policy = f"{policy_match.group(1)} {policy_match.group(2)}" if policy_match else "reject 1-65535"


            consensus_lines = [
                f"r {nickname} {fingerprint} {digest} {published} {ip} {or_port} {dir_port}",
                f"s {flags}",
                f"v {version}",
                f"pr {proto}",
                f"w Bandwidth={bandwidth}",
                f"p {policy}",
            ]

            result = "\n".join(consensus_lines)
            return result

        except Exception as e:
            print(f"[!] Failed to extract consensus from descriptor: {e}")
            import traceback
            traceback.print_exc()
            return ""

    async def run(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()

        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            print("[*] Cleaning up server and temporary files...")
            await runner.cleanup()
            self._cleanup()

    def _cleanup(self):
        try:
            self._tempdir_obj.cleanup()
            print(f"[+] Temporary directory {self.storage_dir} deleted.")
        except Exception as e:
            print(f"[!] Failed to delete temp dir: {e}")


def compute_descriptor_digest(descriptor: str, *, encoding: str = "hex") -> str:
    """
    计算服务器 descriptor 的 SHA-1 digest。
    """
    match = re.search(r'\nrouter-signature\n', descriptor)
    cut = descriptor[:match.start() + 1] if match else descriptor
    digest_bin = hashlib.sha1(cut.encode('utf-8')).digest()

    if encoding == "hex":
        return digest_bin.hex().upper()
    if encoding == "base64":
        return base64.b64encode(digest_bin).decode('ascii')
    raise ValueError("encoding must be 'hex' or 'base64'")


def parse_single_consensus_entry(entry_str: str) -> dict:
    """
    Parse a single router consensus block into a dictionary.

    :param entry_str: Multiline string representing a single consensus entry.
    :return: Dictionary with parsed fields.
    """
    relay = {}
    lines = entry_str.strip().splitlines()

    for line in lines:
        if line.startswith('r '):
            parts = line.strip().split()
            relay["nickname"] = parts[1]
            relay["fingerprint"] = parts[2]
            relay["digest"] = parts[3]
            relay["service_key"] = parts[3]
            relay["ip"] = parts[6]
            relay["or_port"] = int(parts[7])
            relay["dir_port"] = int(parts[8])

        elif line.startswith('s '):
            relay["flags"] = line[2:].split()

        elif line.startswith('p '):
            relay["exit_policy"] = line[2:].strip()

        elif line.startswith('v '):
            relay["version"] = line[2:].strip()

        elif line.startswith('pr '):
            relay["protocols"] = line[3:].strip()

        elif line.startswith('w '):
            parts = line[2:].split()
            for part in parts:
                if part.startswith('Bandwidth='):
                    relay["bandwidth"] = int(part.split('=')[1])

    return relay


def parse_full_consensus(consensus_text: str):
    """
    Parses a full Tor consensus file into header, router blocks, footer, and directory signatures.

    :param consensus_text: The full consensus file text as a string.
    :return: A dictionary with 'header', 'routers', 'footer', and 'signatures'.
    """
    lines = consensus_text.strip().splitlines()
    header_lines = []
    router_entries = []
    footer_lines = []
    signatures = []

    current_router = []
    in_router_section = False
    in_footer = False
    current_signature = []

    for line in lines:
        if line.startswith("r ") and not in_footer:
            if current_router:
                router_entries.append("\n".join(current_router))
                current_router = []
            current_router.append(line)
            in_router_section = True

        elif line.startswith("directory-footer"):
            if current_router:
                router_entries.append("\n".join(current_router))
                current_router = []
            in_router_section = False
            in_footer = True
            footer_lines.append(line)

        elif in_footer:
            footer_lines.append(line)
            if line.startswith("directory-signature "):
                if current_signature:
                    signatures.append(_parse_signature_block(current_signature))
                    current_signature = []
                current_signature = [line]
            elif line.startswith("-----BEGIN SIGNATURE-----"):
                current_signature.append(line)
            elif line.startswith("-----END SIGNATURE-----"):
                current_signature.append(line)
                signatures.append(_parse_signature_block(current_signature))
                current_signature = []
            elif current_signature:
                current_signature.append(line)

        elif in_router_section:
            current_router.append(line)

        else:
            header_lines.append(line)

    if current_router:
        router_entries.append("\n".join(current_router))

    return {
        "header": "\n".join(header_lines),
        "routers": router_entries,
        "footer": "\n".join(footer_lines),
        "signatures": signatures
    }


def _parse_signature_block(sig_lines):
    """
    Parses a directory-signature block.
    """
    header = sig_lines[0].strip()
    match = re.match(r"directory-signature (\S+) (\S+)", header)
    fingerprint, digest = match.groups() if match else ("?", "?")
    sig_block = "\n".join(sig_lines[1:])
    return {
        "fingerprint": fingerprint,
        "digest": digest,
        "signature": sig_block
    }

def parse_urlsafe_fingerprint(encoded: str) -> str:
    padding = '=' * (-len(encoded) % 4)
    raw = base64.urlsafe_b64decode(encoded + padding)
    return base64.b64encode(raw).decode('ascii').rstrip('=')

# 方案1: 使用哈希值作为文件名（推荐）
def fingerprint_to_filename_hash(fingerprint: str) -> str:
    """
    将fingerprint转换为SHA256哈希值作为文件名
    这样可以避免特殊字符问题，同时保证唯一性
    """
    return hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()