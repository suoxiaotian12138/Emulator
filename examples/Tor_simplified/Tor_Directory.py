# directory.py
from __future__ import annotations

import asyncio
import hashlib
from typing import Dict, List, Optional
from datetime import datetime
from pathlib import Path
from aiohttp import web
import re

class TorDirectoryServer:
    def __init__(self, host='127.0.0.1', port=9030, storage_dir='descriptors'):
        self.host = host
        self.port = port
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.app = web.Application()
        self._setup_routes()

    def _setup_routes(self):
        self.app.router.add_post("/tor/post/dir", self.handle_descriptor_upload)
        self.app.router.add_get("/tor/server/desc/{fingerprint}", self.handle_descriptor_query)
        self.app.router.add_get("/tor/status-vote/current/consensus", self.handle_consensus_query)

    async def handle_descriptor_upload(self, request):
        descriptor = await request.text()
        print("[+] Received server descriptor:")
        await self._handle_descriptor_upload(descriptor)
        return web.Response(text="Descriptor received.")

    async def handle_descriptor_query(self, request):
        fingerprint = request.match_info['fingerprint']
        print(f"[+] Received descriptor query for fingerprint: {fingerprint}")
        return await self._handle_descriptor_query(fingerprint)

    async def handle_consensus_query(self, request):
        print("[+] Received consensus request")
        return await self._handle_consensus_query()

    def extract_fingerprint(self, descriptor: str) -> str:
        match = re.search(r'^fingerprint\s+([A-Z0-9 ]+)', descriptor, re.MULTILINE)
        if match:
            # Remove spaces and make it compact
            return match.group(1).replace(" ", "")
        else:
            # fallback: SHA1 hash
            return hashlib.sha1(descriptor.encode()).hexdigest()

    async def _handle_descriptor_upload(self, descriptor: str):
        if not self.try_extract_consensus_line(descriptor):
            print("[!] Descriptor dropped: missing fields")
            return
        fingerprint = self.extract_fingerprint(descriptor)
        file_path = self.storage_dir / f"{fingerprint}.desc"
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(descriptor)

    async def _handle_descriptor_query(self, fingerprint: str):
        file_path = self.storage_dir / f"{fingerprint}.desc"
        if file_path.exists():
            with open(file_path, "r", encoding="utf-8") as f:
                desc = f.read()
            # send back descriptor
            return web.Response(text=desc, content_type='text/plain')
        else:
            raise web.HTTPNotFound(text="Descriptor not found")

    async def _handle_consensus_query(self):
        """
        响应 GET /tor/status-vote/current/consensus 请求
        返回当前共识文件内容（纯文本）
        """
        consensus_path = self.storage_dir / "consensus" / "consensus.txt"

        if not consensus_path.exists():
            raise web.HTTPNotFound(text="Consensus file not found.")
        content = consensus_path.read_text(encoding="utf-8").strip()
        if not content:
            raise web.HTTPNotFound(text="Consensus file is empty.")
        return web.Response(text=content + "\n", content_type="text/plain")


    def try_extract_consensus_line(self, descriptor: str) -> bool:
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
            fingerprint_full = fingerprint_match.group(1).replace(" ", "")
            fingerprint = fingerprint_full[:32]
            fingerprint_rest = fingerprint_full[32:]

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
                f"r {nickname} {fingerprint} {fingerprint_rest} {published} {ip} {or_port} {dir_port}",
                f"s {flags}",
                f"v {version}",
                f"pr {proto}",
                f"w Bandwidth={bandwidth}",
                f"p {policy}",
            ]

            consensus_dir = self.storage_dir / "consensus"
            consensus_dir.mkdir(parents=True, exist_ok=True)
            consensus_path = consensus_dir / "consensus.txt"
            with open(consensus_path, "a", encoding="utf-8") as f:
                f.write("\n".join(consensus_lines))
                f.write("\n\n")

            return True

        except Exception as e:
            print(f"[!] Failed to extract consensus from descriptor: {e}")
            return False
    async def run(self):
        runner = web.AppRunner(self.app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        print(f"[*] Server running at http://{self.host}:{self.port}")
        await site.start()

        # 等待信号终止，而不是无限循环
        try:
            await asyncio.Event().wait()  # 永久等待直到被取消
        except asyncio.CancelledError:
            await runner.cleanup()

if __name__ == "__main__":
    dir_server = TorDirectoryServer()
    asyncio.run(dir_server.run())














class Directory:
    """Download a consensus and extract relay information."""

    def __init__(self) -> None:
        self._consensus = None  # raw consensus object

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def fetch_consensus(self, *, endpoints: Optional[List] = None) -> None:
        """
        Download the latest consensus and cache it in `self._consensus`.

        Parameters
        ----------
        endpoints : optional
            A list of specific directory mirrors or authorities to query
            (only meaningful for the Stem backend). If omitted Stem falls
            back to its baked‑in list of “fallback dir” nodes.  Torpy always
            rotates over the current authorities automatically.
        """
        # Stem returns a generator; the first (and only) element is the doc
        from stem.descriptor.remote import get_consensus

        result = get_consensus(endpoints=endpoints, timeout=300).run()  # -> list
        print(result[0].__str__())
        print(type(result[0]))
        self._consensus = result

    @property
    def valid_after(self) -> datetime | None:
        """Returns the consensus ‘valid‑after’ timestamp."""
        if not self._consensus:
            return None
        return getattr(self._consensus, "valid_after", None)

    def relays_parse(self) -> List[Dict]:
        """
        Parse the cached consensus and return a list of relay dicts.

        Each dict contains: fingerprint, nickname, ip, or_port, dir_port, flags.
        """
        if self._consensus is None:
            self.fetch_consensus()

        relays = []
        for node in self._consensus:
            node_str = node.__str__()
            relay_info = parse_single_consensus_entry(node_str)
            # relay_info = {
            #     "exit_policy": node.exit_policy.summary() if node.exit_policy else "none",
            #     "digest": node.digest,
            #     "dir_port": node.dir_port,
            #     "service_key": node.identifier,  # Ed25519 base64 string
            #     "nickname": node.nickname,
            #     "ip": node.address,
            #     "or_port": node.or_port,
            #     "flags": list(node.flags),
            # }
            relays.append(relay_info)

        return relays


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


if __name__ == "__main__":
    # with open("consesus.txt", "r", encoding="utf-8") as f:
    #     consensus = f.read()
    #
    # logging.basicConfig(level=logging.INFO)

    # --- Stem backend -------------------------------------------------- #
    d_stem = Directory()
    d_stem.fetch_consensus()  # downloads in ~1 s
    guards = [r for r in d_stem.relays_parse() if "Guard" in r["flags"]]
    print(f"[Stem] total relays={len(d_stem.relays_parse())}  guards={len(guards)}")


