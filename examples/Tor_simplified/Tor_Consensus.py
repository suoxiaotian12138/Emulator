# directory.py
from __future__ import annotations

import random
import aiohttp
from typing import Dict, List, Optional
from datetime import datetime
import base64
import binascii
from stem.descriptor.remote import DescriptorDownloader
from stem.descriptor.server_descriptor import RelayDescriptor



class Tor_Consensus:
    """Download a consensus and extract relay information."""
    def __init__(self, model, dire_ip='127.0.0.1', dire_port=9030) -> None:
        self.dire_ip = dire_ip
        self.dire_port = dire_port
        self.fetch_consensus, self.fetch_descriptor = self.setup_model(model)
        self.relays = None

    async def consus_init(self):
        self.relays = await self.fetch_consensus()


    def setup_model(self, model):
        if model == 'real':
            return self._fetch_consensus_real, self._fetch_descriptor_real
        elif model == 'sim':
            return self._fetch_consensus_sim, self._fetch_descriptor_sim

    async def _fetch_consensus_real(self, *, endpoints: Optional[List] = None):
        """
        Download the latest consensus and cache it in `self._consensus`.
        """
        from stem.descriptor.remote import get_consensus

        result = get_consensus(endpoints=endpoints, timeout=300).run()  # -> list
        consensus = result
        return self._relays_parse(consensus)

    @staticmethod
    async def _fetch_descriptor_real(fingerprint: str, timeout: int = 30) -> RelayDescriptor:
        fp = fingerprint

        processed = []
        if len(fp) == 27:  # base64格式
            fp = base64_to_hex_fingerprint(fp)
        elif len(fp) == 40:  # 十六进制格式
            fp = fp.upper()
        processed.append(fp)

        downloader = DescriptorDownloader(timeout=timeout)

        # ── Stem allows up to 96 fingerprints per request ───────────────────────────
        query = downloader.get_server_descriptors(fingerprints=fp)
        descriptor = query.run()  # blocks until the batch finishes

        if not descriptor:
            raise RuntimeError("No descriptors retrieved – check network connectivity.")
        return descriptor[0].__str__()

    async def _fetch_consensus_sim(self):
        url = f"http://{self.dire_ip}:{self.dire_port}/tor/status-vote/current/consensus"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        consensus = split_tor_descriptors(text)
                        return self._relays_parse(consensus)

                    else:
                        print(f"[!] Failed to query consensus: HTTP {resp.status}")
        except Exception as e:
            print(f"[!] Exception during consensus query: {e}")

    async def _fetch_descriptor_sim(self, fingerprint):
        print(fingerprint)
        safe_fingerprint = make_urlsafe_fingerprint(fingerprint)

        url = f"http://{self.dire_ip}:{self.dire_port}/tor/server/desc/{safe_fingerprint}"
        print("_fetch_descriptor_sim: ", url)
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as resp:
                    text = await resp.text()
                    return text
        except Exception as e:
            print(f"[!] Query failed: {e}")

    def _relays_parse(self, consensus) -> List[Dict]:
        """
        Parse the cached consensus and return a list of relay dicts.
        Each dict contains: fingerprint, nickname, ip, or_port, dir_port, flags.
        """
        relays = []
        for node in consensus:
            node_str = node.__str__()
            relay_info = parse_single_consensus_entry(node_str)
            relays.append(relay_info)
        return relays

    @property
    def valid_after(self) -> datetime | None:
        """Returns the consensus ‘valid‑after’ timestamp."""
        if not self.relays:
            return None
        return getattr(self.relays, "valid_after", None)

    def get_routers(self, flags=None, has_dir_port=True, with_renew=True):
        """
        Select consensus routers that satisfy certain parameters.

        :param flags: Router flags
        :param has_dir_port: Has dir port
        :param with_renew: do renew consensus if old
        :return: return list of routers
        """
        results = []

        for onion_router in self.relays:
            if flags and not all(f in onion_router["flags"] for f in flags):
                continue
            if has_dir_port and not onion_router["dir_port"]:
                continue
            results.append(onion_router)

        return results

    def get_random_router(self, flags=None, has_dir_port=None, with_renew=True):

        routers = self.get_routers(flags, has_dir_port, with_renew)
        return random.choice(routers)

    def get_random_guard_node(self, different_flags=None):
        flags = different_flags or ['Guard']
        return self.get_random_router(flags)

    def get_random_exit_node(self):
        flags = ['Fast', 'Running', 'Valid', 'Exit']
        return self.get_random_router(flags)

    def get_random_middle_node(self):
        # 为了方便处理，暂时先添加一个middle标签，实际并不存在
        flags = ['Fast', 'Running', 'Valid', 'Middle']
        # flags = ['Fast', 'Running', 'Valid']
        return self.get_random_router(flags)

def split_tor_descriptors(text: str) -> list[str]:
    """
    将以 'r ' 开头的多段 Tor 共识描述文本按段拆分为列表。
    每一段从 'r ' 开始，直到遇到下一个 'r ' 或文件结尾。
    """
    blocks = []
    current_block = []

    for line in text.strip().splitlines():
        if line.startswith("r "):
            if current_block:
                blocks.append("\n".join(current_block))
                current_block = []
        current_block.append(line)

    if current_block:
        blocks.append("\n".join(current_block))

    return blocks



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


def base64_to_hex_fingerprint(base64_fp):
    """
    将base64格式的指纹转换为十六进制格式
    共识中的指纹是base64编码的，但很多API需要十六进制格式
    """
    try:
        # 解码base64
        decoded = base64.b64decode(base64_fp + '==')  # 添加padding以防万一
        # 转换为十六进制
        hex_fp = binascii.hexlify(decoded).decode('utf-8').upper()
        return hex_fp
    except Exception as e:
        print(f"指纹格式转换失败: {e}")
        return None

def make_urlsafe_fingerprint(fp: str) -> str:
    # 补齐 padding，解码成原始 bytes，然后再用 url-safe 编码
    padding = '=' * (-len(fp) % 4)
    raw = base64.b64decode(fp + padding)
    urlsafe = base64.urlsafe_b64encode(raw).decode('ascii')
    return urlsafe.rstrip('=')

def hex_to_base64_fingerprint(hex_fp):
    """
    将十六进制格式的指纹转换为base64格式
    """
    try:
        # 移除可能的空格和冒号
        hex_fp = hex_fp.replace(':', '').replace(' ', '')
        # 转换为字节
        bytes_fp = binascii.unhexlify(hex_fp)
        # 编码为base64并移除padding
        b64_fp = base64.b64encode(bytes_fp).decode('utf-8').rstrip('=')
        return b64_fp
    except Exception as e:
        print(f"指纹格式转换失败: {e}")
        return None

if __name__ == "__main__":
    # with open("consesus.txt", "r", encoding="utf-8") as f:
    #     consensus = f.read()
    #
    # logging.basicConfig(level=logging.INFO)

    # --- Stem backend -------------------------------------------------- #
    d_stem = Tor_Consensus()
    guards = [r for r in d_stem.relays if "Guard" in r["flags"]]

    print(f"[Stem] total relays={len(d_stem.relays)}  guards={len(guards)}")
    print(d_stem.relays[0])
    print(type(d_stem.get_random_middle_node()))
