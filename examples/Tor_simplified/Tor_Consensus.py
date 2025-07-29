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
    def __init__(self, model, dire_ip='192.168.66.241', dire_port=9030) -> None:
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
        Download the latest consensus.
        """
        from stem.descriptor.remote import get_consensus

        result = get_consensus(endpoints=endpoints, timeout=300).run()  # -> list
        consensus = result
        return self._relays_parse(consensus)

    @staticmethod
    async def _fetch_descriptor_real(fingerprint: str, timeout: int = 30) -> RelayDescriptor:
        fp = fingerprint

        processed = []
        if len(fp) == 27:
            fp = base64_to_hex_fingerprint(fp)
        elif len(fp) == 40:
            fp = fp.upper()
        processed.append(fp)

        downloader = DescriptorDownloader(timeout=timeout)

        query = downloader.get_server_descriptors(fingerprints=fp)
        descriptor = query.run()

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
        # safe_fingerprint = make_urlsafe_fingerprint(fingerprint)
        url = f"http://{self.dire_ip}:{self.dire_port}/tor/server/fp/{fingerprint}"
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

    def get_random_router(self, flags=None, has_dir_port=None, exclude=None):
        exclude = set(exclude or [])
        routers = self.get_routers(flags, has_dir_port)
        candidates = [r for r in routers if r["fingerprint"] not in exclude]

        if not candidates:
            raise RuntimeError("No available routers after exclusion")
        return random.choice(candidates)

    def get_random_guard_node(self, exclude=None):
        flags = ['Guard']
        return self.get_random_router(flags=flags, exclude=exclude)

    def get_random_middle_node(self, exclude=None):
        flags = ['Fast', 'Running', 'Valid']
        return self.get_random_router(flags=flags, exclude=exclude)

    def get_random_exit_node(self, exclude=None):
        flags = ['Exit', 'Fast', 'Running', 'Valid']
        return self.get_random_router(flags=flags, exclude=exclude)


def split_tor_descriptors(text: str) -> list[str]:
    """
    将共识文本拆分为合法的 relay descriptor 块，过滤掉 header 和非节点段。
    每个块以 'r ' 开头，至少包含一个 's ' 行（节点 flags）。
    """
    blocks = []
    current_block = []
    has_s_line = False  # 标记是否包含 s 行

    for line in text.strip().splitlines():
        if line.startswith("r "):
            if current_block and has_s_line:
                blocks.append("\n".join(current_block))
            current_block = [line]
            has_s_line = False
        elif line.startswith(("s ", "v ", "pr ", "w ", "p ")):
            current_block.append(line)
            if line.startswith("s "):
                has_s_line = True
        elif current_block:
            current_block.append(line)

    if current_block and has_s_line:
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


