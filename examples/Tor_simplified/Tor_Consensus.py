from __future__ import annotations


from stem.descriptor.remote import DescriptorDownloader
from stem.descriptor.server_descriptor import RelayDescriptor

import aiohttp, asyncio, random, base64, binascii
from typing import Optional, List, Dict
from datetime import datetime
import hashlib, time, statistics
from typing import Optional, List, Dict

class Tor_Consensus:
    def __init__(self, model, dire_ip='192.168.66.241', dire_port=9030) -> None:
        self.dire_ip = dire_ip
        self.dire_port = dire_port
        self._session: aiohttp.ClientSession | None = None      # ★ 持久化 session
        self.fetch_consensus, self.fetch_descriptor = self.setup_model(model)
        self.relays: Optional[List[Dict]] = None
        # === NEW: 元数据（仅存储，不做日志） ===
        self.model = model
        self.consensus_id: Optional[str] = None  # 稳定ID
        self.fetched_at: Optional[float] = None  # time.time()
        self.meta: Dict = {}  # 摘要统计（数量/旗标/带宽）
        # （real 模式下你可以后续再填 valid_after/valid_until）

    def setup_model(self, model):
        if model == 'real':
            return self._fetch_consensus_real, self._fetch_descriptor_real
        elif model == 'sim':
            return self._fetch_consensus_sim, self._fetch_descriptor_sim

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

    # ---------- Session 生命周期 ----------
    async def _ensure_session(self):
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(limit=128, ssl=False)
            )
        return self._session

    async def aclose(self):
        if self._session and not self._session.closed:
            await self._session.close()

    # ---------- 外部入口 ----------
    async def consus_init_async(self):
        """异步拉取共识并解析。【轻改动】填充 consensus_id/meta，但不做日志。"""
        self.relays = await self.fetch_consensus()
        # NEW: 拉取成功后生成 ID/摘要
        self.fetched_at = time.time()
        self.consensus_id = self._compute_consensus_id(self.relays, self.model, self.dire_ip, self.dire_port)
        self.meta = self._summarize_relays(self.relays)

    # ---------- SIM model ----------
    async def _fetch_consensus_sim(self):
        sess = await self._ensure_session()                      # ★
        url = f"http://{self.dire_ip}:{self.dire_port}/tor/status-vote/current/consensus"
        async with sess.get(url, timeout=10) as resp:
            resp.raise_for_status()
            text = await resp.text()
        consensus = split_tor_descriptors(text)
        return self._relays_parse(consensus)

    async def _fetch_descriptor_sim(self, fingerprint: str):
        sess = await self._ensure_session()                      # ★
        url = f"http://{self.dire_ip}:{self.dire_port}/tor/server/fp/{fingerprint}"
        async with sess.get(url, timeout=5) as resp:
            resp.raise_for_status()
            return await resp.text()

    # ---------- REAL model ----------
    # 保持原同步逻辑，用线程池包一层以防真运行 real 时阻塞
    async def _fetch_consensus_real(self, *, endpoints: Optional[List] = None):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.__fetch_consensus_real_sync, endpoints)

    def __fetch_consensus_real_sync(self, endpoints):
        from stem.descriptor.remote import get_consensus
        consensus = get_consensus(endpoints=endpoints, timeout=300).run()
        return self._relays_parse(consensus)

    async def _fetch_descriptor_real(self, fingerprint: str, timeout: int = 30):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._fetch_desc_real_sync, fingerprint, timeout)


    @staticmethod
    async def _fetch_desc_real_sync(fingerprint: str, timeout: int = 30) -> RelayDescriptor:
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

    @staticmethod
    def _compute_consensus_id(relays: List[Dict], model: str, dire_ip: str, dire_port: int) -> str:
        fps = [r.get("fingerprint", "") for r in relays]
        fps = [fp.upper() for fp in fps if fp]  # 统一 HEX 大写
        fps.sort()
        base = f"{model}|{dire_ip}:{dire_port}|{','.join(fps)}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]  # 取前16位即可

    # === NEW: 做一个很轻的摘要，便于写到 paths/circuits 里当标签或供分析使用 ===
    @staticmethod
    def _summarize_relays(relays: List[Dict]) -> Dict:
        n = len(relays)
        flags_count = {"Guard": 0, "Exit": 0, "Fast": 0, "Running": 0, "Valid": 0}
        bw = []
        for r in relays:
            rf = r.get("flags", [])
            for f in flags_count.keys():
                if f in rf: flags_count[f] += 1
            if "bandwidth" in r and isinstance(r["bandwidth"], int):
                bw.append(r["bandwidth"])
        bw_stats = {}
        if bw:
            # 注意：statistics.quantiles 默认等分；这里只要中位数就行
            try:
                p50 = statistics.median(bw)
            except Exception:
                p50 = None
            bw_stats = {"count": len(bw), "mean": statistics.fmean(bw), "p50": p50,
                        "min": min(bw), "max": max(bw)}
        return {"count": n, "flags": flags_count, "bandwidth": bw_stats}

    # === NEW: 对外快照接口（client 用这个拿到 id+摘要） ===
    def get_consensus_snapshot(self) -> Dict:
        """
        返回 {'consensus_id', 'fetched_at', 'meta', 'dire', 'model'}
        （纯数据，不做任何日志/副作用）
        """
        return {
            "consensus_id": self.consensus_id,
            "fetched_at": self.fetched_at,
            "meta": self.meta,
            "dire": f"{self.dire_ip}:{self.dire_port}",
            "model": self.model,
        }

    # === NEW: 可选的“按TTL刷新”接口（你愿意再用，不用也行；不写日志） ===
    def should_refresh(self, ttl_sec: int = 3600) -> bool:
        return (self.fetched_at is None) or (time.time() - self.fetched_at >= ttl_sec)

    async def refresh_if_needed(self, ttl_sec: int = 3600):
        if self.should_refresh(ttl_sec):
            await self.consus_init_async()


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


