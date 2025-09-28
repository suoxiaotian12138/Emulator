import asyncio
import contextlib
import random
import time
from collections import deque
import math
from typing import Optional, Tuple
import geoip2.database
import aiohttp


# ========= 目录客户端（只需能拿到 descriptor 原文） =========

class DirectoryClient:
    """
    通过 HTTP 目录拿描述符文本，要求目录实现 /tor/server/fp/<fingerprint>。
    你已有目录服务的话，base_url 形如 "http://127.0.0.1:8080"。
    """
    def __init__(self, base_url: str, session: Optional["aiohttp.ClientSession"] = None):
        self.base_url = base_url.rstrip("/")
        self._sess = session

        if aiohttp is None:
            raise RuntimeError("aiohttp is required for DirectoryClient")

    async def _ensure(self) -> "aiohttp.ClientSession":
        if self._sess is None or self._sess.closed:
            self._sess = aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=64, ssl=False))
        return self._sess

    async def get_descriptor(self, fingerprint: str, timeout: float = 5.0) -> str:
        sess = await self._ensure()
        url = f"{self.base_url}/tor/server/fp/{fingerprint}"
        async with sess.get(url, timeout=timeout) as r:
            r.raise_for_status()
            return await r.text()

    async def aclose(self):
        if self._sess and not self._sess.closed:
            await self._sess.close()


# ========= 描述符解析 & 映射缓存 =========

def parse_sim_ip_from_descriptor(desc_text: str) -> Optional[str]:
    """
    在 descriptor 文本中解析 "opt sim-ip <ip>" 行；若没有返回 None。
    """
    for line in desc_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # 大小写不敏感
        lower = line.lower()
        if lower.startswith("opt sim-ip"):
            parts = line.split()
            if len(parts) >= 3:
                return parts[2].strip()
    return None


class MappingCache:
    """
    指纹/IP -> sim_ip 的轻量缓存，TTL 过期自动刷新。
    仅在“首次与某个对端通信”或 TTL 过期时才访问目录，平时走内存。
    """
    def __init__(self, directory: DirectoryClient, default_sim_ip: str = "1.1.1.1", ttl_sec: float = 300.0):
        self.dir = directory
        self.default_sim_ip = default_sim_ip
        self.ttl = float(ttl_sec)
        self._fp2sim: dict[str, Tuple[str, float]] = {}           # fp -> (sim_ip, expires_at)
        self._addr2sim: dict[Tuple[str, int], Tuple[str, float]] = {}  # 退化用

    @staticmethod
    def _now() -> float:
        return time.monotonic()

    async def resolve_by_fp(self, fingerprint: str) -> str:
        now = self._now()
        hit = self._fp2sim.get(fingerprint)
        if hit and hit[1] > now:
            return hit[0]
        # miss: 去目录取 descriptor
        try:
            desc = await self.dir.get_descriptor(fingerprint)
            sim = parse_sim_ip_from_descriptor(desc) or self.default_sim_ip
        except Exception:
            sim = self.default_sim_ip
        self._fp2sim[fingerprint] = (sim, now + self.ttl)
        return sim

    def cache_addr(self, addr: Tuple[str, int], sim_ip: str, ttl: Optional[float] = None):
        self._addr2sim[addr] = (sim_ip, self._now() + (ttl or self.ttl))

    async def resolve_peer(self, fingerprint: Optional[str], addr: Optional[Tuple[str, int]]) -> str:
        if fingerprint:
            return await self.resolve_by_fp(fingerprint)
        if addr:
            now = self._now()
            hit = self._addr2sim.get(addr)
            if hit and hit[1] > now:
                return hit[0]
        return self.default_sim_ip


# ========= 地理延迟模型（只做“传播+抖动”） =========

class GeoDelayModel:
    """
    只实现地理传播延迟与抖动。默认策略：
      - 如果 src_sim == dst_sim：返回 1ms
      - 否则返回 40ms（你可以传入自定义函数/表，替换这个策略）
    抖动：~10% 基于截断正态，最多 ±30%
    """
    def __init__(self, latency_fn=None, jitter_ratio: float = 0.10, jitter_cap: float = 0.30, floor_ms: float = 1.0):
        """
        latency_fn: Callable(src_sim_ip:str, dst_sim_ip:str) -> base_ms
        jitter_ratio: 抖动标准差占基线比例（默认 10%）
        jitter_cap: 抖动截断上限（默认 ±30%）
        floor_ms: 同地最低 1ms
        """
        self.latency_fn = latency_fn or self._default_latency
        self.jitter_ratio = float(jitter_ratio)
        self.jitter_cap = float(jitter_cap)
        self.floor_ms = float(floor_ms)

    @staticmethod
    def _default_latency(src_sim: str, dst_sim: str) -> float:
        if src_sim == dst_sim:
            return 1.0
        return 40.0  # 你可以换成基于区域/AS 的 lookup

    def base_owd_ms(self, src_sim: str, dst_sim: str) -> float:
        return max(self.floor_ms, float(self.latency_fn(src_sim, dst_sim)))

    def jitter_ms(self, base_ms: float) -> float:
        sigma = max(0.2, base_ms * self.jitter_ratio)
        j = random.gauss(0.0, sigma)
        cap = base_ms * self.jitter_cap
        if j > cap:
            j = cap
        elif j < -cap:
            j = -cap
        # 传播延迟是非负，这里只允许“增加或少量不增加”，不允许变成负值
        return max(0.0, j)


# ========= 写端注入器（只做地理延迟；不做带宽/排队） =========

class DelayInjectorWriter:
    """
    包装底层 writer，把“地理传播延迟 + 抖动”注入到 *首批* 数据：
      - 当队列从 empty -> non-empty：等待 base_owd + jitter 后 flush 一次（“预热”）
      - 队列持续非空时：立即 flush（不再叠加传播延迟），直到清空
      - 队列再次从空 -> 非空：重复“预热”

    这样可让握手/首包体现地理 RTT，而不会把连续数据人为限速。
    """

    def __init__(
        self,
        writer,                         # 必须有 write() / drain()
        *,
        src_sim_ip: str,
        dst_sim_ip: str,
        model: GeoDelayModel,
        max_batch_bytes: int = 64 * 1024
    ):
        self._w = writer
        self._loop = asyncio.get_running_loop()
        self._src = src_sim_ip
        self._dst = dst_sim_ip
        self._model = model

        self._base_s = (self._model.base_owd_ms(self._src, self._dst) + self._model.jitter_ms(
            self._model.base_owd_ms(self._src, self._dst))) / 1000.0

        self._q: deque[bytes] = deque()
        self._wake = asyncio.Event()
        self._closed = False
        self._task: Optional[asyncio.Task] = None
        self._max_batch = int(max_batch_bytes)

        # 管线状态：cold -> 首次需要等待 base；hot -> 立即 flush；empty -> 回到 cold
        self._pipeline_hot = False

    # -------- 工厂方法：帮你解析对端 sim-ip 并创建 ----------
    @classmethod
    async def create(
        cls,
        writer,
        *,
        local_sim_ip: str,
        peer_fingerprint: Optional[str],
        peer_addr: Optional[Tuple[str, int]],
        mapping: MappingCache,
        model: GeoDelayModel,
        max_batch_bytes: int = 64 * 1024
    ) -> "DelayInjectorWriter":
        dst_sim = await mapping.resolve_peer(peer_fingerprint, peer_addr)
        inst = cls(
            writer,
            src_sim_ip=local_sim_ip,
            dst_sim_ip=dst_sim,
            model=model,
            max_batch_bytes=max_batch_bytes
        )
        await inst.start()
        return inst

    async def start(self):
        if self._task is None:
            self._task = asyncio.create_task(self._writer_loop())

    async def aclose(self):
        self._closed = True
        self._wake.set()
        if self._task:
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def send(self, blob: bytes):
        if self._closed:
            return
        self._q.append(blob)
        self._wake.set()

    # -------- 内部：写循环 --------
    async def _writer_loop(self):
        try:
            while not self._closed:
                # 没数据就等待
                if not self._q:
                    self._pipeline_hot = False  # 队列空了，回到 cold 状态
                    self._wake.clear()
                    try:
                        await asyncio.wait_for(self._wake.wait(), timeout=5.0)
                    except asyncio.TimeoutError:
                        continue

                # 队列非空；若尚未“预热”，先等待一次 base 传播+抖动
                if not self._pipeline_hot:
                    # 重新计算一遍 jitter（让每次“预热”不完全相同）
                    base_ms = self._model.base_owd_ms(self._src, self._dst)
                    jitter_ms = self._model.jitter_ms(base_ms)
                    base_s = (base_ms + jitter_ms) / 1000.0
                    if base_s > 0:
                        await asyncio.sleep(base_s)
                    self._pipeline_hot = True

                # 批量取数据并写
                out = bytearray()
                while self._q and len(out) < self._max_batch:
                    out += self._q.popleft()

                if out:
                    self._w.write(out)
                    await self._w.drain()
                else:
                    # 没取到数据（极少发生）
                    await asyncio.sleep(0)
        except asyncio.CancelledError:
            pass
        finally:
            # 尝试把剩余写掉
            try:
                while self._q:
                    out = bytearray()
                    while self._q and len(out) < self._max_batch:
                        out += self._q.popleft()
                    self._w.write(out)
                    await self._w.drain()
            except Exception:
                pass


# ======== GeoIP 驱动：经纬度 -> 大圆距离 -> OWD(ms) ========



def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """大圆距离（km）"""
    R = 6371.0088
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = phi2 - phi1
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlmb/2)**2
    return 2 * R * math.asin(math.sqrt(a))


class GeoIPLocator:
    """
    轻量 GeoIP 封装：优先给出 (lat, lon)，没有则给区域码（continent/country）。
    - 依赖 geoip2 + 本地 mmdb（建议用 GeoLite2-City.mmdb）
    - 内置缓存，避免热路径频繁 I/O
    """
    def __init__(self, mmdb_path: Optional[str] = None):
        self._reader = None
        if mmdb_path and geoip2:
            self._reader = geoip2.database.Reader(mmdb_path)
        self._cache: dict[str, Tuple[Optional[float], Optional[float], Optional[str], Optional[str]]] = {}

    def close(self):
        if self._reader:
            self._reader.close()

    def lookup(self, ip: str) -> Tuple[Optional[float], Optional[float], Optional[str], Optional[str]]:
        """
        返回 (lat, lon, continent_code, country_iso)
        任一取不到则为 None
        """
        hit = self._cache.get(ip)
        if hit is not None:
            return hit
        lat = lon = None
        cont = country = None
        try:
            if self._reader:
                r = self._reader.city(ip)
                if r.location and (r.location.latitude is not None) and (r.location.longitude is not None):
                    lat, lon = float(r.location.latitude), float(r.location.longitude)
                cont = getattr(getattr(r, "continent", None), "code", None)
                country = getattr(getattr(r, "country", None), "iso_code", None)
        except Exception:
            pass
        self._cache[ip] = (lat, lon, cont, country)
        return self._cache[ip]


# 一个合理的“区域对单向延迟 OWD(ms)”回退表（你可按测量值调整）
REGION_OWD_MS = {
    ("NA", "NA"): 8,   ("EU", "EU"): 7,   ("AP", "AP"): 12, ("SA", "SA"): 15, ("AF", "AF"): 18, ("OC", "OC"): 15,
    ("NA", "EU"): 35,  ("NA", "AP"): 80,  ("NA", "SA"): 40, ("NA", "AF"): 70, ("NA", "OC"): 90,
    ("EU", "AP"): 65,  ("EU", "SA"): 60,  ("EU", "AF"): 35, ("EU", "OC"): 85,
    ("AP", "SA"): 95,  ("AP", "AF"): 80,  ("AP", "OC"): 30,
    ("SA", "AF"): 70,  ("SA", "OC"): 110,
    ("AF", "OC"): 100,
}
# 对称补全（查不到 (A,B) 时用 (B,A)）
def _region_lookup_owd(cont1: Optional[str], cont2: Optional[str], default_ms: float = 40.0) -> float:
    if not cont1 or not cont2:
        return default_ms
    if cont1 == cont2:
        return REGION_OWD_MS.get((cont1, cont2), 10.0)
    return REGION_OWD_MS.get((cont1, cont2), REGION_OWD_MS.get((cont2, cont1), default_ms))


def make_geo_latency_fn(
    locator: GeoIPLocator,
    *,
    # 物理/工程参数（可按你的网络测量校准）
    fiber_k: float = 1.8,       # 路由膨胀系数（真实路径/设备绕行），1.3~2.5 常见
    access_ms: float = 2.0,     # 接入/城域固定开销
    floor_same_city_ms: float = 1.0,  # 同城/同点下限 OWD
    fallback_region_default_ms: float = 40.0
):
    """
    返回一个函数：latency_fn(src_sim_ip, dst_sim_ip) -> OWD(ms)
    计算顺序：
      1) 两端均有经纬度 → 大圆距离 d_km → OWD = max(floor, fiber_k*0.0049*d_km + access_ms)
      2) 否则用大洲回退矩阵 REGION_OWD_MS
      3) 实在拿不到 → fallback_region_default_ms
    """
    LIGHTSPEED_IN_FIBER_MS_PER_KM = 0.0049  # 纤维中传播常数（ms/km）

    def latency_fn(src_ip: str, dst_ip: str) -> float:
        lat1, lon1, cont1, _ = locator.lookup(src_ip)
        lat2, lon2, cont2, _ = locator.lookup(dst_ip)

        # 优先用经纬度：更细粒度
        if (lat1 is not None) and (lon1 is not None) and (lat2 is not None) and (lon2 is not None):
            d_km = haversine_km(lat1, lon1, lat2, lon2)
            base = fiber_k * LIGHTSPEED_IN_FIBER_MS_PER_KM * d_km + access_ms
            return max(floor_same_city_ms if d_km < 25 else 0.0, base)  # <25km 视为“同城下限”

        # 退化：用大洲对回退
        return _region_lookup_owd(cont1, cont2, fallback_region_default_ms)

    return latency_fn
