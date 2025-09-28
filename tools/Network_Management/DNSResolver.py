import asyncio
import time
from typing import Optional, Dict, Tuple, Any
import dns.asyncresolver
import dns.exception
import dns.name
import dns.rdatatype

class _CacheEntry:
    __slots__ = ("value", "expire_at", "neg")
    def __init__(self, value: Any, expire_at: float, neg: bool=False):
        self.value = value
        self.expire_at = expire_at
        self.neg = neg  # negative cache flag

class AsyncDNSCache:
    """TTL/负缓存/LRU(可选) 的简单实现。"""
    def __init__(self, max_size: int = 10000):
        self._cache: Dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()
        self._max_size = max_size

    async def get(self, key: str) -> Optional[_CacheEntry]:
        now = time.time()
        entry = self._cache.get(key)
        if not entry:
            return None
        if entry.expire_at <= now:
            # 过期直接删（懒删除）
            async with self._lock:
                self._cache.pop(key, None)
            return None
        return entry

    async def set(self, key: str, value: Any, ttl: float, neg: bool=False):
        expire_at = time.time() + ttl
        async with self._lock:
            if len(self._cache) >= self._max_size:
                # 简易淘汰：随机/任意弹一项（够用就好；要更精细可换成 OrderedDict/LRU）
                self._cache.pop(next(iter(self._cache)))
            self._cache[key] = _CacheEntry(value=value, expire_at=expire_at, neg=neg)

class DNSResolver:
    """
    高并发优化：
      - in-flight de-dup
      - TTL 缓存（正/负）
      - 多 nameserver 并发竞速
      - stale-while-revalidate
    """
    def __init__(
        self,
        use_cache: bool = True,
        nameservers: Optional[list[str]] = None,
        timeout: float = 1.5,
        lifetime: float = 2.5,
        min_ttl: int = 5,
        max_ttl: int = 1800,
        neg_ttl: int = 20,  # 负缓存 TTL
        parallel_ns: bool = True,
    ):
        self.use_cache = use_cache
        self.cache = AsyncDNSCache() if use_cache else None
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.neg_ttl = neg_ttl
        self.parallel_ns = parallel_ns

        # 主 resolver（也可让它带 nameservers）
        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
        if nameservers:
            self.resolver.nameservers = nameservers

        # in-flight map: domain -> Task
        self._inflight: Dict[str, asyncio.Task] = {}
        self._inflight_lock = asyncio.Lock()

        # 预生成并发 resolvers（每个 nameserver 一个）
        self._per_ns_resolvers: list[dns.asyncresolver.Resolver] = []
        if nameservers:
            for ns in nameservers:
                r = dns.asyncresolver.Resolver(configure=False)
                r.nameservers = [ns]
                r.timeout = timeout
                r.lifetime = lifetime
                self._per_ns_resolvers.append(r)

    def _clamp_ttl(self, ttl: int) -> int:
        return max(self.min_ttl, min(self.max_ttl, int(ttl)))

    async def _query_A(self, domain: str) -> Tuple[str, int]:
        """
        真实做查询：返回 (ip, ttl)。可能抛异常。
        - 如果设置了并行 nameserver，则并发竞速。
        """
        qname = domain  # 保持原样；需要的话可规范化 punycode：dns.name.from_text(domain).to_unicode()
        async def _do_resolve(res: dns.asyncresolver.Resolver):
            ans = await res.resolve(qname, 'A')
            # 取第一个 A 与对应 TTL
            ip = ans[0].address
            ttl = getattr(ans.rrset, "ttl", self.min_ttl)
            return ip, self._clamp_ttl(ttl)

        if self.parallel_ns and self._per_ns_resolvers:
            tasks = [asyncio.create_task(_do_resolve(r)) for r in self._per_ns_resolvers]
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for p in pending:
                p.cancel()
            # 拿到最先成功的结果；若全失败，重新抛出第一个异常
            for d in done:
                if d.exception() is None:
                    return d.result()
            # 全失败，抛第一个的异常
            raise list(done)[0].exception()
        else:
            return await _do_resolve(self.resolver)

    async def resolve_ipv4(self, domain: str) -> str:
        """
        高性能版本：带缓存、去重、并发 NS、负缓存。
        """
        key = f"A:{domain}"

        # 命中（正/负）
        if self.use_cache:
            entry = await self.cache.get(key)
            if entry:
                if entry.neg:
                    raise RuntimeError(f"DNS negative-cached for {domain}")
                return entry.value

        # 去重：同一个域名同时只有一个真正的查询
        async with self._inflight_lock:
            task = self._inflight.get(key)
            if not task:
                task = asyncio.create_task(self._resolve_and_fill_cache(key, domain))
                self._inflight[key] = task

        try:
            return await task
        finally:
            # 清理 in-flight
            async with self._inflight_lock:
                self._inflight.pop(key, None)

    async def _resolve_and_fill_cache(self, key: str, domain: str) -> str:
        try:
            ip, ttl = await self._query_A(domain)
            if self.use_cache:
                await self.cache.set(key, ip, ttl=ttl, neg=False)
            return ip
        except (dns.exception.DNSException, Exception) as e:
            # 负缓存，短 TTL
            if self.use_cache:
                await self.cache.set(key, str(e), ttl=self.neg_ttl, neg=True)
            raise RuntimeError(f"DNS resolution failed for {domain}: {e}")

    # 可选：带 SWR 的“返回旧值+后台刷新”
    async def resolve_ipv4_swr(self, domain: str) -> str:
        """
        stale-while-revalidate：如果命中且将近过期，先返回旧值，然后后台刷新。
        """
        key = f"A:{domain}"
        if not self.use_cache:
            return await self.resolve_ipv4(domain)

        entry = await self.cache.get(key)
        if entry and not entry.neg:
            # 近似“快过期”的判断：剩余 < min_ttl*2 就后台刷新
            remain = entry.expire_at - time.time()
            if remain < (self.min_ttl * 2):
                # 背景刷新（不阻塞请求路径）
                asyncio.create_task(self._resolve_and_fill_cache(key, domain))
            return entry.value

        # 没命中或负缓存，走正常路径
        return await self.resolve_ipv4(domain)
