import asyncio
import time
from typing import Any, Dict, Optional, Tuple

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver


class DNSResolveError(Exception):
    """Stable DNS error exposed to Tor relay code.

    transient=True maps to RESOLVED type 0xF0; transient=False maps to 0xF1.
    code is suitable for metrics/logging and negative-cache reconstruction.
    """

    def __init__(self, message: str, *, transient: bool, code: str):
        super().__init__(message)
        self.transient = bool(transient)
        self.code = code


class _CacheEntry:
    __slots__ = ("value", "expire_at", "neg")

    def __init__(self, value: Any, expire_at: float, neg: bool = False):
        self.value = value
        self.expire_at = expire_at
        self.neg = neg


class AsyncDNSCache:
    """Simple TTL cache with negative-cache support."""

    def __init__(self, max_size: int = 10000):
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self._cache: Dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()
        self._max_size = max_size

    async def get(self, key: str) -> Optional[_CacheEntry]:
        now = time.monotonic()
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.expire_at <= now:
            async with self._lock:
                current = self._cache.get(key)
                if current is entry:
                    self._cache.pop(key, None)
            return None
        return entry

    async def set(self, key: str, value: Any, ttl: float, neg: bool = False):
        expire_at = time.monotonic() + max(0.0, float(ttl))
        async with self._lock:
            if key not in self._cache and len(self._cache) >= self._max_size:
                self._cache.pop(next(iter(self._cache)), None)
            self._cache[key] = _CacheEntry(value=value, expire_at=expire_at, neg=neg)


class DNSResolver:
    """Asynchronous IPv4 resolver with cache, de-duplication and NS racing."""

    def __init__(
        self,
        use_cache: bool = True,
        nameservers: Optional[list[str]] = None,
        timeout: float = 1.5,
        lifetime: float = 2.5,
        min_ttl: int = 5,
        max_ttl: int = 1800,
        neg_ttl: int = 20,
        parallel_ns: bool = True,
    ):
        if min_ttl < 0 or max_ttl < min_ttl:
            raise ValueError("invalid TTL bounds")
        if neg_ttl < 0:
            raise ValueError("neg_ttl must be non-negative")

        self.use_cache = use_cache
        self.cache = AsyncDNSCache() if use_cache else None
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.neg_ttl = neg_ttl
        self.parallel_ns = parallel_ns

        self.resolver = dns.asyncresolver.Resolver(configure=True)
        self.resolver.timeout = timeout
        self.resolver.lifetime = lifetime
        if nameservers:
            self.resolver.nameservers = nameservers

        self._inflight: Dict[str, asyncio.Task[Tuple[str, int]]] = {}
        self._inflight_lock = asyncio.Lock()

        self._per_ns_resolvers: list[dns.asyncresolver.Resolver] = []
        if nameservers:
            for ns in nameservers:
                resolver = dns.asyncresolver.Resolver(configure=False)
                resolver.nameservers = [ns]
                resolver.timeout = timeout
                resolver.lifetime = lifetime
                self._per_ns_resolvers.append(resolver)

    def _clamp_ttl(self, ttl: int) -> int:
        return max(self.min_ttl, min(self.max_ttl, int(ttl)))

    @staticmethod
    def _classify_exception(domain: str, exc: BaseException) -> DNSResolveError:
        if isinstance(exc, DNSResolveError):
            return exc
        if isinstance(exc, dns.resolver.NXDOMAIN):
            return DNSResolveError(
                f"DNS name does not exist: {domain}", transient=False, code="NXDOMAIN"
            )
        if isinstance(exc, dns.resolver.NoAnswer):
            return DNSResolveError(
                f"DNS response has no A record: {domain}", transient=False, code="NO_ANSWER"
            )
        if isinstance(exc, dns.resolver.YXDOMAIN):
            return DNSResolveError(
                f"DNS name is too long after substitution: {domain}",
                transient=False,
                code="YXDOMAIN",
            )
        if isinstance(exc, dns.exception.Timeout):
            return DNSResolveError(
                f"DNS query timed out: {domain}", transient=True, code="TIMEOUT"
            )
        if isinstance(exc, dns.resolver.NoNameservers):
            return DNSResolveError(
                f"No usable DNS nameserver for: {domain}",
                transient=True,
                code="NO_NAMESERVERS",
            )
        if isinstance(exc, dns.exception.DNSException):
            return DNSResolveError(
                f"DNS protocol failure for {domain}: {exc}",
                transient=True,
                code="DNS_FAILURE",
            )
        return DNSResolveError(
            f"Unexpected resolver failure for {domain}: {exc}",
            transient=True,
            code="INTERNAL",
        )

    async def _query_A(self, domain: str) -> Tuple[str, int]:
        async def _do_resolve(resolver: dns.asyncresolver.Resolver) -> Tuple[str, int]:
            answer = await resolver.resolve(domain, dns.rdatatype.A)
            if not answer:
                raise dns.resolver.NoAnswer(response=getattr(answer, "response", None))
            ip = answer[0].address
            ttl = getattr(answer.rrset, "ttl", self.min_ttl)
            return ip, self._clamp_ttl(ttl)

        if not self.parallel_ns or not self._per_ns_resolvers:
            try:
                return await _do_resolve(self.resolver)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                raise self._classify_exception(domain, exc) from exc

        tasks = {
            asyncio.create_task(_do_resolve(resolver))
            for resolver in self._per_ns_resolvers
        }
        errors: list[DNSResolveError] = []

        try:
            while tasks:
                done, pending = await asyncio.wait(
                    tasks, return_when=asyncio.FIRST_COMPLETED
                )
                tasks = pending

                for task in done:
                    try:
                        result = task.result()
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        errors.append(self._classify_exception(domain, exc))
                        continue

                    for pending_task in tasks:
                        pending_task.cancel()
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                    return result

            if not errors:
                raise DNSResolveError(
                    f"No DNS resolver completed for {domain}",
                    transient=True,
                    code="NO_RESULT",
                )

            # A definitive negative answer wins over temporary transport failures.
            definitive = next((error for error in errors if not error.transient), None)
            raise definitive or errors[-1]
        finally:
            for task in tasks:
                task.cancel()
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    async def _resolve_and_fill_cache(self, key: str, domain: str) -> Tuple[str, int]:
        try:
            result = await self._query_A(domain)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error = self._classify_exception(domain, exc)
            if self.use_cache:
                await self.cache.set(
                    key,
                    (error.code, str(error), error.transient),
                    ttl=self.neg_ttl,
                    neg=True,
                )
            raise error from exc

        ip, ttl = result
        if self.use_cache:
            await self.cache.set(key, result, ttl=ttl, neg=False)
        return result

    async def resolve_ipv4_with_ttl(self, domain: str) -> Tuple[str, int]:
        if not isinstance(domain, str):
            raise ValueError("domain must be a string")
        normalized = domain.strip().rstrip(".").lower()
        if not normalized:
            raise ValueError("domain must not be empty")

        key = f"A:{normalized}"
        if self.use_cache:
            entry = await self.cache.get(key)
            if entry is not None:
                if entry.neg:
                    code, message, transient = entry.value
                    raise DNSResolveError(
                        message, transient=transient, code=code
                    )
                ip, _original_ttl = entry.value
                remaining_ttl = max(0, int(entry.expire_at - time.monotonic()))
                return ip, remaining_ttl

        async with self._inflight_lock:
            task = self._inflight.get(key)
            if task is None:
                task = asyncio.create_task(
                    self._resolve_and_fill_cache(key, normalized)
                )
                self._inflight[key] = task

                def _cleanup(done_task: asyncio.Task, *, cache_key: str = key):
                    if self._inflight.get(cache_key) is done_task:
                        self._inflight.pop(cache_key, None)

                task.add_done_callback(_cleanup)

        # shield prevents one cancelled waiter from cancelling the shared lookup.
        return await asyncio.shield(task)

    async def resolve_ipv4(self, domain: str) -> str:
        ip, _ttl = await self.resolve_ipv4_with_ttl(domain)
        return ip

    async def resolve_ipv4_swr(self, domain: str) -> str:
        normalized = domain.strip().rstrip(".").lower()
        key = f"A:{normalized}"
        if not self.use_cache:
            return await self.resolve_ipv4(normalized)

        entry = await self.cache.get(key)
        if entry is not None and not entry.neg:
            ip, _ttl = entry.value
            remain = entry.expire_at - time.monotonic()
            if remain < self.min_ttl * 2:
                # Reuse the normal in-flight de-dup path instead of spawning duplicate refreshes.
                refresh = asyncio.create_task(self.resolve_ipv4_with_ttl(normalized))

                def _consume_refresh_result(done_task: asyncio.Task):
                    try:
                        done_task.result()
                    except (asyncio.CancelledError, DNSResolveError):
                        pass

                refresh.add_done_callback(_consume_refresh_result)
            return ip

        return await self.resolve_ipv4(normalized)
