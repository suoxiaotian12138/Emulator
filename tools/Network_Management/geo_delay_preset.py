from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Dict, Any

# 依赖：你已经有的这些类/函数（在 geo_delay_injector.py 里）
from tools.Network_Management.geo_delay_injector import (
    DirectoryClient, MappingCache,
    GeoDelayModel, GeoIPLocator, make_geo_latency_fn,
)

# --------- 环境参数解析小工具 ---------

def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name, "")
    if v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")

def _normalize_url(addr_or_url: Optional[str]) -> Optional[str]:
    if not addr_or_url:
        return None
    s = addr_or_url.strip()
    if "://" in s:
        return s
    return f"http://{s}"

# --------- 封装好的“一键延迟环境” ---------

@dataclass
class DelayEnv:
    enable: bool
    mapping: Optional[MappingCache]
    model: Optional[GeoDelayModel]
    directory: Optional[DirectoryClient]
    locator: Optional[GeoIPLocator]
    default_sim_ip: str

    # ——— 主入口：用配置或环境变量创建 ———
    @classmethod
    async def create(
        cls,
        *,
        enable: Optional[bool] = None,
        directory_url: Optional[str] = None,     # 例如 "http://127.0.0.1:8080"；缺省读 env DIRECTORY_ADDR
        mmdb_path: Optional[str] = None,         # 例如 r"D:\data\GeoLite2-City.mmdb"；缺省读 env GEO_MMDB
        default_sim_ip: str = "1.1.1.1",
        cache_ttl_sec: float = 300.0,
        # Geo 传播模型参数（可不改）
        fiber_k: float = 1.8,
        access_ms: float = 2.0,
        floor_same_city_ms: float = 1.0,
        fallback_region_default_ms: float = 40.0,
        # 抖动
        jitter_ratio: float = 0.10,
        jitter_cap: float = 0.30,
        floor_ms: float = 1.0,
    ) -> "DelayEnv":

        # 开关优先使用显式参数，其次环境变量，默认开
        if enable is None:
            enable = _env_bool("GEO_DELAY_ENABLE", True)

        if not enable:
            # 一键关闭：不占用任何资源，也不用修改调用代码
            return cls(False, None, None, None, None, default_sim_ip)

        # 目录地址：优先参数，其次 env:DIRECTORY_ADDR（可写 "127.0.0.1:8080"）
        if directory_url is None:
            directory_url = os.environ.get("DIRECTORY_ADDR", "127.0.0.1:8080")
        directory_url = _normalize_url(directory_url)

        # GeoIP mmdb：优先参数，其次 env:GEO_MMDB
        if mmdb_path is None:
            mmdb_path = os.environ.get("GEO_MMDB", None)

        # 1) 目录客户端（指纹->descriptor）
        dire = DirectoryClient(base_url=directory_url)

        # 2) GeoIP 定位器（经纬度/大洲）
        locator = GeoIPLocator(mmdb_path=mmdb_path)

        # 3) 基于 GeoIP 的“单向传播基线函数”
        geo_latency_fn = make_geo_latency_fn(
            locator,
            fiber_k=fiber_k,
            access_ms=access_ms,
            floor_same_city_ms=floor_same_city_ms,
            fallback_region_default_ms=fallback_region_default_ms,
        )

        # 4) 延迟模型（把基线 + 抖动封进去）
        model = GeoDelayModel(
            latency_fn=geo_latency_fn,
            jitter_ratio=jitter_ratio,
            jitter_cap=jitter_cap,
            floor_ms=floor_ms,
        )

        # 5) 指纹/IP -> sim_ip 的缓存
        mapping = MappingCache(directory=dire, default_sim_ip=default_sim_ip, ttl_sec=cache_ttl_sec)

        return cls(True, mapping, model, dire, locator, default_sim_ip)

    # —— 给 Tor_Socket.dial() 的参数，一把梭 ——
    def socket_kwargs(self, *, local_sim_ip: Optional[str] = None, force_disable: Optional[bool] = None) -> Dict[str, Any]:
        """
        直接这样用：
           sock = await Tor_Socket.dial(..., **env.socket_kwargs(local_sim_ip="8.8.8.8"))
        """
        if (force_disable is True) or (not self.enable):
            return {"enable_delay": False}

        return {
            "enable_delay": True,
            "local_sim_ip": local_sim_ip or self.default_sim_ip,
            "delay_mapping": self.mapping,
            "delay_model": self.model,
        }

    # —— 异步上下文：自动清理资源（aiohttp/GeoIP reader） ——
    async def aclose(self):
        try:
            if self.directory:
                await self.directory.aclose()
        finally:
            if self.locator:
                self.locator.close()

    async def __aenter__(self) -> "DelayEnv":
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.aclose()

    # —— 极简：完全从环境变量构造（一个函数就够） ——
    @classmethod
    async def from_env(cls) -> "DelayEnv":
        """
        支持的环境变量：
          GEO_DELAY_ENABLE=1/0
          DIRECTORY_ADDR=127.0.0.1:8080 或 http://...
          GEO_MMDB=D:\\data\\GeoLite2-City.mmdb
          GEO_CACHE_TTL=300
          GEO_DEFAULT_SIM_IP=1.1.1.1
          GEO_JITTER_RATIO=0.10
          GEO_JITTER_CAP=0.30
        """
        ttl = float(os.environ.get("GEO_CACHE_TTL", "300"))
        return await cls.create(
            enable=_env_bool("GEO_DELAY_ENABLE", True),
            directory_url=os.environ.get("DIRECTORY_ADDR"),
            mmdb_path=os.environ.get("GEO_MMDB"),
            default_sim_ip=os.environ.get("GEO_DEFAULT_SIM_IP", "1.1.1.1"),
            cache_ttl_sec=ttl,
            jitter_ratio=float(os.environ.get("GEO_JITTER_RATIO", "0.10")),
            jitter_cap=float(os.environ.get("GEO_JITTER_CAP", "0.30")),
        )
