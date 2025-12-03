# tools/Network_Management/geo_delay_preset.py
from __future__ import annotations

import math
from functools import lru_cache
from typing import Callable, Dict, Tuple, Optional

# 可选依赖：MaxMind GeoIP2
try:
    import geoip2.database  # pip install geoip2  （需要 MaxMind 的 *.mmdb 文件）
except Exception:  # 不强依赖
    geoip2 = None


# --------- 基础：大圆距离（km） ----------
def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0088  # WGS-84 平均半径
    phi1 = math.radians(lat1); phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlmb/2)**2
    return 2 * R * math.asin(math.sqrt(a))


# --------- 解析 IP -> (lat, lon) 的解析器 ----------
class GeoResolver:
    """
    两级解析：
      1) manual_coords: 人工表优先（适合 sim_ip 不是“真实公网IP”时）
      2) GeoIP2 数据库（若可用）
    """
    def __init__(self, db_path: Optional[str] = None,
                 manual_coords: Optional[Dict[str, Tuple[float, float]]] = None):
        self._manual = manual_coords or {}
        self._reader = None
        if db_path and geoip2 is not None:
            try:
                self._reader = geoip2.database.Reader(db_path)
            except Exception:
                self._reader = None  # 打不开就算了

    def close(self):
        if self._reader:
            try:
                self._reader.close()
            except Exception:
                pass

    @lru_cache(maxsize=4096)
    def ip_to_latlon(self, ip: str) -> Optional[Tuple[float, float]]:
        # 1) 人工表优先
        if ip in self._manual:
            return self._manual[ip]

        # 2) GeoIP2
        if self._reader:
            try:
                rec = self._reader.city(ip)
                lat = rec.location.latitude
                lon = rec.location.longitude
                if lat is not None and lon is not None:
                    return (float(lat), float(lon))
            except Exception:
                pass

        return None


# --------- “真实传播时延”的经验模型 ----------
def _fiber_owd_ms(distance_km: float,
                  *,
                  index_of_refraction: float = 1.468,   # 常用折射率
                  extra_ms: float = 0.0,
                  inflate_factor: float = 1.35         # 铺设绕路/交换机绕行的等效放大
                  ) -> float:
    """
    传播速度 ~= c / n    (c≈299792 km/s, n≈1.468 => ~204,000 km/s)
    一次单向传播:  (distance / (c/n)) * 1000 ms
    再乘以 inflate_factor（路由绕行）+ 额外常量 extra_ms（交换/排队常量）。
    """
    C = 299792.458  # km/s
    speed_km_s = C / float(index_of_refraction)  # ~204,000 km/s
    base_ms = (distance_km / speed_km_s) * 1000.0
    return base_ms * float(inflate_factor) + float(extra_ms)


def build_latency_fn_by_geoip(*,
                              db_path: Optional[str],
                              manual_coords: Optional[Dict[str, Tuple[float, float]]] = None,
                              same_site_floor_ms: float = 1.0,
                              same_city_thresh_km: float = 10.0,
                              metro_thresh_km: float = 80.0,
                              metro_bias_ms: float = 2.0,
                              extra_ms: float = 1.0,
                              inflate_factor: float = 1.35) -> Tuple[Callable[[str, str], float], GeoResolver]:
    """
    返回 (latency_fn, resolver)：
      - latency_fn(src_sim_ip, dst_sim_ip) -> one-way delay (ms)
      - resolver.close() 可在测试收尾关掉（防泄露 “Unclosed client session/connector”）

    规则：
      1) 如果两 IP 无法解析经纬度 => 给一个温和的保守值（40ms）
      2) 若距离 < same_city_thresh_km => 返回 same_site_floor_ms
      3) 若距离 < metro_thresh_km    => 返回 floor + metro_bias_ms
      4) 其余：fiber 传播 + 膨胀因子 + 常量开销
    """
    resolver = GeoResolver(db_path=db_path, manual_coords=manual_coords or {})

    def _latency_fn(src_ip: str, dst_ip: str) -> float:
        if not src_ip or not dst_ip:
            return 40.0
        a = resolver.ip_to_latlon(src_ip)
        b = resolver.ip_to_latlon(dst_ip)
        if a is None or b is None:
            return 40.0  # 查不到经纬度时的兜底

        d_km = _haversine_km(a[0], a[1], b[0], b[1])

        if d_km <= same_city_thresh_km:
            return max(0.1, same_site_floor_ms)
        if d_km <= metro_thresh_km:
            return max(0.5, same_site_floor_ms + metro_bias_ms)

        return _fiber_owd_ms(
            d_km,
            index_of_refraction=1.468,
            extra_ms=extra_ms,
            inflate_factor=inflate_factor
        )

    return _latency_fn, resolver
