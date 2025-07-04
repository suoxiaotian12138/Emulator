# -*- coding: utf-8 -*-
"""
Unified RTT Simulator – v2
Author: your_name
"""

import math, random, ipaddress, time, geoip2.database
from functools import lru_cache
from dataclasses import dataclass
from typing import Dict, List, Tuple, Optional
from pathlib import Path

# ----------------------------------------------------------------------
# 0. 常量 / 外部数据
# ----------------------------------------------------------------------
GEO_READER = geoip2.database.Reader(
    str(Path(__file__).resolve().parent / "baselib/geoip/GeoLite2-City.mmdb")
)
C_FIBER = 200_000.0  # km/s
CAIDA_MEDIAN = {                    # 示例，建议用 CSV 批量导入
    ("US", "CN"): 185, ("CN", "US"): 185,
    ("US", "FR"): 95,  ("FR", "US"): 95,
    ("CN", "JP"): 55,  ("JP", "CN"): 55,
    ("US", "US"): 40,
}
# 越少出现的组合 fallback
RTT_FALLBACK = {
    ("US", "US"): 40, ("CN", "CN"): 50, ("FR", "FR"): 25,
    ("US", "CN"): 180, ("US", "FR"): 100, ("CN", "FR"): 210,
}
# ISP tiers
TIER1 = {"Level3", "Lumen", "Telia", "NTT", "GTT", "Cogent", "Hurricane Electric"}
TIER2 = {"Comcast", "Verizon", "AT&T", "Orange", "Vodafone", "China Telecom", "KDDI"}

# ----------------------------------------------------------------------
# 1. 基础结构
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class Location:
    country: str
    city: str
    lat: float
    lon: float
    asn: int
    isp: str

@lru_cache(maxsize=4096)
def _loc(ip: str) -> Optional[Location]:
    """GeoLite2-City lookup + 兜底 CIDR 推断"""
    try:
        geo = GEO_READER.city(ip)
        return Location(
            country = geo.country.iso_code or "ZZ",
            city    = geo.city.name or "Unknown",
            lat     = geo.location.latitude,
            lon     = geo.location.longitude,
            asn     = geo.traits.autonomous_system_number or 0,
            isp     = geo.traits.isp or "",
        )
    except Exception:
        return None

def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km"""
    rlat1, rlat2 = math.radians(lat1), math.radians(lat2)
    dlat = rlat2 - rlat1
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(rlat1)*math.cos(rlat2)*math.sin(dlon/2)**2
    return 6371.0 * 2 * math.asin(math.sqrt(a))

def _isp_factor(isp: str) -> float:
    if isp in TIER1: return 0.90
    if isp in TIER2: return 1.00
    return 1.15   # 默认差一点

# ----------------------------------------------------------------------
# 2. 主类 – 复用旧接口
# ----------------------------------------------------------------------
class OptimizedNetworkSimulator:
    def __init__(self):
        self.latency_cache: Dict[Tuple[str, str], float] = {}
        self.cache_limit = 500

    # ---------- 核心延迟 ----------
    def calculate_latency(self, ip1: str, ip2: str) -> float:
        key = tuple(sorted((ip1, ip2)))
        if key in self.latency_cache:
            return self.latency_cache[key]

        L1, L2 = _loc(ip1), _loc(ip2)

        # --- L1: city-level ---
        if L1 and L2 and None not in (L1.lat, L2.lat):
            d_km   = _haversine(L1.lat, L1.lon, L2.lat, L2.lon)
            theo   = 2 * d_km / C_FIBER * 1000        # ms
            base   = theo + 4.0                       # device / switching
            adj    = (_isp_factor(L1.isp)+_isp_factor(L2.isp))/2
            jitter = random.uniform(-0.05, 0.05)
            rtt    = max(base * adj * (1+jitter), 0.3)
        # --- L2: country-level ---
        elif L1 and L2:
            rtt = CAIDA_MEDIAN.get((L1.country, L2.country))
            if rtt is None: rtt = CAIDA_MEDIAN.get((L2.country, L1.country))
            if rtt is not None:
                rtt *= 1 + random.uniform(-0.07, 0.07)
            else:  # fallback to constant matrix
                rtt = RTT_FALLBACK.get((L1.country, L2.country), 150)
        # --- L3: total fallback ---
        else:
            rtt = RTT_FALLBACK.get(("US", "CN"), 150)

        rtt = round(rtt, 2)
        # cache housekeeping
        if len(self.latency_cache) >= self.cache_limit:
            for k in list(self.latency_cache)[: self.cache_limit // 2]:
                self.latency_cache.pop(k, None)
        self.latency_cache[key] = rtt
        return rtt

    # ---------- 仍保留的旧 API ----------
    def get_location(self, ip: str):  # 兼容外部调用
        return _loc(ip)

    def get_network_profile(self, ip: str) -> Dict:
        loc = _loc(ip)
        if not loc:
            return {'error': 'location_fail'}
        q   = _isp_factor(loc.isp)
        return {
            'ip': ip,
            'location': {'country': loc.country, 'city': loc.city,
                         'lat': loc.lat, 'lon': loc.lon},
            'isp': loc.isp, 'quality_score': round(2.0 - q, 2)
        }

    def simulate_tor_circuit(self, client_ip: str, target_ip: str,
                             guard_pool: List[str], mid_pool: List[str],
                             exit_pool: List[str]) -> Dict:
        import random
        guard, mid, exit_ = [random.choice(p) for p in (guard_pool, mid_pool, exit_pool)]
        seg = {
            'client→guard': self.calculate_latency(client_ip, guard),
            'guard→mid':    self.calculate_latency(guard, mid),
            'mid→exit':     self.calculate_latency(mid, exit_),
            'exit→target':  self.calculate_latency(exit_, target_ip)
        }
        total = sum(seg.values()) + 3*8.5 + random.uniform(2,6)
        return {'circuit': (guard, mid, exit_), 'segments': seg, 'total_ms': round(total,2)}

# ----------------------------------------------------------------------
# 3. Benchmark 函数（压缩版）
# ----------------------------------------------------------------------
def performance_benchmark_v2():
    print("=== RTT Simulator v2 Benchmark ===")
    sim = OptimizedNetworkSimulator()

    test_pairs = [
        ('Local DNS', '8.8.8.8', '8.8.4.4'),
        ('US->CN',     '1.1.1.1', '202.96.209.133'),
        ('EU->US',     '52.208.132.186', '52.85.83.116'),
        ('JP->BR',     '61.117.1.30', '200.160.2.3'),
        ('Unknown',    '10.0.0.1', '192.0.2.1'),
    ]

    t0 = time.time()
    for name, a, b in test_pairs:
        print(f"{name:10} {a:15} → {b:15} : {sim.calculate_latency(a,b):6.2f} ms")
    print(f" ✦ Avg time / call: {(time.time()-t0)/len(test_pairs)*1e3:.2f} ms\n")

    # Tor circuit demo
    guard_pool = ['199.87.154.255','185.220.101.32','94.230.208.147']
    mid_pool   = ['185.220.102.8','199.87.154.251','94.230.208.148']
    exit_pool  = ['199.87.154.253','185.220.102.4','94.230.208.149']
    tor = sim.simulate_tor_circuit('192.168.1.100','93.184.216.34',
                                   guard_pool, mid_pool, exit_pool)
    print("Tor circuit → total {:.2f} ms\nsegments:".format(tor['total_ms']))
    for k,v in tor['segments'].items():
        print(f"  {k:12}: {v:6.2f} ms")

if __name__ == "__main__":
    performance_benchmark_v2()
