import sys
import os
import asyncio
import time
import statistics as stats
import contextlib
from aiohttp import web

# Win 兼容
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# 你的工程对象
from examples.Tor_simplified.Tor_Directory import TorDirectoryServer
from examples.Tor_simplified.Tor_Node import Tor_Node
from examples.Tor_simplified.Tor_Client import Tor_Client

# 延迟注入工具
from tools.Network_Management.geo_delay_injector import DirectoryClient, MappingCache, GeoDelayModel

# 注册器（被动端自动注入）
from tools.Network_Management.socket_delay_registry import (
    set_default_env, clear_default_env, register_delay_env, clear_all
)

# 主动端透传参数
from tools.Network_Management.delay_env import configure

# ================= 基本配置 =================
DIR_HOST, DIR_PORT = "127.0.0.1", 8080
os.environ["DIRECTORY_ADDR"] = f"{DIR_HOST}:{DIR_PORT}"

HOPS = 3
REQUEST = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
DST = ("example.com", 80)

# 三类节点的 sim_ip（用首段标识“洲”）
# 10.* -> NA  20.* -> EU  30.* -> AS  40.* -> AU
SIM_POOL = [
    "10.0.0.1","10.0.0.2","10.0.0.3",   # Guard : 北美
    "20.0.0.1","20.0.0.2","20.0.0.3",   # Middle: 欧洲
    "30.0.0.1","30.0.0.2","30.0.0.3",   # Exit  : 亚洲
]

BASE_PORT = 9700
CLIENT_PORT = 9801

# 近/远 两组 client 的 sim_ip
CLIENT_NEAR = "10.0.9.9"   # 与 Guard 同洲（北美）
CLIENT_FAR  = "40.0.0.1"   # 澳大利亚，远离三跳路径（NA→EU→AS）

# 每个场景的重复次数
REPEAT = 5


# ================= 目录服务 =================
async def start_directory():
    srv = TorDirectoryServer(host=DIR_HOST, port=DIR_PORT)
    runner = web.AppRunner(srv.app)
    await runner.setup()
    site = web.TCPSite(runner, DIR_HOST, DIR_PORT)
    await site.start()
    print(f"[DIR] http://{DIR_HOST}:{DIR_PORT}")
    return runner


# ================= 启动节点 =================
async def start_nodes():
    nodes = []
    role_flags = {
        "Guard":  ["Running","Valid","Guard","Fast"],
        "Middle": ["Running","Valid","Fast"],
        "Exit":   ["Running","Valid","Exit","Fast"],
    }
    names = [
        ("N1-GUA","Guard"),
        ("N2-GUA","Guard"),
        ("N3-GUA","Guard"),
        ("N4-MID","Middle"),
        ("N5-MID","Middle"),
        ("N6-MID","Middle"),
        ("N7-EXT","Exit"),
        ("N8-EXT","Exit"),
        ("N9-EXT","Exit"),
    ]

    for i, (name, role) in enumerate(names, start=1):
        port = BASE_PORT + i
        sim_ip = SIM_POOL[i-1]
        node = Tor_Node(
            name=name, host="127.0.0.1", port=port,
            flags=role_flags[role],
            protocols="Cons=2 Desc=2 DirCache=2 FlowCtrl=2 Link=4-5 LinkAuth=3 Microdesc=2 Padding=2 Relay=4",
            exit_policy="accept *:1-65535" if role == "Exit" else "reject *:*",
            sim_ip=sim_ip,
        )
        nodes.append(node)
        asyncio.create_task(node.start_protocol())

    # 给目录注册一些时间
    await asyncio.sleep(1.2)
    return nodes


# ================= 洲际延迟模型 =================
def region_of(sim_ip: str) -> str:
    # 根据首段粗暴映射：10->NA 20->EU 30->AS 40->AU 其他->NA
    try:
        first = int(sim_ip.split(".")[0])
    except Exception:
        return "NA"
    return {10:"NA", 20:"EU", 30:"AS", 40:"AU"}.get(first, "NA")

def make_latency_fn():
    # 基础/更激进的洲际时延（单程，毫秒）
    # 同洲：3ms；跨洲：更大
    base = {
        "NA": {"NA": 3,   "EU": 80,  "AS": 140, "AU": 160},
        "EU": {"NA": 80,  "EU": 3,   "AS": 120, "AU": 180},
        "AS": {"NA": 140, "EU": 120, "AS": 3,   "AU": 100},
        "AU": {"NA": 160, "EU": 180, "AS": 100, "AU": 3},
    }

    def latency_ms(src_ip: str, dst_ip: str) -> float:
        r1, r2 = region_of(src_ip), region_of(dst_ip)
        return float(base[r1][r2])

    return latency_ms


# ================= 注入参数下发（默认+节点级） =================
def apply_delay_env(*, enable: bool, nodes, mapping: MappingCache, model: GeoDelayModel, client_sim_ip: str):
    # A) 主动端透传（Tor_Socket(..., **get_args(...)) 取用）
    configure(enabled=enable, mapping=mapping, model=model)

    # B) 被动端自动查表（listen 侧）
    clear_all()
    clear_default_env()

    # client 默认（被动接收的socket会继承，除非节点级覆盖）
    set_default_env(enable=enable, local_sim_ip=client_sim_ip, mapping=mapping, model=model)

    # 每个节点用自己的 sim_ip（覆盖默认）
    for n in nodes:
        register_delay_env(
            n.node_id,
            enable=enable,
            local_sim_ip=getattr(n, "sim_ip", client_sim_ip),
            mapping=mapping,
            model=model
        )


# ================= 单次请求（返回E2E ms） =================
async def one_request(label: str, *, enable_delay: bool, mapping: MappingCache, model: GeoDelayModel, nodes, client_sim_ip: str) -> float:
    apply_delay_env(enable=enable_delay, nodes=nodes, mapping=mapping, model=model, client_sim_ip=client_sim_ip)

    client = Tor_Client(name=f"client-{label}", host="127.0.0.1", port=CLIENT_PORT, model='sim', sim_ip=client_sim_ip)
    t_client = asyncio.create_task(client.start_protocol())

    # 等握手
    await asyncio.sleep(0.8)

    t0 = time.perf_counter()
    try:
        await client.make_stream(message=REQUEST, addr=DST, hops_count=HOPS)
        e2e = (time.perf_counter() - t0) * 1000.0
        print(f"[{label}] E2E = {e2e:.1f} ms")
    except Exception as e:
        print(f"[{label}] FAILED: {e}")
        e2e = float('nan')

    # 等日志刷出
    await asyncio.sleep(0.8)

    with contextlib.suppress(asyncio.CancelledError):
        t_client.cancel()
        await t_client

    return e2e


# ================= N次场景测试 =================
async def run_scenario(name: str, *, enable_delay: bool, mapping: MappingCache, base_model: GeoDelayModel, nodes, client_sim_ip: str, repeat: int):
    # 每个场景可独立定制模型抖动，避免过于“死板”
    model = GeoDelayModel(
        latency_fn=base_model.latency_fn,
        jitter_ratio=0.05 if enable_delay else 0.0,  # GEO 场景加一点抖动
        jitter_cap=0.35,
        floor_ms=1.0
    )
    results = []
    for i in range(1, repeat + 1):
        label = f"{name}-{i}"
        e2e = await one_request(label, enable_delay=enable_delay, mapping=mapping, model=model, nodes=nodes, client_sim_ip=client_sim_ip)
        results.append(e2e)
    # 统计
    valid = [x for x in results if x == x]  # 过滤 NaN
    mean = stats.mean(valid) if valid else float('nan')
    stdev = stats.pstdev(valid) if len(valid) > 1 else 0.0
    print(f"[{name}] MEAN={mean:.1f} ms  STD={stdev:.1f} ms  (n={len(valid)}/{repeat})")
    return name, results, mean, stdev


# ================= 主流程 =================
async def main():
    # 目录
    dir_runner = await start_directory()

    # 映射/模型
    dcli = DirectoryClient(f"http://{DIR_HOST}:{DIR_PORT}")
    mapping = MappingCache(directory=dcli, default_sim_ip="127.0.0.1", ttl_sec=180.0)
    base_model = GeoDelayModel(latency_fn=make_latency_fn(), jitter_ratio=0.0, jitter_cap=0.0, floor_ms=1.0)

    # 9 节点
    nodes = await start_nodes()

    # 三个场景：NO_DELAY / GEO_NEAR / GEO_FAR
    s1 = await run_scenario("NO_DELAY",  enable_delay=False, mapping=mapping, base_model=base_model, nodes=nodes, client_sim_ip=CLIENT_NEAR, repeat=REPEAT)
    s2 = await run_scenario("GEO_NEAR",  enable_delay=True,  mapping=mapping, base_model=base_model, nodes=nodes, client_sim_ip=CLIENT_NEAR, repeat=REPEAT)
    s3 = await run_scenario("GEO_FAR",   enable_delay=True,  mapping=mapping, base_model=base_model, nodes=nodes, client_sim_ip=CLIENT_FAR,  repeat=REPEAT)

    # 总结
    print("\n===== SUMMARY =====")
    for name, results, mean, stdev in (s1, s2, s3):
        print(f"{name:<10}: {mean:6.1f} ms (±{stdev:.1f})  -> {', '.join(f'{x:.1f}' for x in results)}")

    # 关节点
    stop_tasks = [asyncio.create_task(n.stop_protocol()) for n in nodes]
    await asyncio.gather(*stop_tasks, return_exceptions=True)

    # 清理
    await asyncio.sleep(0.5)
    with contextlib.suppress(Exception):
        await dcli.aclose()
    with contextlib.suppress(Exception):
        await dir_runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
