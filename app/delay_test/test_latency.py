import sys
import os
import asyncio
import concurrent.futures
import time
import json
from contextlib import suppress

# ==== Windows 事件循环 & 线程池（与你原脚本一致风格） ====
if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

MAX_TLS_THREADS = min(64, (os.cpu_count() or 4) * 8)
loop = asyncio.get_event_loop()
loop.set_default_executor(concurrent.futures.ThreadPoolExecutor(
    max_workers=MAX_TLS_THREADS,
    thread_name_prefix="tls-worker"
))

# ==== 你工程里的模块 ====
from aiohttp import web
from examples.Tor_simplified.Tor_Directory import TorDirectoryServer
from examples.Tor_simplified.Tor_Node import Tor_Node
from examples.Tor_simplified.Tor_Client import Tor_Client
from tools.Network_Management.topology import select_relays_by_role

# ==== 延迟注入一键封装（你已上传） ====
from tools.Network_Management.delay_env import DelayEnv
from tools.Network_Management.socket_delay_registry import (
    install_global_socket_delay,   # 全局安装“默认 socket 延迟参数”
    uninstall_global_socket_delay  # 全局卸载
)

# ================== 可调参数 ==================
CONSENSUS_FILE = os.environ.get("CONSENSUS_FILE",
    r"D:\project\Oniverse_refactor\2023-01-01-00-00-00-consensus"
)
DIR_HOST = "127.0.0.1"
DIR_PORT = 8080
os.environ["DIRECTORY_ADDR"] = f"{DIR_HOST}:{DIR_PORT}"

# 每类节点数量（>3 可避免角色被抢用导致不够）
N_GUARD = 4
N_MIDDLE = 4
N_EXIT = 4

# 三跳
HOPS = 3

# 请求：
REQ = b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"
DST = ("example.com", 80)

# 给每类节点准备一些 sim_ip（可按需扩展/替换）
SIM_IPS_GUARD = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "9.9.9.9"]
SIM_IPS_MID   = ["23.228.128.136", "52.0.0.1", "104.16.0.1", "151.101.1.69"]
SIM_IPS_EXIT  = ["203.0.113.10", "198.51.100.20", "185.199.108.153", "140.82.113.4"]

# 端口段（避免冲突）
BASE_PORT = 9700
CLIENT_PORT = 9801

RESULTS_FILE = os.path.join(os.path.dirname(__file__), "latency_results.jsonl")


# ================== 小工具 ==================
async def start_directory_nonblocking():
    """用 AppRunner/TCPSite 启目录服务，不接管事件循环。"""
    dir_server = TorDirectoryServer(host=DIR_HOST, port=DIR_PORT)
    runner = web.AppRunner(dir_server.app)
    await runner.setup()
    site = web.TCPSite(runner, DIR_HOST, DIR_PORT)
    await site.start()
    print(f"[DIR] http://{DIR_HOST}:{DIR_PORT}")
    return runner

async def spawn_nodes_with_simip(guards, middles, exits, base_port):
    """按选出的 relays 启动节点，并为每一类按顺序分配 sim_ip。"""
    nodes = []

    # Guard
    for i, r in enumerate(guards):
        ip = "127.0.0.1"; port = base_port + i
        sim_ip = SIM_IPS_GUARD[i % len(SIM_IPS_GUARD)]
        n = Tor_Node(
            name=r["nickname"], host=ip, port=port, flags=r["flags"],
            protocols=r["protocols"], exit_policy=r["exit_policy"], sim_ip=sim_ip
        )
        nodes.append(n)
        asyncio.create_task(n.start_protocol())

    # Middle
    offset = len(guards)
    for i, r in enumerate(middles):
        ip = "127.0.0.1"; port = base_port + offset + i
        sim_ip = SIM_IPS_MID[i % len(SIM_IPS_MID)]
        n = Tor_Node(
            name=r["nickname"], host=ip, port=port, flags=r["flags"],
            protocols=r["protocols"], exit_policy=r["exit_policy"], sim_ip=sim_ip
        )
        nodes.append(n)
        asyncio.create_task(n.start_protocol())

    # Exit
    offset += len(middles)
    for i, r in enumerate(exits):
        ip = "127.0.0.1"; port = base_port + offset + i
        sim_ip = SIM_IPS_EXIT[i % len(SIM_IPS_EXIT)]
        n = Tor_Node(
            name=r["nickname"], host=ip, port=port, flags=r["flags"],
            protocols=r["protocols"], exit_policy=r["exit_policy"], sim_ip=sim_ip
        )
        nodes.append(n)
        asyncio.create_task(n.start_protocol())

    # 等一会儿，确保节点监听起来 & 描述符上传
    await asyncio.sleep(1.2)
    return nodes

async def build_topology(base_port):
    relays = select_relays_by_role(CONSENSUS_FILE, N_GUARD, N_MIDDLE, N_EXIT)
    guards, middles, exits = relays["guard"], relays["middle"], relays["exit"]
    nodes = await spawn_nodes_with_simip(guards, middles, exits, base_port)
    return nodes


async def run_one_round(label: str, enable_delay: bool, env: DelayEnv | None):
    """
    - enable_delay=False：卸载全局 socket 延迟参数
    - enable_delay=True ：安装 env 的 socket_kwargs 到全局
    然后起客户端，打一条 3-hop 请求，测 E2E。
    """
    # 切换“全局延迟参数”
    if enable_delay and env:
        install_global_socket_delay(**env.socket_kwargs())
        print(f"[{label}] delay=ON  (global socket kwargs installed)")
    else:
        uninstall_global_socket_delay()
        print(f"[{label}] delay=OFF (global socket kwargs cleared)")

    # 启客户端
    client = Tor_Client(name=f"client-{label}", host="127.0.0.1", port=CLIENT_PORT, model="sim")
    task_client = asyncio.create_task(client.start_protocol())

    # 等待 client 就绪
    await asyncio.sleep(0.6)

    # 建路+发流（一次），测 E2E
    t0 = time.perf_counter()
    try:
        await client.make_stream(message=REQ, addr=DST, hops_count=HOPS)
        e2e_ms = (time.perf_counter() - t0) * 1000.0
        print(f"[{label}] E2E = {e2e_ms:.1f} ms")
    except Exception as e:
        print(f"[{label}] E2E FAIL: {e!r}")
        e2e_ms = float("nan")

    # 给协议栈一点时间把 END/日志刷出
    await asyncio.sleep(0.6)

    # 关闭客户端
    with suppress(Exception):
        task_client.cancel()
        await task_client

    return {"label": label, "E2E_ms": e2e_ms}


async def main():
    # 1) 启目录
    dir_runner = await start_directory_nonblocking()

    # 2) 起拓扑（≥3 跳且每类多台）
    _nodes = await build_topology(BASE_PORT)

    # 3) 延迟环境（只在“有延迟”回合用；一键打包 mapping+model+开关）
    #    这里的 `client_sim_ip` 是“本端”的模拟 IP，可写成你运行 client 所在的“地区代表 IP”
    env = await DelayEnv.create(
        dire_addr=(DIR_HOST, DIR_PORT),
        client_sim_ip="198.18.0.1",    # 随意取个测试网段/地区代表IP
        jitter_ratio=0.10,             # 抖动 10%
        jitter_cap=0.30,               # 抖动封顶 30%
        same_city_ms=1.0,              # 同城/同点最小 1ms
        default_owd_ms=40.0            # 异地单程基线 40ms（GeoIP 会覆盖具体对）
    )

    # 4) 两轮对比
    res_no  = await run_one_round("NO_DELAY", enable_delay=False, env=None)
    res_geo = await run_one_round("GEO_DELAY", enable_delay=True,  env=env)

    # 5) 写结果
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(res_no, ensure_ascii=False) + "\n")
        f.write(json.dumps(res_geo, ensure_ascii=False) + "\n")
    print(f"[WRITE] -> {RESULTS_FILE}")

    # 6) 稍等让节点把日志 flush 完，再清理目录 runner
    await asyncio.sleep(1.0)
    await dir_runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
