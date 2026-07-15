from network_src.TorCore.Tor_Client import Tor_Client, TorResolveError

import asyncio
import concurrent.futures
import contextlib
import os
import sys


if sys.platform.startswith("win"):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


async def query_one(
    client: Tor_Client,
    hostname: str,
    *,
    hops_count: int,
    timeout: float,
) -> None:
    """通过 Tor 电路向出口节点发送一次 RELAY_RESOLVE 查询。"""
    started = asyncio.get_running_loop().time()

    try:
        result = await client.resolve_hostname(
            hostname,
            hops_count=hops_count,
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        elapsed = asyncio.get_running_loop().time() - started
        print(
            f"[DNS][TIMEOUT] client={client.name} host={hostname} "
            f"elapsed={elapsed:.3f}s"
        )
        return
    except TorResolveError as exc:
        elapsed = asyncio.get_running_loop().time() - started
        error_kind = "transient" if exc.transient else "nontransient"
        print(
            f"[DNS][ERROR] client={client.name} host={hostname} "
            f"kind={error_kind} elapsed={elapsed:.3f}s error={exc}"
        )
        return
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        elapsed = asyncio.get_running_loop().time() - started
        print(
            f"[DNS][FAIL] client={client.name} host={hostname} "
            f"elapsed={elapsed:.3f}s error={exc!r}"
        )
        return

    elapsed = asyncio.get_running_loop().time() - started
    print(
        f"[DNS][OK] client={client.name} host={hostname} "
        f"answers={len(result.answers)} elapsed={elapsed:.3f}s"
    )

    for index, answer in enumerate(result.answers, start=1):
        print(
            f"  answer[{index}] type={answer.answer_type} "
            f"value={answer.value} ttl={answer.ttl}"
        )


async def stop_client(client: Tor_Client, protocol_task: asyncio.Task) -> None:
    """停止 client，并确保 start_protocol 后台任务退出。"""
    with contextlib.suppress(Exception):
        await client.stop_protocol()

    if not protocol_task.done():
        protocol_task.cancel()

    with contextlib.suppress(asyncio.CancelledError, Exception):
        await protocol_task


async def main() -> None:
    loop = asyncio.get_running_loop()
    print("event-loop =>", type(loop))

    max_workers = int(os.environ.get("MAX_TLS_THREADS", "128"))
    loop.set_default_executor(
        concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="tls-worker",
        )
    )

    # ---------- 从环境变量读取参数 ----------
    directory_addr = os.environ.get("DIRECTORY_ADDR", "192.168.66.241:9030")
    node_addr = os.environ.get("NODE_ADDR", "192.168.66.242")
    clients_count = int(os.environ.get("CLIENTS_COUNT", "1"))
    base_port = int(os.environ.get("CLIENT_BASE_PORT", "9102"))
    hops_count = int(os.environ.get("HOPS", "3"))
    query_timeout = float(os.environ.get("DNS_TIMEOUT", "5.0"))

    # 多个域名用逗号分隔，例如：DNS_NAMES=www.baidu.com,www.qq.com
    raw_names = os.environ.get("DNS_NAMES", "www.qq.com")
    hostnames = [name.strip() for name in raw_names.split(",") if name.strip()]
    if not hostnames:
        raise ValueError("DNS_NAMES must contain at least one hostname")

    os.environ["DIRECTORY_ADDR"] = directory_addr

    print(f"[Config] DIRECTORY_ADDR={directory_addr}")
    print(f"[Config] NODE_ADDR={node_addr}")
    print(f"[Config] CLIENTS_COUNT={clients_count}")
    print(f"[Config] CLIENT_BASE_PORT={base_port}")
    print(f"[Config] HOPS={hops_count}")
    print(f"[Config] DNS_TIMEOUT={query_timeout}s")
    print(f"[Config] DNS_NAMES={hostnames}")

    clients: list[Tor_Client] = []
    protocol_tasks: list[asyncio.Task] = []

    try:
        # 1. 创建并启动 Tor client。
        for index in range(clients_count):
            client = Tor_Client(
                name=f"dns-client{index}",
                host=node_addr,
                port=base_port + index,
                model="sim",
            )
            clients.append(client)
            protocol_tasks.append(
                asyncio.create_task(
                    client.start_protocol(),
                    name=f"{client.name}.protocol",
                )
            )

        # 2. 等待每个 client 完成目录获取、Guard 连接和 Tor link handshake。
        await asyncio.gather(*(client.ready_to_send.wait() for client in clients))
        print(f"[Main] {len(clients)} client(s) ready; starting DNS queries")

        # 3. 每个 client 查询所有指定域名。
        query_tasks = [
            asyncio.create_task(
                query_one(
                    client,
                    hostname,
                    hops_count=hops_count,
                    timeout=query_timeout,
                ),
                name=f"resolve:{client.name}:{hostname}",
            )
            for client in clients
            for hostname in hostnames
        ]

        await asyncio.gather(*query_tasks)
        print("[Main] All DNS queries completed")

    finally:
        await asyncio.gather(
            *(
                stop_client(client, task)
                for client, task in zip(clients, protocol_tasks)
            ),
            return_exceptions=True,
        )
        print("[Main] Finished")


if __name__ == "__main__":
    asyncio.run(main())
