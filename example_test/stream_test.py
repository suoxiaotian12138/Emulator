
import asyncio
from network_src.TorCore.Tor_Node import Tor_Node
from network_src.TorCore.Tor_Directory import TorDirectoryServer
from network_src.TorCore.Tor_Client import Tor_Client
import aiohttp


BASE_GUARD_PORT = 9001  # 全局端口起始值

async def register_all_nodes(relays):
    """
    启动所有 guard 节点，使用固定 IP 和递增端口注册。
    :param guard_relays: relay 字典列表，每个为 parse_single_consensus_entry 的结果
    :return: list of guard instances
    """
    guards = []
    for i, relay in enumerate(relays):
        name = relay['nickname']
        protocols = relay["protocols"]
        exit_policy = relay["exit_policy"]
        flags = relay["flags"]
        sim_addr = relay["ip"]
        ip = "127.0.0.1"
        port = BASE_GUARD_PORT + i
        guard = Tor_Node(name, ip, port, flags, protocols, exit_policy, sim_addr)
        guards.append(guard)

    # 启动所有 guards（异步不阻塞）
    for guard in guards:
        asyncio.create_task(guard.start_protocol())

    return guards


async def generator_topology(guard_num, middle_num, exit_num, file_path):
    from tools.Network_Management.topology import select_relays_by_role
    relays = select_relays_by_role(file_path, guard_num, middle_num, exit_num)
    guards = relays['guard']
    middles = relays['middle']
    exits = relays['exit']
    relay_list = guards + middles + exits
    print(len(relay_list))
    print(relay_list[-1])
    await register_all_nodes(relay_list)


async def main():
    # 启动目录服务器
    # dir_server = TorDirectoryServer()
    # server_task = asyncio.create_task(dir_server.run())

    await asyncio.sleep(1)  # 可替换为 wait_for_port_open

    # 多个 guard 配置
    guard_configs = [
        ("guard1", "127.0.0.1", 9001, 'Guard'),
        ("Middle1", "127.0.0.1", 9002, 'Middle'),
        ("Middle2", "127.0.0.1", 9003, 'Middle'),
        ("Exit1", "127.0.0.1", 9004, 'Exit'),
        ("Exit3", "127.0.0.1", 9005, 'Exit'),
    ]
    # 注册所有 guard
    file_path = "D:\project\Oniverse_refactor/2023-01-01-00-00-00-consensus"
    await generator_topology(guard_num=3, middle_num=3, exit_num=3, file_path=file_path)


    await asyncio.sleep(5)  # 等待文件写入完成
    client = Tor_Client(name="client1", host='127.0.0.1', port=9102, model='sim')
    message = b"GET /watch?v=oHg5SJYRHA0 HTTP/1.1\r\nHost: www.youtube.com\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
    addr = ("www.youtube.com", 443)
    hop = 3

    # 先启动监听器
    listen_task = asyncio.create_task(client.start_protocol())
    print("[Main] Listener started. Waiting 10 seconds before sending...")

    # 等待10秒后再开始发送流
    await asyncio.sleep(10)
    print("[Main] make_stream started.")


    client_task = asyncio.create_task(client.make_stream(message=message, addr=addr, hops_count=hop))

    try:
        await client_task
        await asyncio.sleep(300)
    finally:
        listen_task.cancel()
        try:
            await listen_task
        except asyncio.CancelledError:
            print("[Main] Listener task cancelled.")

    # 阻塞等待
    await asyncio.Event().wait()



if __name__ == "__main__":
    asyncio.run(main())
    # file_path = "D:\project\Oniverse_refactor/2023-01-01-00-00-00-consensus"
    # generator_topology(guard_num=3, middle_num=3, exit_num=3, file_path=file_path)