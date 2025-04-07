import os
import sys
import subprocess
import time
import tempfile
import signal

# 当前脚本所在目录路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = "D:/project/Oniverse/logs"


def create_tac_file(node_type, ip, port, name, group=1):
    """创建一个临时的 .tac 文件用于 twistd 启动"""
    tac_content = f"""
import os
import sys
sys.path.append('{BASE_DIR}')
from twisted.python import log
from twisted.application import service, internet
from Crypto.NodeBuild import LoopixNodeSetup
from databasemanage.database_init import loopix_database_initial


loopix_database_initial()
node_set = [{port}, '{ip}', '{name}', {group}]
setup = LoopixNodeSetup(node_set)
created_node = setup.NodeBuild('{node_type}')
application = service.Application('{node_type}')
udp_server = internet.UDPServer(created_node.port, created_node)
udp_server.setServiceParent(application)
"""

    # # 创建临时文件
    # fd, tac_path = tempfile.mkstemp(suffix='.tac', prefix=f'{node_type}_{name}_')
    # with os.fdopen(fd, 'w') as f:
    #     f.write(tac_content)

    os.makedirs(BASE_DIR, exist_ok=True)

    # 生成文件路径
    tac_path = os.path.join(BASE_DIR, f"{node_type}_{name}.tac")
    # 写入文件
    with open(tac_path, 'w') as f:
        f.write(tac_content)


    return tac_path


def start_node(node_type, ip, port, name, group=1):
    """启动一个 Twisted 节点"""
    # 创建 TAC 文件
    tac_file = create_tac_file(node_type, ip, port, name, group)

    # 定义日志和 PID 文件
    log_file = os.path.join(BASE_DIR, f"{node_type}_{name}.log")
    pid_file = os.path.join(BASE_DIR, f"{node_type}_{name}.pid")

    # 构建 twistd 命令
    cmd = [
        "twistd",
        "--nodaemon",  # 不作为守护进程运行，便于在控制台查看输出
        f"--pidfile={pid_file}",
        f"--logfile={log_file}",
        "-y", tac_file
    ]

    # 启动进程
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NEW_CONSOLE  # Windows 特有，为每个进程创建新控制台窗口
    )

    print(f"Started {node_type} {name} on {ip}:{port}, PID: {process.pid}")
    return process, tac_file


if __name__ == "__main__":
    # 节点配置
    nodes = [
        ("Mixnode", "127.0.0.1", 9991, "mix1", 1),
        ("Mixnode", "127.0.0.1", 9992, "mix2", 2),
        ("Mixnode", "127.0.0.1", 9993, "mix3", 3),
        ("Provider", "127.0.0.1", 9994, "provider1"),
        ("Client", "127.0.0.1", 9995, "client1"),
        ("Client", "127.0.0.1", 9996, "client2")
    ]

    # 存储进程和TAC文件以便后续清理
    processes = []
    tac_files = []

    try:
        # 启动所有节点
        for node_config in nodes:
            process, tac_file = start_node(*node_config)
            processes.append(process)
            tac_files.append(tac_file)
            time.sleep(1)  # 给每个节点一些启动时间

        print(f"Successfully started {len(processes)} nodes.")
        print("Press Ctrl+C to terminate all nodes...")

        # 等待所有进程完成（或被中断）
        while all(process.poll() is None for process in processes):
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nTerminating all nodes...")
    finally:
        # 终止所有进程
        for i, process in enumerate(processes):
            if process.poll() is None:  # 如果进程仍在运行
                process.terminate()
                print(f"Terminated node {i + 1}")

        # # 清理临时TAC文件
        # for tac_file in tac_files:
        #     try:
        #         os.remove(tac_file)
        #     except:
        #         pass

        print("All nodes terminated and temporary files cleaned up.")