import os

from urllib.parse import urlparse
from typing import Literal

import socket
import asyncio
from typing import Optional
from tools.Network_Management.tls_registry import (
    register_server_ctx,
)
from examples.Tor_simplified.Tor_Circuit import Tor_CircuitsList
from examples.Tor_simplified.Tor_Cell import *

from tools.Log.LogPrinter import LogPrinter
from tools.Log.bus import EventBus, NoOpBus, GlobalBus
from tools.Packet.packet_TCP import accept_tls_connections, TLSConnector
from tools.Crypt.key_generator import create_server_context, ed25519_setup, rsa_setup, generate_cert_and_key_from_ed25519, generate_tls_rsa_cert
from tools.Network_Management.bandwidth_limiter import init_global_limiter_from_env

from examples.Tor_simplified.Tor_Socket import Tor_Socket
from tools.Network_Management.delay_env import get_args
import contextlib

class Tor_base:

    def __init__(self, name: str, host: str, port: int, model: Literal["sim", "real"] = "sim", sim_ip: str | None = None):

        self.host = host
        self.port = port
        self.name = name
        self.addr = (host, port)

        self.lock = asyncio.Lock()
        self.routing_table = {}
        self.circuit_list = Tor_CircuitsList()

        self.socket = self.socket_recv_set(self.host, self.port)   # Used to accept socket connections,not to send or receive data directly.
        self.socket_map = {}   # dict[Tuple[str, int], socket.socket]
        self.dire_ip, self.dire_port = self.get_directory_address()
        self.model = model
        self.tasks = {}  # save handles
        self.running = True
        self.node_id = f"{self.name}@{self.host}:{self.port}"

        self.tls_privt, self.tls_pubk = ed25519_setup()
        self.rsa_pvk, _ = rsa_setup()
        self.rsa_tls_pvk, self.rsa_tls_puk = rsa_setup()

        self.cert_file, self.key_file = generate_tls_rsa_cert(self.rsa_tls_pvk)
        register_server_ctx(self.node_id, self.cert_file, self.key_file)

        # self.context = create_server_context(self.cert_file, self.key_file)
        self.listener_ready = asyncio.Event()
        self.tls_connector = TLSConnector(
            certfile=self.cert_file,  # self.cert_file
            keyfile=self.key_file,  # self.key_file
            max_concurrent_tls=2000,  # 服务端并发TLS握手限制
            handshake_timeout=15.0  # 适当的握手超时
        )

        # Unified log output format
        printer = LogPrinter(name)
        self.print = printer.print

        # 默认给 NoOpBus，确保永不为 None（零侵入调用）
        self.event_bus: EventBus | NoOpBus = NoOpBus()
        # 绑定常用方法引用，减少属性查找开销（微优化）
        self._ev = self.event_bus.ev
        self._circuit = self.event_bus.circuit
        self._path = self.event_bus.path
        self._stream = self.event_bus.stream

        self.sim_ip = sim_ip
        self._bg_tasks: set[asyncio.Task] = set()
        self.limiter = init_global_limiter_from_env()

    def attach_bus(self, bus: Optional[EventBus]):
        """在启动脚本里调用；忘记传就用全局默认。"""
        self.event_bus = bus
        # 重新绑定快捷引用（避免每次 getattr）
        self._ev = bus.ev
        self._circuit = bus.circuit
        self._path = bus.path
        self._stream = bus.stream


    def sign_message(self, private_key, message):
        signature = private_key.sign(message)
        return signature

    def verify_sign(self, public_key, message, signature):
        public_key.verify(signature, message)

    @staticmethod
    def socket_recv_set(host: str, port: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(2048)  # backlog >= max_concurrent_tls
        sock.setblocking(False)
        return sock

    @staticmethod
    def get_directory_address(default=None):
        addr = os.environ.get('DIRECTORY_ADDR', default)
        # print("addr is :",addr)
        if not addr:
            return None  # ✅ 改为返回 None 而不是抛错

        if "://" not in addr:
            addr = "http://" + addr

        parsed = urlparse(addr)
        host = parsed.hostname
        port = parsed.port

        if host is None or port is None:
            raise ValueError(f"Invalid DIRECTORY_ADDR format: {addr}")

        return (host, port)

    # examples/Tor_simplified/Tor_base.py

    from tools.Network_Management.delay_env import get_args  # 顶部已有就不用再加

    async def monitor_tor_socket(self):
        async def on_accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            tor_sock = Tor_Socket(
                reader=reader,
                writer=writer,
                source_ip=self.host,
                on_cell=self.handle_cell,
                node_id=self.node_id,
                limiter=self.limiter,
                **get_args(sim_ip=self.sim_ip)
            )

            peer = writer.get_extra_info("peername")
            if not peer:
                return
            addr = (peer[0], peer[1])

            # ★必须统一走 handle_connection，确保回收
            self._spawn_bg_task(self.handle_connection(addr, tor_sock))

        self.print(f"[LISTEN] Node {self.name} listening on {self.host}:{self.port}")
        try:
            await accept_tls_connections(
                self.socket,
                self.tls_connector,
                on_accept,
                node_id=self.node_id,
                on_server_ready=self.listener_ready.set
            )
        except asyncio.CancelledError:
            raise
        finally:
            with contextlib.suppress(Exception):
                self.socket.close()


    async def handle_connection(self, addr, tor_sock: Tor_Socket):
        self.socket_map[addr] = tor_sock
        handle = None
        try:
            handle = await tor_sock.start_listen()

            # ★避免 start_listen 内部异常导致 listen_started 永远不 set
            await asyncio.wait_for(tor_sock.listen_started.wait(), timeout=3.0)

            await handle

        except asyncio.TimeoutError:
            self._ev("conn_listen_not_started", peer=f"{addr[0]}:{addr[1]}")
            with contextlib.suppress(Exception):
                await tor_sock._abort()

        except asyncio.CancelledError:
            with contextlib.suppress(Exception):
                await tor_sock._abort()
            raise

        except Exception as e:
            self._ev("conn_task_error", peer=f"{addr[0]}:{addr[1]}", error=str(e))
            with contextlib.suppress(Exception):
                await tor_sock._abort()

        finally:
            self.socket_map.pop(addr, None)

            with contextlib.suppress(Exception):
                await self._cleanup_dependents_for_socket(tor_sock)

            self.print(f"[AsyncMonitor] Connection {addr} closed and removed from map.")

    def handle_cell(self, cell, sock):
        pass


    async def _cleanup_dependents_for_socket(self, dead_sock: Tor_Socket):
        """
        当某条 TLS/Tor 连接断开时，清理所有依赖该连接的 circuit/stream，避免任务泄漏。
        """
        # 1) 找所有包含 dead_sock 的 circuit
        affected = []
        for c in list(self.circuit_list.values()):  # 如果你没有 values()，换成你内部保存 circuit 的迭代方式
            try:
                for n in getattr(c, "circuit_nodes", []):
                    if getattr(n, "sock", None) == dead_sock:
                        affected.append(c)
                        break
            except Exception:
                continue

        # 2) 对每个 circuit：关 stream，尝试通知对端 DESTROY，然后从 circuit_list 移除
        for c in affected:
            cid = getattr(c, "id", None)
            with contextlib.suppress(Exception):
                c.close_all_streams()

            # 发 DESTROY（如果还有对端可发的话）
            with contextlib.suppress(Exception):
                # 选择一条仍然活着的 sock 发送 DESTROY
                for n in getattr(c, "circuit_nodes", []):
                    s = getattr(n, "sock", None)
                    if s and not s._closing.is_set():
                        await s.send_cell(CellDestroy(circuit_id=cid, reason=0))
                        break

            with contextlib.suppress(Exception):
                c.circuit_nodes.clear()

            with contextlib.suppress(Exception):
                self.circuit_list.remove(cid)

            self._ev("circuit_cleanup_due_to_sock_close", circ_id=cid, peer=str(getattr(dead_sock, "peer_str", "unknown")))

    async def stop_protocol(self):
        self.running = False

        # A) cancel 并 await start_protocol 里登记的长期任务
        for t in list(getattr(self, "tasks", {}).values()):
            if t and not t.done():
                t.cancel()
        for t in list(getattr(self, "tasks", {}).values()):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t

        # B) cancel 并 await 所有后台任务（包括 handle_connection, stream pumps 等）
        bg = list(getattr(self, "_bg_tasks", set()))
        for t in bg:
            if t and not t.done():
                t.cancel()
        if bg:
            await asyncio.gather(*bg, return_exceptions=True)
        if hasattr(self, "_bg_tasks"):
            self._bg_tasks.clear()

        # C) 关闭所有 Tor_Socket（此时 loop 还活着，安全）
        for addr, s in list(getattr(self, "socket_map", {}).items()):
            with contextlib.suppress(Exception):
                await s._abort()
        if hasattr(self, "socket_map"):
            self.socket_map.clear()

        # D) 关闭监听 socket，确保不再向 selector 注册已失效的 fd
        with contextlib.suppress(Exception):
            self.socket.close()

        # E) 可选：停掉你自己的 flush task
        t = getattr(self, "_relay_flush_task", None)
        if t and not t.done():
            t.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await t

        if self.limiter is not None:
            stats = self.limiter.stats()
            self.print(
                f"[LimiterStats] total={stats.total_bytes}B "
                f"avg={stats.average_rate_bps:.2f}B/s peak={stats.peak_rate_bps:.2f}B/s"
            )
            
    def _spawn_bg_task(self, coro,  name: str | None = None):
        t = asyncio.create_task(coro)
        self._bg_tasks.add(t)
        t.add_done_callback(lambda _t: self._bg_tasks.discard(_t))
        return t

