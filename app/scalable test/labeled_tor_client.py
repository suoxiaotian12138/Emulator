"""Tor client wrapper that prefixes logs with a ratio label.

The deployment experiments need a lightweight client that behaves like the
base ``Tor_Client`` but ensures every emitted log record carries a
``ratio_label`` prefix so runs from different TorBox replacement ratios are
trivially distinguishable. No path-pattern awareness is required here; circuit
selection remains the default random behavior from ``Tor_Client``.
"""
from __future__ import annotations
import asyncio
from typing import Callable
import contextlib
from examples.Tor_simplified.Tor_Router import Tor_Router
from examples.Tor_simplified.Tor_Socket import Tor_Socket
from examples.Tor_simplified.Tor_Client import Tor_Client
from tools.Log.bus import EventBus
from tools.Log.writer import AsyncJsonlWriter
from tools.Network_Management.delay_env import get_args

class LabeledTorClient(Tor_Client):
    """Tor_Client variant that injects a ratio label into all bus emissions."""

    def __init__(self, *args, ratio_label: str, writer: AsyncJsonlWriter, **kwargs):
        super().__init__(*args, **kwargs)
        self.ratio_label = ratio_label
        self._writer = writer
        self._guard_locks: dict[tuple[str, int], asyncio.Lock] = {}

    async def consensus_init(self):  # type: ignore[override]
        """Load consensus only; guard selection happens per-circuit."""

        await self.consensus.consus_init_async()
        self.ready_to_send.set()

    def _wrap_emitter(self, emitter: Callable[[str, dict], None]) -> Callable[[str, dict], None]:
        def wrapped(kind: str, record: dict) -> None:
            tagged = {"ratio_label": self.ratio_label}
            tagged.update(record)
            emitter(kind, tagged)

        return wrapped

    def attach_labeled_bus(
            self,
            role: str = "client",
            *,
            enable_circuit_summary: bool = True,  # 控制 self._circuit
            enable_path_summary: bool = False,  # 可选：控制 self._path
            enable_stream_summary: bool = False,  # 可选：控制 self._stream
            enable_ev: bool = False,  # 可选：控制 self._ev(cell_trace 等)
    ) -> None:
        bus = EventBus(self._wrap_emitter(self._writer.emit_nowait), node_id=self.name, role=role)
        self.event_bus = bus
        self.emit = bus.emit

        def _noop(*args, **kwargs):
            return None

        self._circuit = bus.circuit if enable_circuit_summary else _noop
        self._path = bus.path if enable_path_summary else _noop
        self._stream = bus.stream if enable_stream_summary else _noop
        self._ev = bus.ev if enable_ev else _noop

    def _get_guard_lock(self, addr: tuple[str, int]) -> asyncio.Lock:
        if addr not in self._guard_locks:
            self._guard_locks[addr] = asyncio.Lock()
        return self._guard_locks[addr]

    async def _select_guard(self) -> Tor_Router:
        guard_info = self.consensus.get_random_guard_node()
        guard_router = Tor_Router(guard_info)
        desc = await self.consensus.fetch_descriptor(guard_router.fingerprint_str)
        guard_router.set_descriptor(desc)
        return guard_router

    async def _ensure_guard_and_socket(self) -> tuple[Tor_Router, Tor_Socket]:
        """Reuse existing guard/socket when possible to avoid redundant fetches."""

        if self.guard:
            socket = self.socket_map.get(self.guard.addr)
            if socket and socket.handshake_done.is_set():
                return self.guard, socket

        guard_router = self.guard or await self._select_guard()
        guard_socket = await self._get_or_create_guard_socket(guard_router)
        self.guard = guard_router
        return guard_router, guard_socket

    async def _get_or_create_guard_socket(self, guard_router: Tor_Router) -> Tor_Socket:
        """Return an existing handshake-complete socket or establish a new one."""
        if getattr(self, "_stopping", False):
            raise asyncio.CancelledError

        addr = guard_router.addr
        lock = self._get_guard_lock(addr)
        async with lock:
            if getattr(self, "_stopping", False):
                raise asyncio.CancelledError
            existing = self.socket_map.get(addr)
            if existing:
                if existing.handshake_done.is_set():
                    return existing
                await existing.handshake_done.wait()
                return existing

            socket = Tor_Socket(
                self.host,
                on_cell=self.handle_cell,
                node_id=self.node_id,
                limiter=self.limiter,
                **get_args(sim_ip=self.sim_ip),
            )
            try:
                await socket.setup_socket(remote_addr=addr)
                self._ev("tls_handshake_done", peer=f"{addr[0]}:{addr[1]}", side="client")

                self._spawn_bg_task(self.handle_connection(addr, socket))
                await socket.listen_started.wait()
                await socket.tor_handshake_client()
                await socket.handshake_done.wait()
                self._ev("tor_handshake_done", peer=f"{addr[0]}:{addr[1]}", versions=[3, 4], auth="none")
            except asyncio.CancelledError:
                with contextlib.suppress(Exception):
                    await socket._abort()
                raise
            except Exception:
                with contextlib.suppress(Exception):
                    await socket._abort()
                raise

        return socket

    async def create_circuit(self, hops_count: int = 3, extend_routers=None):  # type: ignore[override]
        guard_router, guard_socket = await self._ensure_guard_and_socket()

        if guard_socket.handshake_done.is_set():
            self.socket_map[guard_router.addr] = guard_socket

        circuit = await super().create_circuit(hops_count=hops_count, extend_routers=extend_routers)



        return circuit