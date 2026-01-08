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
import asyncio
import time

class LabeledTorClient(Tor_Client):
    """Tor_Client variant that injects a ratio label into all bus emissions."""

    def __init__(self, *args, ratio_label: str, writer: AsyncJsonlWriter, tls_sem: asyncio.Semaphore | None = None,**kwargs):
        super().__init__(*args, **kwargs)
        self.ratio_label = ratio_label
        self._writer = writer
        self._guard_locks: dict[tuple[str, int], asyncio.Lock] = {}
        self._tls_sem = tls_sem

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
                if self._tls_sem is None:
                    await socket.setup_socket(remote_addr=addr)
                else:
                    async with self._tls_sem:
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

    import time

    async def create_circuit(self, hops_count: int = 3, extend_routers=None):  # type: ignore[override]
        t_e2e0 = time.perf_counter()

        # 1) Ensure guard and socket
        t0 = time.perf_counter()
        guard_router, guard_socket = await self._ensure_guard_and_socket()
        guard_prepare_ms = (time.perf_counter() - t0) * 1000.0

        # Make the socket visible to legacy code paths if needed
        # Do it unconditionally to avoid "guard socket not ready".
        try:
            self.socket_map[guard_router.addr] = guard_socket
        except Exception:
            pass

        # 2) Create circuit object on this guard channel
        # This mirrors Tor_Client.create_circuit but uses guard_socket directly.
        if not getattr(self, "circuit_list", None):
            raise RuntimeError("circuit_list not initialized")

        circuit = await self.circuit_list.create_new_client(guard_socket.channel)

        snap = self.consensus.get_consensus_snapshot()
        used_fp = set()

        # 3) Guard descriptor fetch (separate timing)
        t_proto0 = time.perf_counter()
        t_desc0 = time.perf_counter()
        if not getattr(self.guard, "descriptor_str", None):
            desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
            self.guard.set_descriptor(desc)
        guard_desc_fetch_ms = (time.perf_counter() - t_desc0) * 1000.0

        used_fp.add(self.guard.fingerprint_str)
        guard_hop = self.guard.spawn_circuit_hop()
        self.print("guard is :", self.guard.ip)

        # 4) CREATE2 send + guard handshake timing
        self._ev(
            "path_step_selected",
            circ_id=circuit.id, hop=1, nickname=guard_hop.nickname,
            fp=guard_hop.fingerprint_str, role="guard",
            consensus_id=snap["consensus_id"],
        )

        create_cell = circuit.make_create2_cell_to_guard(guard_hop)

        t_send0 = time.perf_counter()
        await guard_socket.send_cell(create_cell)
        create2_send_ms = (time.perf_counter() - t_send0) * 1000.0

        # IMPORTANT: protect long waits with asyncio.wait_for
        t_hs0 = time.perf_counter()
        try:
            await asyncio.wait_for(circuit.guard_handsake(wait_time=600), timeout=60.0)
        except asyncio.TimeoutError as e:
            # Emit a structured fail event
            self._ev("circuit_guard_handshake_timeout", circ_id=circuit.id)
            raise
        guard_handshake_ms = (time.perf_counter() - t_hs0) * 1000.0

        # 5) EXTEND2 loop
        hop_timings = []
        while circuit.nodes_count < hops_count:
            hop = circuit.nodes_count + 1
            if hop == hops_count:
                router = self.consensus.get_random_exit_node(exclude=used_fp)
                role = "exit"
            else:
                router = self.consensus.get_random_middle_node(exclude=used_fp)
                role = "middle"

            used_fp.add(router["fingerprint"])

            self._ev(
                "path_step_selected",
                circ_id=circuit.id, hop=hop, nickname=router["nickname"],
                fp=router["fingerprint"], role=role,
                weight=router.get("bandwidth"),
                consensus_id=snap["consensus_id"],
            )

            # Descriptor fetch timing per hop
            t_dh0 = time.perf_counter()
            descriptor_str = await self.consensus.fetch_descriptor(router["fingerprint"])
            desc_fetch_ms = (time.perf_counter() - t_dh0) * 1000.0

            extend_node = Tor_Router(router)
            extend_node.set_descriptor(descriptor_str)
            extend_hop = extend_node.spawn_circuit_hop()

            # EXTEND2 send timing
            t_es0 = time.perf_counter()
            extend_cell = circuit.connect_to_extend(extend_hop)
            await guard_socket.send_cell(extend_cell)
            extend_send_ms = (time.perf_counter() - t_es0) * 1000.0

            # Extend handshake timing with outer timeout
            t_eh0 = time.perf_counter()
            try:
                await asyncio.wait_for(circuit.extend_handshake(descriptor_str, wait_time=60), timeout=60.0)
            except asyncio.TimeoutError:
                self._ev(
                    "circuit_extend_timeout",
                    circ_id=circuit.id, hop=hop, fp=router["fingerprint"], role=role
                )
                raise
            extend_hs_ms = (time.perf_counter() - t_eh0) * 1000.0
            self.print("hop is :", extend_node.ip)

            hop_timings.append(
                {
                    "hop": hop,
                    "role": role,
                    "fp": router["fingerprint"],
                    "desc_fetch_ms": desc_fetch_ms,
                    "extend_send_ms": extend_send_ms,
                    "extend_hs_ms": extend_hs_ms,
                }
            )

        protocol_build_ms = (time.perf_counter() - t_proto0) * 1000.0
        e2e_build_ms = (time.perf_counter() - t_e2e0) * 1000.0

        # 6) Emit one consolidated timing record
        self._ev(
            "circuit_timing",
            circ_id=f"{self.name}:{circuit.id}",
            client=self.name,
            hops=hops_count,
            guard_fp=guard_hop.fingerprint_str,
            consensus_id=snap["consensus_id"],
            guard_prepare_ms=guard_prepare_ms,
            guard_desc_fetch_ms=guard_desc_fetch_ms,
            create2_send_ms=create2_send_ms,
            guard_handshake_ms=guard_handshake_ms,
            protocol_build_ms=protocol_build_ms,
            e2e_build_ms=e2e_build_ms,
            hop_timings=hop_timings,
            success=True,
        )

        timing = {
            "guard_prepare_ms": guard_prepare_ms,
            "guard_desc_fetch_ms": guard_desc_fetch_ms,
            "create2_send_ms": create2_send_ms,
            "guard_handshake_ms": guard_handshake_ms,
            "hop_timings": hop_timings,
            "protocol_build_ms": protocol_build_ms,
            "e2e_build_ms": e2e_build_ms,
        }
        return circuit, timing