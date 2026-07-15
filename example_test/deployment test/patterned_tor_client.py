"""Pattern-aware Tor client for deployment experiments.

This subclass adds a pattern-based circuit builder that reuses the standard
``Tor_Client`` behaviors while allowing callers to specify whether each hop
(guard, middle, exit) should come from TorBox relays (``R``) or non-TorBox
relays (``T``). The pattern-aware path selection is the only customization;
all handshake, logging, and circuit construction logic remains identical to the
base client.
"""
from __future__ import annotations

import asyncio
import time
from typing import Iterable, List, Optional

from network_src.TorCore.Tor_Cell import CellDestroy
from network_src.TorCore.Tor_Client import Tor_Client
from network_src.TorCore.Tor_Consensus import Tor_Consensus
from network_src.TorCore.Tor_Router import Tor_Router
from network_src.TorCore.Tor_Socket import Tor_Socket
from tools.Log.utils import HopTimer, classify_exception
from tools.Log.bus import NoOpBus
from tools.Network_Management.delay_env import get_args

Pattern = str

PATTERNS: set[Pattern] = {
    "RRR",
    "TTT",
    "RTR",
    "TRT",
    "RRT",
    "RTT",
    "TRR",
    "TTR",
}


class PatternedTorClient(Tor_Client):
    """Tor_Client that can build 3-hop circuits using explicit hop patterns.

    The subclass intentionally mutes the base client's event bus logging so only
    the E1/E2/E3 deployment logs are emitted.
    """

    class _SilentBus(NoOpBus):
        def __init__(self):
            super().__init__()
            self.emit = lambda *_, **__: None  # type: ignore[attr-defined]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._pattern_lock = asyncio.Lock()
        self._current_pattern: Pattern | None = None  # Only set during explicit pattern builds
        self._guard_locks: dict[tuple[str, int], asyncio.Lock] = {}
        self._disable_base_logging()

    async def consensus_init(self):  # type: ignore[override]
        """Load consensus only; guard/socket is selected on demand."""
        await self.consensus.consus_init_async()
        self.ready_to_send.set()


    def _disable_base_logging(self):
        bus = self._SilentBus()
        self.event_bus = bus
        self._ev = bus.ev
        self._circuit = bus.circuit
        self._path = bus.path
        self._stream = bus.stream

    def attach_bus(self, bus=None):  # type: ignore[override]
        """Override to keep base Tor_Client logging silenced."""

        self._disable_base_logging()

    def _is_torbox_ip(self, ip: str) -> bool:
        return ip.startswith(Tor_Consensus.TORBOX_IP_PREFIX)

    def _guard_matches_pattern(self, guard_char: str) -> bool:
        if not self.guard:
            return False
        if guard_char == "R":
            return self._is_torbox_ip(self.guard.ip)
        return not self._is_torbox_ip(self.guard.ip)

    def _get_guard_lock(self, addr: tuple[str, int]) -> asyncio.Lock:
        if addr not in self._guard_locks:
            self._guard_locks[addr] = asyncio.Lock()
        return self._guard_locks[addr]

    async def _select_guard_for_char(self, guard_char: str) -> Tor_Router:
        if guard_char not in {"R", "T"}:
            raise ValueError(f"Unknown guard pattern char: {guard_char}")


        getter = (
            self.consensus.get_random_guard_node_torbox
            if guard_char == "R"
            else self.consensus.get_random_guard_node_not_torbox
        )
        guard_info = getter()
        guard_router = Tor_Router(guard_info)
        desc = await self.consensus.fetch_descriptor(guard_router.fingerprint_str)
        guard_router.set_descriptor(desc)
        return guard_router

    async def _get_or_create_guard_socket(self, guard_router: Tor_Router) -> Tor_Socket:
        """Return an existing handshake-complete socket or establish a new one."""

        addr = guard_router.addr
        lock = self._get_guard_lock(addr)
        async with lock:
            existing = self.socket_map.get(addr)
            if existing:
                if existing.handshake_done.is_set():
                    return existing
                # Wait for in-flight handshake to finish if already started
                await existing.handshake_done.wait()
                return existing

            socket = Tor_Socket(
                self.host,
                on_cell=self.handle_cell,
                node_id=self.node_id,
                limiter=self.limiter,
                **get_args(sim_ip=self.sim_ip),
            )
            await socket.setup_socket(remote_addr=addr)
            self._ev("tls_handshake_done", peer=f"{addr[0]}:{addr[1]}", side="client")

            self._spawn_bg_task(self.handle_connection(addr, socket))
            await socket.listen_started.wait()
            await socket.tor_handshake_client()
            await socket.handshake_done.wait()
            self._ev("tor_handshake_done", peer=f"{addr[0]}:{addr[1]}", versions=[3, 4], auth="none")

        return socket

    async def _ensure_guard_for_pattern(self, guard_char: str) -> Tor_Socket:
        if self._guard_matches_pattern(guard_char):
            socket = self.socket_map.get(self.guard.addr) if self.guard else None
            if socket and socket.handshake_done.is_set():
                return socket

        guard_router = await self._select_guard_for_char(guard_char)
        guard_socket = await self._get_or_create_guard_socket(guard_router)

        self.guard = guard_router  # Bind selected guard to client state for logging
        return guard_socket

    def _select_router(self, role: str, char: str, exclude: Iterable[str]):
        exclude_set = set(exclude or [])
        if char not in {"R", "T"}:
            raise ValueError(f"Unknown pattern char for role {role}: {char}")

        is_torbox = char == "R"
        if role == "middle":
            getter = (
                self.consensus.get_random_middle_node_torbox
                if is_torbox
                else self.consensus.get_random_middle_node_not_torbox
            )
        elif role == "exit":
            getter = (
                self.consensus.get_random_exit_node_torbox
                if is_torbox
                else self.consensus.get_random_exit_node_not_torbox
            )
        else:
            raise ValueError(f"Unsupported role: {role}")

        return getter(exclude=exclude_set)

    async def create_circuit(
        self,
        hops_count: int = 3,
        extend_routers: Optional[List[dict]] = None,
    ):
        pattern = self._current_pattern
        if pattern is None:
            if not self.guard:
                guard_info = self.consensus.get_random_guard_node()
                guard_router = Tor_Router(guard_info)
                desc = await self.consensus.fetch_descriptor(guard_router.fingerprint_str)
                guard_router.set_descriptor(desc)
                self.guard = guard_router
            await self._get_or_create_guard_socket(self.guard)
            return await super().create_circuit(hops_count=hops_count, extend_routers=extend_routers)

        guard_char, middle_char, exit_char = pattern
        guard_socket = await self._ensure_guard_for_pattern(guard_char)

        if extend_routers is None:
            exclude = {self.guard.fingerprint_str}
            middle_router = self._select_router("middle", middle_char, exclude)
            exclude.add(middle_router["fingerprint"])
            exit_router = self._select_router("exit", exit_char, exclude)
            extend_routers = [middle_router, exit_router]

        return await self._create_circuit_with_routers(guard_socket, extend_routers, hops_count=hops_count)

    async def build_circuit_by_pattern(
        self,
        pattern: Pattern,
        *,
        hops_count: int = 3,
        extend_routers: Optional[List[dict]] = None,
        isolation_key: str = "general",
        prefer_new: bool = True,
    ):
        """Explicitly build a circuit using the given pattern."""

        pattern = pattern.upper()
        if pattern not in PATTERNS:
            raise ValueError(f"Unsupported pattern '{pattern}'. Must be one of {sorted(PATTERNS)}")

        async with self._pattern_lock:
            self._current_pattern = pattern
            try:
                circuit = await self.circuit_mgr.get_or_build(
                    isolation_key, hops_count=hops_count, extend_routers=extend_routers, prefer_new=prefer_new
                )
            finally:
                self._current_pattern = None
        return circuit

    async def _create_circuit_with_routers(self, socket, extend_routers: List[dict], hops_count=3):
        if hops_count != 3:
            raise ValueError("PatternedTorClient only supports 3-hop circuits")
        if len(extend_routers) < 2:
            raise ValueError("extend_routers must provide at least middle and exit routers")

        circuit = await self.circuit_list.create_new_client(socket.channel)
        circuit.guard_socket = socket  # Record the guard socket used for this circuit
        snap = self.consensus.get_consensus_snapshot()
        t0_total = time.perf_counter()
        # Record when circuit construction begins (after TLS handshake, before first cell).
        circuit.build_start_ts = t0_total

        if not getattr(self.guard, "descriptor_str", None):
            desc = await self.consensus.fetch_descriptor(self.guard.fingerprint_str)
            self.guard.set_descriptor(desc)

        guard_hop = self.guard.spawn_circuit_hop()
        self._ev(
            "path_step_selected",
            circ_id=circuit.id,
            hop=1,
            nickname=guard_hop.nickname,
            fp=guard_hop.fingerprint_str,
            role="guard",
            consensus_id=snap["consensus_id"],
        )
        create_cell = circuit.make_create2_cell_to_guard(guard_hop)
        self._ev(
            "cell_trace",
            circ_id=circuit.id,
            peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
            side="client",
            dir="send",
            cell_cmd="CREATE2",
        )
        circuit.create2_send_ts = time.perf_counter()
        await socket.send_cell(create_cell)
        await circuit.guard_handsake(wait_time=600)

        hop_index = 2
        for router in extend_routers[: hops_count - 1]:
            descriptor_str = await self.consensus.fetch_descriptor(router["fingerprint"])
            extend_node = Tor_Router(router)
            extend_node.set_descriptor(descriptor_str)
            extend_hop = extend_node.spawn_circuit_hop()

            self._ev(
                "path_step_selected",
                circ_id=circuit.id,
                hop=hop_index,
                nickname=router["nickname"],
                fp=router["fingerprint"],
                role="middle" if hop_index == 2 else "exit",
                weight=router.get("bandwidth"),
                consensus_id=snap["consensus_id"],
            )

            t_rtt = HopTimer().start()
            try:
                extend_cell = circuit.connect_to_extend(extend_hop)
                self._ev(
                    "cell_trace",
                    circ_id=circuit.id,
                    peer=f"{extend_node.ip}:{extend_node.or_port}",
                    side="client",
                    dir="send",
                    cell_cmd="EXTEND2",
                )
                await socket.send_cell(extend_cell)
                await circuit.extend_handshake(descriptor_str, wait_time=60)
                self._ev(
                    "circuit_extend_success",
                    circ_id=circuit.id,
                    hop=hop_index,
                    nickname=router["nickname"],
                    fp=router["fingerprint"],
                    rtt_ms=t_rtt.ms(),
                )
            except Exception as e:  # noqa: BLE001
                reason = classify_exception(e).value
                self._ev(
                    "circuit_extend_fail",
                    circ_id=circuit.id,
                    hop=hop_index,
                    nickname=router["nickname"],
                    rtt_ms=t_rtt.ms(),
                    fp=router["fingerprint"],
                    fail_reason=reason,
                    error=str(e),
                )
                self._circuit(
                    circ_id=f"{self.name}:{circuit.id}",
                    client=self.name,
                    guard=self.guard.fingerprint_str,
                    middle=None,
                    exit=None,
                    build_ms=(time.perf_counter() - t0_total) * 1000.0,
                    success=False,
                    fail_reason=f"extend_hop{hop_index}:{e}",
                )
                raise

            hop_index += 1

        guard_fp = circuit.circuit_nodes[0].fingerprint_str
        exit_fp = circuit.circuit_nodes[-1].fingerprint_str
        middles = [n.fingerprint_str for n in circuit.circuit_nodes[1:-1]]
        middle_str = ";".join(middles) if middles else None

        self._path(
            client=self.name,
            guard=guard_fp,
            middle=middle_str,
            exit=exit_fp,
            wg=1.0,
            we=1.0,
            consensus_id=snap["consensus_id"],
        )

        self._circuit(
            circ_id=f"{self.name}:{circuit.id}",
            client=self.name,
            guard=guard_fp,
            middle=middle_str,
            exit=exit_fp,
            build_ms=(time.perf_counter() - t0_total) * 1000.0,
            success=True,
        )

        return circuit

    def get_active_guard_socket(self, circuit=None) -> Tor_Socket | None:
        """Safely fetch the guard socket used by a circuit (or current guard)."""

        if circuit is not None:
            sock = getattr(circuit, "guard_socket", None)
            if sock:
                return sock
        if self.guard:
            sock = self.socket_map.get(self.guard.addr)
            if sock and sock.handshake_done.is_set():
                return sock
        return None

    def _send_destroy(self, circ_id: int):
        sock = self.socket_map.get(self.guard.addr if self.guard else None)
        if not sock:
            return
        try:
            destroy = CellDestroy(circuit_id=circ_id, reason=0)
            asyncio.create_task(sock.send_cell(destroy))
        except Exception:
            pass