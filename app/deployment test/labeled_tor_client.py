"""Tor client wrapper that prefixes logs with a ratio label.

The deployment experiments need a lightweight client that behaves like the
base ``Tor_Client`` but ensures every emitted log record carries a
``ratio_label`` prefix so runs from different TorBox replacement ratios are
trivially distinguishable. No path-pattern awareness is required here; circuit
selection remains the default random behavior from ``Tor_Client``.
"""
from __future__ import annotations

import asyncio
import time
from typing import Callable

from examples.Tor_simplified.Tor_Cell import CellRelayData, RelayedTorCell
from examples.Tor_simplified.Tor_Client import Tor_Client
from examples.Tor_simplified.Tor_Router import Tor_Router
from examples.Tor_simplified.Tor_Socket import Tor_Socket
from tools.Log.bus import EventBus
from tools.Log.writer import AsyncJsonlWriter
from tools.Network_Management.delay_env import get_args
from examples.Tor_simplified.Tor_Circuit import compute_isolation_key


class LabeledTorClient(Tor_Client):
    """Tor_Client variant that injects a ratio label and rotates guards on demand."""

    def __init__(self, *args, ratio_label: str, writer: AsyncJsonlWriter, **kwargs):
        super().__init__(*args, **kwargs)
        self.ratio_label = ratio_label
        self._writer = writer
        self._guard_locks: dict[tuple[str, int], asyncio.Lock] = {}
        self._descriptor_cache: dict[str, str] = {}
        self._descriptor_locks: dict[str, asyncio.Lock] = {}
        self._circuit_guards: dict[int, Tor_Router] = {}
        # Suppress verbose base client logging to keep experiment output lean.
        self.print = lambda *args, **kwargs: None

    def _wrap_emitter(self, emitter: Callable[[str, dict], None]) -> Callable[[str, dict], None]:
        def wrapped(kind: str, record: dict) -> None:
            tagged = {"ratio_label": self.ratio_label}
            tagged.update(record)
            emitter(kind, tagged)

        return wrapped

    async def consensus_init(self):  # type: ignore[override]
        """Load consensus only; guard sockets are selected lazily per circuit."""

        await self.consensus.consus_init_async()
        self.ready_to_send.set()

    def _get_guard_lock(self, addr: tuple[str, int]) -> asyncio.Lock:
        if addr not in self._guard_locks:
            self._guard_locks[addr] = asyncio.Lock()
        return self._guard_locks[addr]

    def _get_descriptor_lock(self, fingerprint: str) -> asyncio.Lock:
        if fingerprint not in self._descriptor_locks:
            self._descriptor_locks[fingerprint] = asyncio.Lock()
        return self._descriptor_locks[fingerprint]

    async def _fetch_guard_descriptor(self, guard_router: Tor_Router, *, retries: int = 3) -> str:
        fingerprint = guard_router.fingerprint_str
        if fingerprint in self._descriptor_cache:
            return self._descriptor_cache[fingerprint]

        lock = self._get_descriptor_lock(fingerprint)
        async with lock:
            if fingerprint in self._descriptor_cache:
                return self._descriptor_cache[fingerprint]

            last_error: BaseException | None = None
            for _ in range(retries):
                try:
                    desc = await self.consensus.fetch_descriptor(fingerprint)
                    self._descriptor_cache[fingerprint] = desc
                    return desc
                except asyncio.TimeoutError as exc:  # pragma: no cover - network timing
                    last_error = exc
                    await asyncio.sleep(0)
            if last_error is not None:
                raise last_error
            raise RuntimeError("descriptor fetch failed without explicit error")

    async def _select_guard(self) -> Tor_Router:
        attempts = 0
        while True:
            attempts += 1
            guard_info = self.consensus.get_random_guard_node()
            guard_router = Tor_Router(guard_info)
            try:
                desc = await self._fetch_guard_descriptor(guard_router)
                guard_router.set_descriptor(desc)
                return guard_router
            except asyncio.TimeoutError:
                if attempts >= 5:
                    raise
                await asyncio.sleep(0)

    async def _get_or_create_guard_socket(self, guard_router: Tor_Router) -> Tor_Socket:
        addr = guard_router.addr
        lock = self._get_guard_lock(addr)
        async with lock:
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
            await socket.setup_socket(remote_addr=addr)
            self._ev("tls_handshake_done", peer=f"{addr[0]}:{addr[1]}", side="client")

            self._spawn_bg_task(self.handle_connection(addr, socket))
            await socket.listen_started.wait()
            await socket.tor_handshake_client()
            await socket.handshake_done.wait()
            self._ev("tor_handshake_done", peer=f"{addr[0]}:{addr[1]}", versions=[3, 4], auth="none")

        return socket

    async def create_circuit(self, hops_count=3, extend_routers=None):  # type: ignore[override]
        await self.ready_to_send.wait()
        guard_router = await self._select_guard()
        guard_socket = await self._get_or_create_guard_socket(guard_router)
        self.guard = guard_router
        circ = await super().create_circuit(hops_count=hops_count, extend_routers=extend_routers)
        self._circuit_guards[circ.id] = guard_router
        return circ

    async def _bind_guard_for_circuit(self, circ) -> Tor_Socket | None:
        guard_router = self._circuit_guards.get(circ.id)
        if guard_router is None:
            return None

        self.guard = guard_router
        socket = self.socket_map.get(guard_router.addr)
        if socket and socket.handshake_done.is_set():
            return socket

        return await self._get_or_create_guard_socket(guard_router)

    async def make_stream(self, message, addr, hops_count=3, extend_routers=None):  # type: ignore[override]
        await self.ready_to_send.wait()

        if getattr(self.circuit_mgr, "isolation_enabled", False):
            iso_key = compute_isolation_key(addr[0], addr[1])
        else:
            iso_key = "general"

        circuit = await self.circuit_mgr.get_or_build(
            iso_key,
            exit_hint=None,
            hops_count=hops_count,
            extend_routers=extend_routers,
        )
        guard_socket = await self._bind_guard_for_circuit(circuit)
        self.circuit_mgr.mark_used(circuit)
        stream = circuit.create_stream()

        stream_id = stream.id
        stream_uid = f"{self.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
        dst = f"{addr[0]}:{addr[1]}"
        self.stream_tracker.start(stream_uid, src=self.name, dst=dst)
        if stream_id is not None:
            self._sid2uid[stream_id] = stream_uid

        try:
            connect_cell = stream.make_connect(addr)
            if guard_socket is None:
                guard_socket = self.socket_map.get(self.guard.addr, None)
            if guard_socket is None:
                raise RuntimeError("guard socket unavailable for circuit send")
            await guard_socket.send_cell(connect_cell)
            await stream.wait_connect_ack()

            max_payload = RelayedTorCell.MAX_PAYLOD_SIZE
            off = 0
            n = len(message)

            while off < n:
                await stream.window.acquire_send(1)

                if hasattr(circuit, "circ_window_up"):
                    await circuit.circ_window_up.acquire_send(1)

                chunk = message[off : off + max_payload]
                off += len(chunk)

                data_cell = stream.make_relay(CellRelayData(chunk, circuit.id))
                self._ev(
                    "cell_trace",
                    circ_id=circuit.id,
                    stream_id=stream.id,
                    peer=f"{self.guard.addr[0]}:{self.guard.addr[1]}",
                    side="client",
                    dir="send",
                    cell_cmd="RELAY_DATA",
                )
                await guard_socket.send_cell(data_cell)

        except asyncio.TimeoutError:
            self.stream_tracker.set_status(stream_uid, "timeout")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise
        except ConnectionResetError:
            self.stream_tracker.set_status(stream_uid, "reset")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise
        except Exception:
            self.stream_tracker.set_status(stream_uid, "error")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise

    async def open_stream(self, addr, hops_count=3, extend_routers=None):  # type: ignore[override]
        await self.ready_to_send.wait()

        if getattr(self.circuit_mgr, "isolation_enabled", False):
            iso_key = compute_isolation_key(addr[0], addr[1])
        else:
            iso_key = "general"

        circuit = await self.circuit_mgr.get_or_build(
            iso_key,
            exit_hint=None,
            hops_count=hops_count,
            extend_routers=extend_routers,
        )
        guard_socket = await self._bind_guard_for_circuit(circuit)
        self.circuit_mgr.mark_used(circuit)
        stream = circuit.create_stream()

        stream_id = stream.id
        stream_uid = f"{self.name}:{circuit.id}:{stream_id if stream_id is not None else int(time.time() * 1e6)}"
        dst = f"{addr[0]}:{addr[1]}"
        self.stream_tracker.start(stream_uid, src=self.name, dst=dst)
        if stream_id is not None:
            self._sid2uid[stream_id] = stream_uid

        try:
            connect_cell = stream.make_connect(addr)
            if guard_socket is None:
                guard_socket = self.socket_map.get(self.guard.addr, None)
            if guard_socket is None:
                raise RuntimeError("guard socket unavailable for circuit send")
            await guard_socket.send_cell(connect_cell)
            await stream.wait_connect_ack()
        except asyncio.TimeoutError:
            self.stream_tracker.set_status(stream_uid, "timeout")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise
        except ConnectionResetError:
            self.stream_tracker.set_status(stream_uid, "reset")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise
        except Exception:
            self.stream_tracker.set_status(stream_uid, "error")
            rec = self.stream_tracker.end(stream_uid)
            self._stream(**rec) if rec else None
            raise

    def attach_labeled_bus(self, role: str = "client") -> None:
        bus = EventBus(self._wrap_emitter(self._writer.emit_nowait), node_id=self.name, role=role)
        self.event_bus = bus
        self.emit = bus.emit
        self._ev = bus.ev
        self._circuit = bus.circuit
        self._path = bus.path
        self._stream = bus.stream