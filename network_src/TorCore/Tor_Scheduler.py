from network_src.TorCore.Tor_Socket import Tor_Socket
from collections import defaultdict, deque
import asyncio
import time


class CircuitSendScheduler:
    def __init__(self, node):
        self.node = node
        self._socket_queues = defaultdict(deque)
        self._socket_members = defaultdict(set)
        self._ready_sockets = deque()
        self._ready_set = set()
        self._blocked_sockets = set()
        self._wake_event = asyncio.Event()
        self._task = None
        self._wait_tasks = {}

    def notify_enqueue(self, circuit, out_sock: Tor_Socket):
        self._ensure_runner()
        queue = self._socket_queues[out_sock]
        members = self._socket_members[out_sock]
        if circuit.id not in members:
            queue.append(circuit)
            members.add(circuit.id)
        if out_sock not in self._blocked_sockets and out_sock not in self._ready_set:
            self._ready_sockets.append(out_sock)
            self._ready_set.add(out_sock)
        self._wake_event.set()

    def _ensure_runner(self):
        if self._task is not None and not self._task.done():
            return
        self._task = self.node._spawn_bg_task(
            self._run(),
            name="circ_send_sched:global",
        )

    def _schedule_ready_on_event(self, out_sock: Tor_Socket, event: asyncio.Event, reason: str):
        if event is None:
            return

        key = (out_sock, id(event))
        if key in self._wait_tasks:
            return
        task = self.node._spawn_bg_task(
            self._wait_event_and_ready(out_sock, event, key),
            name=f"circ_send_sched:wait:{reason}:{getattr(out_sock, 'peer_str', 'unknown')}",
        )
        self._wait_tasks[key] = task

    async def _wait_event_and_ready(self, out_sock: Tor_Socket, event: asyncio.Event, key):
        try:
            await event.wait()
        finally:
            self._wait_tasks.pop(key, None)

        if out_sock._closing.is_set():
            return
        if out_sock in self._blocked_sockets:
            return
        queue = self._socket_queues.get(out_sock)
        if queue and out_sock not in self._ready_set:
            self._ready_sockets.append(out_sock)
            self._ready_set.add(out_sock)
            self._wake_event.set()

    def _block_on_outbuf(self, out_sock: Tor_Socket):
        if out_sock in self._blocked_sockets:
            return
        self._blocked_sockets.add(out_sock)
        self._schedule_ready_on_event(out_sock, out_sock._outbuf_low_event, "outbuf_low")

    async def _run(self):
        while True:
            if not self._ready_sockets:
                self._wake_event.clear()
                await self._wake_event.wait()

            if not self._ready_sockets:
                continue

            out_sock = self._ready_sockets.popleft()
            self._ready_set.discard(out_sock)

            if out_sock._closing.is_set() or out_sock in self._blocked_sockets:
                continue

            queue = self._socket_queues.get(out_sock)
            members = self._socket_members.get(out_sock)

            if not queue:
                continue

            circuit = queue.popleft()
            if members is not None:
                members.discard(circuit.id)
            entry = circuit.peek_sendq(out_sock)
            if entry is None:
                continue

            if entry.is_data:
                cw = self.node._cw_send(circuit, out_sock)
                if not cw.can_send(1):
                    queue.append(circuit)
                    if members is not None:
                        members.add(circuit.id)
                    self._schedule_ready_on_event(out_sock, cw.credit_event, "circ_credit")
                    continue
                if entry.stream is not None and not entry.stream.window.can_send(1):
                    queue.append(circuit)
                    if members is not None:
                        members.add(circuit.id)
                    self._schedule_ready_on_event(out_sock, entry.stream.window.credit_event, "stream_credit")
                    continue
                if not out_sock.can_accept_data():
                    queue.append(circuit)
                    if members is not None:
                        members.add(circuit.id)
                    self._block_on_outbuf(out_sock)
                    continue
                circuit.pop_sendq(out_sock)
                cw.on_send_data_cell(1)
                if cw.should_record_sendme_sent():
                    direction = self.node._sendme_direction_for_out_sock(circuit, out_sock)
                    digest = getattr(entry.cell, "_sendme_digest_forward", None)
                    circuit.record_sendme_expected(direction, digest)
                if entry.stream is not None:
                    entry.stream.window.on_send_data_cell(1)
            else:
                circuit.pop_sendq(out_sock)

            await out_sock.send_cell(entry.cell)
            circuit.record_send_dequeue(time.monotonic() - entry.enqueued_at)

            if circuit.peek_sendq(out_sock):
                queue.append(circuit)
                if members is not None:
                    members.add(circuit.id)

            if queue and out_sock not in self._blocked_sockets and out_sock not in self._ready_set:
                self._ready_sockets.append(out_sock)
                self._ready_set.add(out_sock)