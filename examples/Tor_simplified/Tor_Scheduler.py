from examples.Tor_simplified.Tor_Socket import Tor_Socket
from collections import defaultdict, deque
import asyncio
import time


class CircuitSendScheduler:
    def __init__(self, node):
        self.node = node
        self._socket_queues = defaultdict(deque)
        self._socket_members = defaultdict(set)
        self._socket_events = defaultdict(asyncio.Event)
        self._tasks = {}

    def notify_enqueue(self, circuit, out_sock: Tor_Socket):
        self._ensure_worker(out_sock)
        queue = self._socket_queues[out_sock]
        members = self._socket_members[out_sock]
        if circuit.id not in members:
            queue.append(circuit)
            members.add(circuit.id)
        self._socket_events[out_sock].set()

    def _ensure_worker(self, out_sock: Tor_Socket):
        if out_sock in self._tasks:
            return
        self._tasks[out_sock] = self.node._spawn_bg_task(
            self._run_socket(out_sock),
            name=f"circ_send_sched:{getattr(out_sock, 'peer_str', 'unknown')}",
        )

    async def _wait_for_credit(self, window, wake_event: asyncio.Event):
        if window.can_send(1):
            return

        done, pending = await asyncio.wait(
            [
                asyncio.create_task(window.credit_event.wait()),
                asyncio.create_task(wake_event.wait()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()

    async def _run_socket(self, out_sock: Tor_Socket):
        queue = self._socket_queues[out_sock]
        members = self._socket_members[out_sock]
        wake_event = self._socket_events[out_sock]
        while not out_sock._closing.is_set():
            if not queue:
                wake_event.clear()
                await asyncio.wait(
                    [
                        asyncio.create_task(wake_event.wait()),
                        asyncio.create_task(out_sock._closing.wait()),
                    ],
                    return_when=asyncio.FIRST_COMPLETED,
                )

            if not queue:
                continue

            circuit = queue.popleft()
            members.discard(circuit.id)
            entry = circuit.peek_sendq(out_sock)
            if entry is None:
                continue

            if entry.is_data:
                cw = self.node._cw_send(circuit, out_sock)
                if not cw.can_send(1):
                    queue.append(circuit)
                    members.add(circuit.id)
                    if len(queue) == 1:
                        await self._wait_for_credit(cw, wake_event)
                    continue
                if entry.stream is not None and not entry.stream.window.can_send(1):
                    queue.append(circuit)
                    members.add(circuit.id)
                    if len(queue) == 1:
                        await self._wait_for_credit(entry.stream.window, wake_event)
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
                members.add(circuit.id)