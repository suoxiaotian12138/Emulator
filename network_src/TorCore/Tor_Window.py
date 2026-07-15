# network_src/TorCore/tor_window.py
from __future__ import annotations
import asyncio


class TorWindow:
    """
    Tor-like window model (usable for stream-level and circuit-level).

    send_window: how many RELAY_DATA cells we can still send (package window)
    recv_window: how many RELAY_DATA cells we are willing to receive (deliver window)
    increment:   how many cells a SENDME returns

    credit_event: set whenever send_window increases, so senders can await credit.
    """

    def __init__(self, start: int, increment: int):
        self.start = int(start)
        self.increment = int(increment)

        self.send_window = int(start)
        self.recv_window = int(start)

        self.credit_event = asyncio.Event()
        self.credit_event.set()  # initial credit exists
        self._send_lock = asyncio.Lock()

    # ---------------- sending side ----------------

    def can_send(self, cells: int = 1) -> bool:
        return self.send_window >= cells

    async def wait_send_credit(self, cells: int = 1, timeout: float | None = None):
        """
        Block until we have at least `cells` send credit.
        """
        if self.can_send(cells):
            return
        self.credit_event.clear()
        if timeout is None:
            while not self.can_send(cells):
                await self.credit_event.wait()
                if not self.can_send(cells):
                    self.credit_event.clear()
        else:
            while not self.can_send(cells):
                await asyncio.wait_for(self.credit_event.wait(), timeout=timeout)
                if not self.can_send(cells):
                    self.credit_event.clear()

    def on_send_data_cell(self, cells: int = 1):
        self.send_window -= cells
        if self.send_window <= 0:
            self.credit_event.clear()

    def should_record_sendme_sent(self) -> bool:
        """
        Record digest only for the DATA cell that is right before we expect a SENDME.
        Tor logic: record only every `increment` DATA cells, not every cell.
        """
        sent = self.start - self.send_window  # how many DATA cells have been sent so far
        if sent <= 0:
            return False
        return (sent % self.increment) == 0

    def sent_cell_for_sendme(self) -> bool:
        """
        Tor-like: return True iff the cell we just sent is the one that should trigger
        an incoming SENDME from the other side.
        """
        return self.should_record_sendme_sent()


    async def acquire_send(self, cells: int = 1, timeout: float | None = None):
        """
        Atomically: wait for credit, then decrement send_window.
        Prevents multi-stream oversubscription on circuit-level windows.
        """
        while True:
            await self.wait_send_credit(cells, timeout=timeout)
            async with self._send_lock:
                if self.send_window >= cells:
                    self.on_send_data_cell(cells)
                    return
                # credit was consumed by other coroutine, retry


    def on_recv_sendme(self, units: int | None = None):
        if units is None:
            units = self.increment
        self.send_window += units
        self.credit_event.set()

    # ---------------- receiving side ----------------

    def on_recv_data_cell(self, cells: int = 1):
        self.recv_window -= cells

    def should_send_sendme(self) -> bool:
        """
        Every `increment` received DATA cells -> emit one SENDME and restore recv_window by increment.
        """
        # Tor-like behavior: when deliver window drops below start - increment,
        # emit SENDME and restore recv_window by increment.
        if self.recv_window <= (self.start - self.increment):
            self.recv_window += self.increment
            return True
        return False
