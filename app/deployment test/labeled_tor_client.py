"""Tor client wrapper that prefixes logs with a ratio label.

The deployment experiments need a lightweight client that behaves like the
base ``Tor_Client`` but ensures every emitted log record carries a
``ratio_label`` prefix so runs from different TorBox replacement ratios are
trivially distinguishable. No path-pattern awareness is required here; circuit
selection remains the default random behavior from ``Tor_Client``.
"""
from __future__ import annotations

from typing import Callable

from examples.Tor_simplified.Tor_Client import Tor_Client
from tools.Log.bus import EventBus
from tools.Log.writer import AsyncJsonlWriter


class LabeledTorClient(Tor_Client):
    """Tor_Client variant that injects a ratio label into all bus emissions."""

    def __init__(self, *args, ratio_label: str, writer: AsyncJsonlWriter, **kwargs):
        super().__init__(*args, **kwargs)
        self.ratio_label = ratio_label
        self._writer = writer

    def _wrap_emitter(self, emitter: Callable[[str, dict], None]) -> Callable[[str, dict], None]:
        def wrapped(kind: str, record: dict) -> None:
            tagged = {"ratio_label": self.ratio_label}
            tagged.update(record)
            emitter(kind, tagged)

        return wrapped

    def attach_labeled_bus(self, role: str = "client") -> None:
        bus = EventBus(self._wrap_emitter(self._writer.emit_nowait), node_id=self.name, role=role)
        self.event_bus = bus
        self.emit = bus.emit
        self._ev = bus.ev
        self._circuit = bus.circuit
        self._path = bus.path
        self._stream = bus.stream