import logging
import os
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Set


logger = logging.getLogger(__name__)


class AllocationError(RuntimeError):
    """Raised when a circuit ID cannot be allocated after many attempts."""

    def __init__(self, channel_id: str, attempts: int):
        super().__init__(f"Failed to allocate circid on {channel_id} after {attempts} attempts")
        self.channel_id = channel_id
        self.attempts = attempts


class CircuitState(str, Enum):
    OPENING = "OPENING"
    OPEN = "OPEN"
    EXTENDING = "EXTENDING"
    DESTROYED = "DESTROYED"


@dataclass
class Channel:
    channel_id: str
    link_protocol_version: int
    circid_len_bytes: int
    initiator_is_me: bool
    used_circids: Set[int] = field(default_factory=set)
    recv_map: Dict[int, "CircuitRef"] = field(default_factory=dict)

    def update_version(self, version: int):
        self.link_protocol_version = version
        self.circid_len_bytes = 4 if version >= 4 else 2


@dataclass
class CircuitRef:
    circuit_id: int
    prev_channel: Optional[Channel] = None
    prev_circid: Optional[int] = None
    next_channel: Optional[Channel] = None
    next_circid: Optional[int] = None
    state: CircuitState = CircuitState.OPENING
    internal_id: Optional[int] = None

    def bind_prev(self, channel: Channel, circid: int):
        self.prev_channel = channel
        self.prev_circid = circid
        self.circuit_id = circid
        channel.recv_map[circid] = self
        channel.used_circids.add(circid)
        logger.info(
            "[circ-map] bind prev circuit_id=%s channel=%s circid=%s", self.circuit_id, channel.channel_id, circid
        )

    def bind_next(self, channel: Channel, circid: int):
        self.next_channel = channel
        self.next_circid = circid
        channel.recv_map[circid] = self
        channel.used_circids.add(circid)
        logger.info(
            "[circ-map] bind next circuit_id=%s channel=%s circid=%s", self.circuit_id, channel.channel_id, circid
        )


def _half_space_bounds(circid_len_bytes: int, msb: int) -> range:
    bits = circid_len_bytes * 8
    if circid_len_bytes == 2:
        half = 1 << 15
    else:
        half = 1 << 31
    if msb:
        start = half
        stop = 1 << bits
    else:
        start = 1
        stop = half
    return range(start, stop)


def allocate_circid(channel: Channel, max_attempts: int = 64) -> int:
    version = channel.link_protocol_version
    circ_len = channel.circid_len_bytes
    if version < 3:
        raise AllocationError(channel.channel_id, 0)

    if version >= 4:
        msb_required = 1 if channel.initiator_is_me else 0
    else:
        # Simple rule for v3-: default to msb based on initiator flag for now
        msb_required = 1 if channel.initiator_is_me else 0

    allowed_range = _half_space_bounds(circ_len, msb_required)
    attempts = 0
    for _ in range(max_attempts):
        attempts += 1
        candidate = random.randrange(allowed_range.start, allowed_range.stop)
        if candidate == 0 or candidate in channel.used_circids:
            continue
        channel.used_circids.add(candidate)
        logger.info(
            "[circ-alloc] chan=%s ver=%s initiator=%s msb=%s circid=%s",
            channel.channel_id,
            version,
            channel.initiator_is_me,
            msb_required,
            candidate,
        )
        return candidate

    raise AllocationError(channel.channel_id, attempts)


def validate_incoming_create_circid(channel: Channel, circid: int, remote_initiator: bool):
    version = channel.link_protocol_version
    if version < 3:
        raise ValueError("Unsupported link protocol version for circid validation")

    if version >= 4:
        expected_msb = 1 if remote_initiator else 0
        msb = (circid >> ((channel.circid_len_bytes * 8) - 1)) & 1
        if msb != expected_msb:
            logger.error(
                "[circ-validate] invalid circid msb chan=%s expected=%s got=%s circid=%s",
                channel.channel_id,
                expected_msb,
                msb,
                circid,
            )
            raise ValueError(f"Invalid circid MSB: expected {expected_msb}, got {msb}")
    else:
        expected_msb = 1 if remote_initiator else 0
        msb = (circid >> ((channel.circid_len_bytes * 8) - 1)) & 1
        if msb != expected_msb:
            raise ValueError("Invalid circid for v3- link")