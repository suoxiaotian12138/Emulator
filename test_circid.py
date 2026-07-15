import asyncio
import sys
import types

sys.modules.setdefault("requests", types.SimpleNamespace(post=lambda *a, **k: None))

from network_src.TorCore.circid_alloc import (
    AllocationError,
    Channel,
    CircuitRef,
    allocate_circid,
    validate_incoming_create_circid,
)
def test_v4_allocation_half_space():
    chan_initiator = Channel("c1", link_protocol_version=4, circid_len_bytes=4, initiator_is_me=True)
    cid_initiator = allocate_circid(chan_initiator)
    assert (cid_initiator >> 31) == 1

    chan_responder = Channel("c2", link_protocol_version=4, circid_len_bytes=4, initiator_is_me=False)
    cid_responder = allocate_circid(chan_responder)
    assert (cid_responder >> 31) == 0


def test_no_reuse_same_channel():
    chan = Channel("c3", link_protocol_version=4, circid_len_bytes=4, initiator_is_me=True)
    cid1 = allocate_circid(chan)
    cid2 = allocate_circid(chan)
    assert cid1 != cid2
    assert cid1 in chan.used_circids and cid2 in chan.used_circids


def test_extend_creates_new_circid_and_forwarding_uses_mapping():
    chan_up = Channel("up", link_protocol_version=4, circid_len_bytes=4, initiator_is_me=False)
    chan_down = Channel("down", link_protocol_version=4, circid_len_bytes=4, initiator_is_me=True)

    circuit = CircuitRef(1)
    cid_up = allocate_circid(chan_up)
    circuit.bind_prev(chan_up, cid_up)

    cid_down = allocate_circid(chan_down)
    circuit.bind_next(chan_down, cid_down)

    class RelayCell:
        def __init__(self, circid):
            self.circuit_id = circid
            self.stream_id = 0
            self._inner = None

    cell = RelayCell(cid_up)
    sending_to_upstream = False
    if sending_to_upstream and circuit.prev_circid is not None:
        cell.circuit_id = circuit.prev_circid
    elif (not sending_to_upstream) and circuit.next_circid is not None:
        cell.circuit_id = circuit.next_circid
    assert cell.circuit_id == cid_down


def test_validate_incoming_create_wrong_msb():
    chan = Channel("c4", link_protocol_version=4, circid_len_bytes=4, initiator_is_me=False)
    wrong_circid = 0x7FFFFFFF  # MSB=0
    try:
        validate_incoming_create_circid(chan, wrong_circid, remote_initiator=True)
    except ValueError:
        return
    raise AssertionError("Expected ValueError for invalid circid")

