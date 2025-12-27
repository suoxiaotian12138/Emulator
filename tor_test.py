import struct
import sys
import types

import pytest


def _stub_module(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod


# Provide minimal stubs for optional torpy dependency so tests can run offline.
_stub_module("torpy")
utils = _stub_module("torpy.utils")
utils.to_hex = lambda b: b.hex()
utils.fp_to_str = lambda fp: fp.hex() if isinstance(fp, (bytes, bytearray)) else str(fp)

cells = _stub_module("torpy.cells")
_stub_nums = {
    "CellVersions": 7,
    "CellCreateFast": 5,
    "CellDestroy": 4,
    "CellCreatedFast": 6,
    "CellRelayEnd": 3,
    "CellRelayData": 2,
    "CellRelaySendMe": 5,
    "CellRelayConnected": 4,
    "CellRelayExtended2": 15,
    "CellRelayTruncated": 9,
    "StreamReason": 0,
}
for _name, _num in _stub_nums.items():
    setattr(cells, _name, type(_name, (), {"NUM": _num}))

parsers = _stub_module("torpy.parsers")
parsers.RouterDescriptorParser = type("RouterDescriptorParser", (), {})

stream = _stub_module("torpy.stream")
stream.TorWindow = type("TorWindow", (), {"__init__": lambda self, *a, **kw: None})

crypto_common = _stub_module("torpy.crypto_common")
crypto_common.b64decode = lambda data: data

msgpack_mod = _stub_module("msgpack")
msgpack_mod.dumps = lambda *a, **kw: b""
msgpack_mod.loads = lambda *a, **kw: None
msgpack_mod.packb = msgpack_mod.dumps
msgpack_mod.unpackb = msgpack_mod.loads

geoip2_mod = _stub_module("geoip2")
geoip2_mod.database = types.SimpleNamespace(Reader=lambda *a, **kw: None)
_stub_module("geoip2.database")

aiohttp_mod = _stub_module("aiohttp")
aiohttp_mod.ClientSession = type("ClientSession", (), {"__init__": lambda self, *a, **kw: None})


from examples.Tor_simplified.Tor_Cell import CellAuthenticate, TorCell, CellPadding
from examples.Tor_simplified.Tor_Socket import Tor_Socket


def _extract_payload(raw: bytes) -> bytes:
    """Helper to strip a v4 fixed-length header (4B circ_id + 1B cmd)."""
    return raw[5:]


def test_authenticate_serialize_roundtrip():
    cell = CellAuthenticate(auth_type=0x0003, auth_data=b"1234")
    raw = cell.serialize(proto_version=4)

    assert len(raw) == 514

    payload = _extract_payload(raw)
    assert payload[:4] == struct.pack("!HH", 0x0003, 4)

    parsed = TorCell.deserialize(CellAuthenticate, 0, payload, proto_version=4)
    assert isinstance(parsed, CellAuthenticate)
    assert parsed.auth_type == 0x0003
    assert parsed.auth_data == b"1234"


@pytest.mark.parametrize("data", [b"", b"A", b"B" * 16, b"C" * 200, b"D" * 505])
def test_authenticate_length_boundaries(data):
    cell = CellAuthenticate(auth_type=0x0003, auth_data=data)
    raw = cell.serialize(proto_version=4)
    assert len(raw) == 514
    payload = _extract_payload(raw)
    assert payload[:4] == struct.pack("!HH", 0x0003, len(data))

    parsed = TorCell.deserialize(CellAuthenticate, 0, payload, proto_version=4)
    assert parsed.auth_data == data


def test_authenticate_too_long():
    too_long = b"Z" * (CellAuthenticate.MAX_AUTH_LEN + 1)
    with pytest.raises(ValueError):
        CellAuthenticate(auth_type=0x0003, auth_data=too_long).serialize(proto_version=4)


def test_fixed_length_alignment_with_buffer():
    async def _run():
        sock = Tor_Socket(source_ip="127.0.0.1", node_id=None)
        sock.protocol.version = 4

        cell1 = CellAuthenticate(auth_type=0x0003, auth_data=b"abcd")
        cell2 = CellPadding()

        combined = cell1.serialize(proto_version=4) + cell2.serialize(proto_version=4)

        await sock.buffer.add(combined)

        parsed1 = await sock.recv_and_parse_cell()
        parsed2 = await sock.recv_and_parse_cell()

        assert isinstance(parsed1, CellAuthenticate)
        assert parsed1.auth_data == b"abcd"
        assert isinstance(parsed2, CellPadding)

    import asyncio

    asyncio.run(_run())