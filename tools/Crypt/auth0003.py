"""Utilities for building AUTH0003 authentication bodies.

This module implements the Ed25519-SHA256-RFC5705 authentication body
construction (AuthType = 0x0003). It is a pure function helper that
produces the 384-byte authentication body and does not perform any
network or TLS-related logic.
"""
from __future__ import annotations

import os
from typing import Iterable, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

AUTH_TYPE = b"AUTH0003"
_AUTH_TYPE_LEN = 8
_FIELD_LEN = 32
_RAND_LEN = 24
_SIGNED_PART_LEN = 320
_SIGNATURE_LEN = 64
_BODY_LEN = 384


class Auth0003ConstructionError(ValueError):
    """Raised when the authentication body cannot be constructed."""


_DEF_FIELD_NAMES: Tuple[str, ...] = (
    "cid",
    "sid",
    "cid_ed",
    "sid_ed",
    "slog",
    "clog",
    "scert",
    "tlssecrets",
)


def _validate_fields(fields: Iterable[Tuple[str, bytes]]) -> None:
    for name, value in fields:
        if len(value) != _FIELD_LEN:
            raise Auth0003ConstructionError(
                f"{name} must be {_FIELD_LEN} bytes, got {len(value)}"
            )


def build_auth0003_body(
    cid: bytes,
    sid: bytes,
    cid_ed: bytes,
    sid_ed: bytes,
    slog: bytes,
    clog: bytes,
    scert: bytes,
    tlssecrets: bytes,
    ks_link_ed_priv: Ed25519PrivateKey,
) -> bytes:
    """Build the AUTH0003 authentication body.

    The function is side-effect free aside from generating random bytes
    for the RAND field. It validates field lengths, constructs the
    signed portion (TYPE..RAND), signs it with the provided Ed25519
    private key, and returns the 384-byte body.
    """

    if len(AUTH_TYPE) != _AUTH_TYPE_LEN:
        raise Auth0003ConstructionError(
            f"AUTH_TYPE must be {_AUTH_TYPE_LEN} bytes, got {len(AUTH_TYPE)}"
        )

    input_fields = (
        ("cid", cid),
        ("sid", sid),
        ("cid_ed", cid_ed),
        ("sid_ed", sid_ed),
        ("slog", slog),
        ("clog", clog),
        ("scert", scert),
        ("tlssecrets", tlssecrets),
    )
    _validate_fields(input_fields)

    rand = os.urandom(_RAND_LEN)

    signed_part = b"".join(
        [
            AUTH_TYPE,
            cid,
            sid,
            cid_ed,
            sid_ed,
            slog,
            clog,
            scert,
            tlssecrets,
            rand,
        ]
    )

    if len(signed_part) < _SIGNED_PART_LEN:
        padding_len = _SIGNED_PART_LEN - len(signed_part)
        signed_part += b"\x00" * padding_len
    elif len(signed_part) != _SIGNED_PART_LEN:
        raise Auth0003ConstructionError(
            f"Signed part length must be {_SIGNED_PART_LEN} bytes, got {len(signed_part)}"
        )

    signature = ks_link_ed_priv.sign(signed_part)

    if len(signature) != _SIGNATURE_LEN:
        raise Auth0003ConstructionError(
            f"Signature length must be {_SIGNATURE_LEN} bytes, got {len(signature)}"
        )

    body = signed_part + signature
    if len(body) != _BODY_LEN:
        raise Auth0003ConstructionError(
            f"Authentication body length must be {_BODY_LEN} bytes, got {len(body)}"
        )

    return body


def _self_test() -> None:
    ks_link_ed_priv = Ed25519PrivateKey.generate()
    ks_link_ed_pub: Ed25519PublicKey = ks_link_ed_priv.public_key()

    random_fields = [os.urandom(_FIELD_LEN) for _ in range(len(_DEF_FIELD_NAMES))]
    body = build_auth0003_body(*random_fields, ks_link_ed_priv)

    signed_part = body[:_SIGNED_PART_LEN]
    signature = body[_SIGNED_PART_LEN:]

    ks_link_ed_pub.verify(signature, signed_part)
    assert len(body) == _BODY_LEN
    print("AUTH0003 body generated and verified successfully.")


if __name__ == "__main__":
    try:
        _self_test()
    except InvalidSignature as exc:  # pragma: no cover - sanity guard
        raise SystemExit(f"Signature verification failed: {exc}")
    except Auth0003ConstructionError as exc:  # pragma: no cover - sanity guard
        raise SystemExit(str(exc))