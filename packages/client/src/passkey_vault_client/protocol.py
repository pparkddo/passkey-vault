"""Byte-level rules a requester needs (docs/interface.md section 2), checked against test-vectors/.

Self-contained on purpose: requesters do not depend on the server package.
"""

from __future__ import annotations

import base64
import re
import struct

LABEL_TAG = b"passkey-vault/oaep-label/v1"
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def lp(x: str | bytes) -> bytes:
    """Length-prefixed encoding: u32be(len) || bytes."""
    b = x.encode("utf-8") if isinstance(x, str) else bytes(x)
    return struct.pack(">I", len(b)) + b


def oaep_label(request_id: str, command: str, pubkey_der: bytes) -> bytes:
    """The RSA-OAEP label that binds a ciphertext to one request, one command and one key."""
    return lp(LABEL_TAG) + lp(request_id) + lp(command) + lp(pubkey_der)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
