"""Byte-level rules: OAEP label, WebAuthn challenges, AAD, input validation.

Mirrors web/js/formats.js. Both are checked against test-vectors/.
Normative definitions: docs/interface.md section 2 and docs/design.md section 3.1.
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
import unicodedata

LABEL_TAG = b"passkey-vault/oaep-label/v1"
APPROVE_TAG = b"passkey-vault/approve/v1"
OP_TAG = b"passkey-vault/op/v1"
ITEM_TAG = b"passkey-vault/item/v1"
WRAP_TAG = b"passkey-vault/wrap/v1"
PRF_SALT = hashlib.sha256(b"passkey-vault/prf-salt/v1").digest()
HKDF_SALT = b"passkey-vault/hkdf-salt/v1"
HKDF_INFO = b"passkey-vault/wrap-key/v1"

SECRET_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
MAX_COMMAND_BYTES = 4096
MAX_META_CHARS = 200
MIN_RSA_BITS = 2048
MAX_RSA_BITS = 4096

# Characters that can disguise what the approver sees, or that cannot be encoded: controls (Cc),
# format characters such as bidi marks and zero-width characters (Cf), lone surrogates (Cs), and
# line/paragraph separators (Zl, Zp).
FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


def _to_bytes(x: str | bytes) -> bytes:
    return x.encode("utf-8") if isinstance(x, str) else bytes(x)


def lp(x: str | bytes) -> bytes:
    """Length-prefixed encoding: u32be(len) || bytes."""
    b = _to_bytes(x)
    return struct.pack(">I", len(b)) + b


def concat(*fields: str | bytes) -> bytes:
    return b"".join(lp(f) for f in fields)


def oaep_label(req_id: str, command: str, pubkey_der: bytes) -> bytes:
    return concat(LABEL_TAG, req_id, command, pubkey_der)


def approve_challenge(req_id: str, secret: str, command: str, pubkey_der: bytes) -> bytes:
    return hashlib.sha256(concat(APPROVE_TAG, req_id, secret, command, pubkey_der)).digest()


def op_challenge(op: str, nonce: bytes, *fields: str | bytes) -> bytes:
    return hashlib.sha256(concat(OP_TAG, op, nonce, *fields)).digest()


def item_aad(name: str, site: str, account: str) -> bytes:
    return concat(ITEM_TAG, name, site, account)


def wrap_aad(credential_id: bytes) -> bytes:
    return concat(WRAP_TAG, credential_id)


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def b64url_decode(s: str) -> bytes:
    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def has_forbidden_chars(s: str) -> bool:
    return any(unicodedata.category(ch) in FORBIDDEN_CATEGORIES for ch in s)


def validate_command(command: object) -> str | None:
    """Return a reason string if invalid, otherwise None."""
    if not isinstance(command, str):
        return "command must be a string"
    if has_forbidden_chars(command):
        return "command must not contain control, format (bidi, zero-width) or separator characters"
    n = len(command.encode("utf-8"))
    if n < 1 or n > MAX_COMMAND_BYTES:
        return f"command must be 1-{MAX_COMMAND_BYTES} UTF-8 bytes"
    return None


def validate_meta(value: object, field: str) -> str | None:
    if not isinstance(value, str):
        return f"{field} must be a string"
    if len(value) > MAX_META_CHARS:
        return f"{field} must be at most {MAX_META_CHARS} characters"
    if has_forbidden_chars(value):
        return f"{field} must not contain control, format or separator characters"
    return None
