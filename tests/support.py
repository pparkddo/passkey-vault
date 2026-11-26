"""Shared test helpers: protocol crypto building blocks, ports, polling."""

from __future__ import annotations

import socket
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402

from passkey_vault.formats import HKDF_INFO, HKDF_SALT  # noqa: E402


def oaep(label: bytes) -> padding.OAEP:
    """RSA-OAEP as the protocol uses it: SHA-256, MGF1-SHA-256, with a label."""
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)


def spki_der(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def wrap_key(prf_output: bytes) -> bytes:
    """PRF output -> AES-256 wrap key, as the approval page derives it."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=HKDF_INFO).derive(prf_output)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_url(url: str, timeout: float = 60) -> bytes:
    """Poll until url answers 200; return the body. Raises TimeoutError."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return r.read()
        except OSError:
            pass
        time.sleep(0.2)
    raise TimeoutError(f"{url} did not answer within {timeout}s")
