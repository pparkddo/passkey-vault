"""Shared test helpers: HTTP, protocol crypto building blocks, ports, polling."""

from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from passkey_vault.formats import HKDF_INFO, HKDF_SALT


def http_json(method: str, url: str, body: dict | None = None, timeout: float = 10,
              headers: dict | None = None) -> tuple[int, dict]:
    """JSON request -> (status, JSON body); HTTP errors are returned, not raised."""
    data = None if body is None else json.dumps(body).encode()
    hdrs = {**({"Content-Type": "application/json"} if data else {}), **(headers or {})}
    req = urllib.request.Request(url, data=data, method=method, headers=hdrs)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        with e:
            return e.code, json.loads(e.read() or b"{}")


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
