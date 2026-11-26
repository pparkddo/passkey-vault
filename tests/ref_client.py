"""Minimal reference requester, for tests and as an example. Real requesters live elsewhere.

    uv run python tests/ref_client.py github "printenv PASSKEY_VAULT_SECRET | wc -c"         # decrypt only
    uv run python tests/ref_client.py github "printenv PASSKEY_VAULT_SECRET | wc -c" --run   # run once

Flow: one-time RSA key (memory only) -> POST /requests -> print approve_url -> long-poll
-> decrypt with the OAEP label -> optionally run the command once. Uses only docs/interface.md.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "server"))
from passkey_vault.formats import b64url_decode, b64url_encode, oaep_label  # noqa: E402

DEFAULT_BASE = "http://127.0.0.1:8741"


class RequesterError(Exception):
    pass


def _call(method: str, url: str, body: dict | None = None, timeout: float = 40,
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


class OneShotRequest:
    """One request. The private key exists only in this object's memory."""

    def __init__(self, base: str, secret: str, command: str, bits: int = 3072) -> None:
        self.base, self.secret, self.command = base.rstrip("/"), secret, command
        self._key: rsa.RSAPrivateKey | None = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        self.pubkey_der = self._key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.id: str | None = None
        self.approve_url: str | None = None

    def create(self) -> dict:
        status, body = _call("POST", f"{self.base}/requests",
                             {"secret": self.secret, "command": self.command, "pubkey": b64url_encode(self.pubkey_der)})
        if status != 201:
            raise RequesterError(f"request failed {status}: {body}")
        self.id, self.approve_url = body["id"], body["approve_url"]
        return body

    def poll(self, wait: int = 30) -> dict:
        status, body = _call("GET", f"{self.base}/requests/{self.id}?wait={wait}", timeout=wait + 10)
        if status != 200:
            raise RequesterError(f"poll failed {status}: {body}")
        return body

    def wait_result(self, total_timeout: float = 330) -> bytes:
        """Plaintext bytes once approved; raises on denied/expired/timeout."""
        deadline = time.monotonic() + total_timeout
        while time.monotonic() < deadline:
            body = self.poll()
            if body["status"] == "approved":
                return self.decrypt(b64url_decode(body["ciphertext"]))
            if body["status"] in ("denied", "expired"):
                raise RequesterError(f"request ended as {body['status']}")
        raise RequesterError("timed out")

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._key is None:
            raise RequesterError("the one-time key was already used")
        label = oaep_label(self.id, self.command, self.pubkey_der)
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)
        plaintext = self._key.decrypt(ciphertext, oaep)
        self._key = None  # one-time: drop the private key after a successful decryption
        return plaintext


def main() -> int:
    ap = argparse.ArgumentParser(description="passkey-vault reference requester (for tests)")
    ap.add_argument("secret")
    ap.add_argument("command", help="command to run, shown verbatim to the approver; secret is in $PASSKEY_VAULT_SECRET")
    ap.add_argument("--base", default=DEFAULT_BASE)
    ap.add_argument("--run", action="store_true", help="run the command once with /bin/sh -c after approval")
    a = ap.parse_args()

    req = OneShotRequest(a.base, a.secret, a.command)
    info = req.create()
    print(f"approve: {info['approve_url']}  (expires {info['expires_at']})", flush=True)
    try:
        secret = req.wait_result()
    except RequesterError as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1
    if not a.run:
        print(f"decrypted {len(secret)} bytes (value not printed)")
        return 0
    env = {**os.environ, "PASSKEY_VAULT_SECRET": secret.decode("utf-8")}
    return subprocess.run(["/bin/sh", "-c", a.command], env=env).returncode  # exactly the approved command


if __name__ == "__main__":
    raise SystemExit(main())
