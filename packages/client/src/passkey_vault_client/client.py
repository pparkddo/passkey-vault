"""Requester SDK.

    from passkey_vault_client import Client

    request = Client().request("github", "gh auth login --with-token")
    print("Approve at", request.approve_url)
    secret = request.wait()          # bytes; raises RequestDenied / RequestExpired / RequestTimeout

Each request generates a fresh RSA key pair in memory. The private key never leaves the
ApprovalRequest object and is dropped after the first successful decryption.
"""

from __future__ import annotations

import ipaddress
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .protocol import b64url_decode, b64url_encode, oaep_label

DEFAULT_URL = "http://127.0.0.1:8741"
MAX_WAIT = 30  # the server's long-poll limit, in seconds

Status = Literal["pending", "approved", "denied", "expired"]


class PkvError(Exception):
    """Base class for every error raised by this package."""


class ServerError(PkvError):
    """The server rejected a call. `code` is the stable error code from docs/interface.md."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(f"{code}: {message} (HTTP {status})")
        self.status, self.code, self.message = status, code, message


class RequestDenied(PkvError):
    """The approver denied the request."""


class RequestExpired(PkvError):
    """The request expired before it was approved and collected."""


class RequestTimeout(PkvError):
    """wait() gave up before the request was decided."""


@dataclass(frozen=True)
class PollResult:
    """One answer from the server. `ciphertext` is set only when status is "approved"."""

    status: Status
    ciphertext: bytes | None = None


def _is_loopback(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class Client:
    """Talks to the requester door of a passkey-vault server."""

    def __init__(self, base_url: str = DEFAULT_URL, http_timeout: float = 10) -> None:
        self.base_url = base_url.rstrip("/")
        self.http_timeout = http_timeout
        # Never send loopback traffic through an HTTP(S)_PROXY from the environment.
        handlers = [urllib.request.ProxyHandler({})] if _is_loopback(self.base_url) else []
        self._opener = urllib.request.build_opener(*handlers)

    def _call(
        self, method: str, path: str, body: dict[str, Any] | None = None, timeout: float | None = None
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            self.base_url + path, data=data, method=method, headers={"Content-Type": "application/json"} if data else {}
        )
        try:
            with self._opener.open(req, timeout=timeout or self.http_timeout) as r:
                result: dict[str, Any] = json.loads(r.read())
                return result
        except urllib.error.HTTPError as e:
            with e:
                try:
                    err = json.loads(e.read() or b"{}")
                except ValueError:
                    err = {}
            raise ServerError(e.code, err.get("error", "http_error"), err.get("message", str(e.reason))) from None
        except urllib.error.URLError as e:
            raise PkvError(f"cannot reach the passkey-vault server at {self.base_url}: {e.reason}") from None

    def request(self, secret: str, command: str, key_bits: int = 3072) -> ApprovalRequest:
        """Ask for `secret` to be used for exactly `command` (shown verbatim to the approver)."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)
        pubkey_der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        body = self._call(
            "POST", "/requests", {"secret": secret, "command": command, "pubkey": b64url_encode(pubkey_der)}
        )
        return ApprovalRequest(
            self, body["id"], body["approve_url"], body["expires_at"], secret, command, pubkey_der, key
        )


class ApprovalRequest:
    """A pending request. Create it with Client.request(); the one-time key stays inside."""

    def __init__(
        self,
        client: Client,
        request_id: str,
        approve_url: str,
        expires_at: str,
        secret: str,
        command: str,
        pubkey_der: bytes,
        private_key: rsa.RSAPrivateKey,
    ) -> None:
        self.client = client
        self.id = request_id
        self.approve_url = approve_url
        self.expires_at = expires_at
        self.secret = secret
        self.command = command
        self.pubkey_der = pubkey_der
        self._key: rsa.RSAPrivateKey | None = private_key

    def __repr__(self) -> str:
        return f"ApprovalRequest(id={self.id!r}, secret={self.secret!r}, command={self.command!r})"

    def poll(self, wait: int = MAX_WAIT) -> PollResult:
        """One long poll of up to `wait` seconds."""
        wait = max(0, min(wait, MAX_WAIT))
        body = self.client._call("GET", f"/requests/{self.id}?wait={wait}", timeout=wait + 10)
        ciphertext = b64url_decode(body["ciphertext"]) if body["status"] == "approved" else None
        return PollResult(body["status"], ciphertext)

    def wait(self, timeout: float = 330) -> bytes:
        """Block until the request is decided; return the secret as bytes."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RequestTimeout(f"no decision within {timeout:.0f}s")
            result = self.poll(int(min(MAX_WAIT, max(1, remaining))))
            if result.status == "approved":
                assert result.ciphertext is not None
                return self.decrypt(result.ciphertext)
            if result.status == "denied":
                raise RequestDenied("the approver denied the request")
            if result.status == "expired":
                raise RequestExpired("the request expired")

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self._key is None:
            raise PkvError("this request's one-time key was already used")
        label = oaep_label(self.id, self.command, self.pubkey_der)
        oaep = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=label)
        plaintext = self._key.decrypt(ciphertext, oaep)
        self._key = None  # one-time key: drop it after a successful decryption
        return plaintext
