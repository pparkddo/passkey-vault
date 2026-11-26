"""Requester door: the requester API. Public contract: docs/interface.md, docs/openapi/requester.yaml."""

from __future__ import annotations

import re

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .config import MAX_WAIT_SECONDS
from .formats import MAX_RSA_BITS, MIN_RSA_BITS, REQUEST_ID_RE, SECRET_NAME_RE, b64url_decode, validate_command
from .http_common import BaseHandler, HttpError


def parse_requester_pubkey(value: object) -> bytes:
    """SPKI DER (base64url) -> DER bytes. Only RSA, 2048-4096 bits, e = 65537."""
    if not isinstance(value, str):
        raise HttpError(400, "invalid_pubkey", "pubkey must be a base64url string")
    try:
        der = b64url_decode(value)
        key = load_der_public_key(der)
    except (ValueError, TypeError):
        raise HttpError(400, "invalid_pubkey", "pubkey is not a SPKI DER public key") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise HttpError(400, "invalid_pubkey", "pubkey is not an RSA key")
    if key.key_size < MIN_RSA_BITS:
        raise HttpError(400, "key_too_small", f"RSA key must be at least {MIN_RSA_BITS} bits")
    if key.key_size > MAX_RSA_BITS or key.key_size % 8:
        raise HttpError(400, "invalid_pubkey", f"RSA key must be at most {MAX_RSA_BITS} bits and a multiple of 8")
    if key.public_numbers().e != 65537:
        raise HttpError(400, "invalid_pubkey", "RSA public exponent must be 65537")
    return der


LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def host_name(header: str | None) -> str:
    """Host header -> lower-case host name without the port ("[::1]:8741" -> "::1")."""
    h = (header or "").strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else ""
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


class RequesterHandler(BaseHandler):
    def check_request(self) -> None:
        # Blocks DNS rebinding: a browser tricked into calling this door sends the attacker's host name.
        if host_name(self.headers.get("Host")) not in LOOPBACK_HOSTS | set(self.app.config.requester_hosts):
            raise HttpError(421, "bad_host", "this host name is not accepted by the requester door")

    def route_create_request(self) -> None:
        body = self.read_object()
        secret, command = body.get("secret"), body.get("command")
        if not isinstance(secret, str) or not SECRET_NAME_RE.fullmatch(secret):
            raise HttpError(400, "invalid_secret_name", "secret must match [A-Za-z0-9._-]{1,64}")
        problem = validate_command(command)
        if problem:
            raise HttpError(400, "invalid_command", problem)
        pubkey_der = parse_requester_pubkey(body.get("pubkey"))
        vault = self.app.vault
        if not vault.initialized:
            raise HttpError(409, "vault_not_initialized", "the vault has not been set up yet")
        if vault.item(secret) is None:
            raise HttpError(404, "unknown_secret", "no vault item with that name")
        req = self.app.queue.create(secret, command, pubkey_der)
        self.send_json(201, {
            "id": req.id,
            "approve_url": f"{self.app.config.origin}/approve?id={req.id}",
            "expires_at": req.public_view()["expires_at"],
        })

    def route_collect(self, req_id: str) -> None:
        raw = self.query().get("wait", ["0"])
        if len(raw) != 1 or not re.fullmatch(r"\d{1,2}", raw[0]) or int(raw[0]) > MAX_WAIT_SECONDS:
            raise HttpError(400, "bad_request", f"wait must be an integer from 0 to {MAX_WAIT_SECONDS}")
        if not REQUEST_ID_RE.fullmatch(req_id):
            raise HttpError(404, "not_found", "no such request")
        self.send_json(200, self.app.queue.collect(req_id, float(raw[0])))

    routes = [
        ("POST", re.compile(r"/requests"), route_create_request),
        ("GET", re.compile(r"/requests/([^/]+)"), route_collect),
    ]
