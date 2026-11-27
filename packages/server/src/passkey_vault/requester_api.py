"""Requester door: the requester API. Public contract: docs/interface.md, docs/openapi/requester.yaml."""

from __future__ import annotations

import re
from typing import ClassVar

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key

from .config import MAX_WAIT_SECONDS, host_name
from .errors import ApiError
from .formats import MAX_RSA_BITS, MIN_RSA_BITS, b64url_decode, validate_command
from .http_common import BaseHandler, Route, require_request_id, require_secret_name

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


def parse_requester_pubkey(value: object) -> tuple[bytes, int]:
    """SPKI DER (base64url) -> (DER bytes, modulus size in bytes). Only RSA, 2048-4096 bits, e = 65537."""
    if not isinstance(value, str):
        raise ApiError(400, "invalid_pubkey", "pubkey must be a base64url string")
    try:
        der = b64url_decode(value)
        key = load_der_public_key(der)
    except (ValueError, TypeError):
        raise ApiError(400, "invalid_pubkey", "pubkey is not a SPKI DER public key") from None
    if not isinstance(key, rsa.RSAPublicKey):
        raise ApiError(400, "invalid_pubkey", "pubkey is not an RSA key")
    if key.key_size < MIN_RSA_BITS:
        raise ApiError(400, "key_too_small", f"RSA key must be at least {MIN_RSA_BITS} bits")
    if key.key_size > MAX_RSA_BITS or key.key_size % 8:
        raise ApiError(400, "invalid_pubkey", f"RSA key must be at most {MAX_RSA_BITS} bits and a multiple of 8")
    if key.public_numbers().e != 65537:
        raise ApiError(400, "invalid_pubkey", "RSA public exponent must be 65537")
    return der, key.key_size // 8


class RequesterHandler(BaseHandler):
    def check_request(self) -> None:
        # Blocks DNS rebinding: a browser tricked into calling this door sends the attacker's host name.
        if host_name(self.headers.get("Host")) not in LOOPBACK_HOSTS | set(self.app.config.requester_hosts):
            raise ApiError(421, "bad_host", "this host name is not accepted by the requester door")

    def route_create_request(self) -> None:
        body = self.read_object()
        secret = require_secret_name(body.get("secret"))
        command = body.get("command")
        problem = validate_command(command)
        if problem:
            raise ApiError(400, "invalid_command", problem)
        assert isinstance(command, str)  # validate_command accepted it
        pubkey_der, key_bytes = parse_requester_pubkey(body.get("pubkey"))
        doc = self.app.vault.require_initialized()
        if secret not in doc["items"]:
            raise ApiError(404, "unknown_secret", "no vault item with that name")
        req = self.app.queue.create(secret, command, pubkey_der, key_bytes)
        self.send_json(
            201,
            {
                "id": req.id,
                "approve_url": f"{self.app.config.origin}/approve?id={req.id}",
                "expires_at": req.expires_at,
            },
        )

    def route_collect(self, req_id: str) -> None:
        raw = self.query().get("wait", ["0"])
        if len(raw) != 1 or not re.fullmatch(r"\d{1,2}", raw[0]) or int(raw[0]) > MAX_WAIT_SECONDS:
            raise ApiError(400, "bad_request", f"wait must be an integer from 0 to {MAX_WAIT_SECONDS}")
        with self.app.queue.deliver(require_request_id(req_id), float(raw[0])) as result:
            self.send_json(200, result)
            self.wfile.flush()

    routes: ClassVar[list[Route]] = [
        ("POST", re.compile(r"/requests"), route_create_request),
        ("GET", re.compile(r"/requests/([^/]+)"), route_collect),
    ]
