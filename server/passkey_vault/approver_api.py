"""Approver door: static approval page + approver API (internal; docs/openapi/approver.yaml).

Assume any process on the host can call this door too. Therefore every call that changes the vault
requires a signature by a registered passkey (with user verification) over a challenge that binds a
single-use nonce and the content of the operation.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.serialization import load_der_public_key

from .formats import REQUEST_ID_RE, SECRET_NAME_RE, approve_challenge, b64url_decode, b64url_encode, op_challenge, validate_meta
from .http_common import BaseHandler, HttpError
from .requests_queue import Request
from .webauthn_check import verify_assertion, verify_registration

NONCE_OPS = {"setup", "add-credential", "put-item", "delete-item", "delete-credential"}
MAX_ITEM_CT = 1024 + 16
CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml", ".png": "image/png", ".woff2": "font/woff2", ".webmanifest": "application/manifest+json",
}


def load_static(web_dir: Path) -> dict[str, tuple[bytes, str]]:
    """Allow-list: load files with known extensions from web/ into memory at start-up."""
    files: dict[str, tuple[bytes, str]] = {}
    for p in sorted(web_dir.rglob("*")):
        rel_parts = p.relative_to(web_dir).parts
        if p.is_file() and p.suffix in CONTENT_TYPES and not any(part.startswith(".") for part in rel_parts):
            files["/" + "/".join(rel_parts)] = (p.read_bytes(), CONTENT_TYPES[p.suffix])
    for alias, target in (("/", "/index.html"), ("/approve", "/approve.html")):
        if target in files:
            files[alias] = files[target]
    return files


def _b64(value: Any, field: str) -> bytes:
    try:
        return b64url_decode(value)
    except ValueError:
        raise HttpError(400, "bad_request", f"{field} must be base64url") from None


def _label(value: Any, field: str = "name", max_len: int = 64) -> str:
    problem = validate_meta(value, field)
    if problem or not value.strip() or len(value) > max_len:
        raise HttpError(400, "bad_request", problem or f"{field} must be 1-{max_len} characters")
    return value


class ApproverHandler(BaseHandler):
    def check_request(self) -> None:
        # CSRF defence in depth. The passkey signature is the real gate for state changes.
        if self.command == "POST" and self.headers.get("Origin") != self.app.config.origin:
            raise HttpError(403, "bad_origin", "origin not allowed")

    # ---------- helpers ----------
    def _consume_nonce(self, body: dict[str, Any], op: str) -> bytes:
        nonce = _b64(body.get("nonce"), "nonce")
        if not self.app.nonces.consume(nonce, op):
            raise HttpError(400, "invalid_nonce", "nonce is unknown or expired; start again")
        return nonce

    def _assert(self, body: dict[str, Any], challenge: bytes, allowed: set[str] | None = None) -> dict[str, Any]:
        cfg = self.app.config
        return verify_assertion(self.app.vault, body.get("assertion"), challenge, cfg.rp_id, cfg.origin, allowed)

    def _register(self, body: dict[str, Any], nonce: bytes, name: str) -> dict[str, Any]:
        cfg = self.app.config
        return verify_registration(body.get("registration"), op_challenge("register", nonce, name),
                                   cfg.rp_id, cfg.origin, name, body.get("wrapped_master_key"))

    def _request(self, req_id: str) -> Request:
        if not REQUEST_ID_RE.fullmatch(req_id):
            raise HttpError(404, "not_found", "no such request")
        return self.app.queue.get(req_id)

    # ---------- static ----------
    def route_static(self) -> None:
        entry = self.app.static.get(urlsplit(self.path).path)
        if entry is None:
            raise HttpError(404, "not_found", "not found")
        self.send_bytes(200, *entry)

    # ---------- reads ----------
    def route_state(self) -> None:
        snap = self.app.vault.snapshot()
        self.send_json(200, {
            "initialized": bool(snap),
            "rp_id": self.app.config.rp_id,
            "credentials": [{k: c[k] for k in ("id", "name", "created_at", "wrapped_master_key")}
                            for c in snap.get("credentials", [])],
            "items": [{"name": n, "site": it["site"], "account": it["account"], "updated_at": it["updated_at"]}
                      for n, it in sorted(snap.get("items", {}).items())],
            "pending": [{k: v[k] for k in ("id", "secret", "command", "expires_at", "expires_in")}
                        for v in (r.public_view() for r in self.app.queue.pending())],
        })

    def route_nonce(self) -> None:
        op = self.read_object().get("op")
        if op not in NONCE_OPS:
            raise HttpError(400, "bad_request", "unknown op")
        initialized = self.app.vault.initialized
        if op == "setup" and initialized:
            raise HttpError(409, "already_initialized", "the vault already exists")
        if op != "setup" and not initialized:
            raise HttpError(409, "vault_not_initialized", "the vault has not been set up yet")
        self.send_json(200, {"nonce": b64url_encode(self.app.nonces.issue(op))})

    def route_get_request(self, req_id: str) -> None:
        req = self._request(req_id)
        view = req.public_view()
        item = self.app.vault.item(req.secret)
        view["item"] = None if item is None else {
            "name": req.secret, "site": item["site"], "account": item["account"], "iv": item["iv"], "ct": item["ct"],
        }
        self.send_json(200, view)

    # ---------- approve / deny ----------
    def route_approve(self, req_id: str) -> None:
        body = self.read_object()
        req = self._request(req_id)
        if req.status != "pending":
            raise HttpError(409, "not_pending", f"request is already {req.status}")
        ciphertext = _b64(body.get("ciphertext"), "ciphertext")
        if len(ciphertext) != load_der_public_key(req.pubkey_der).key_size // 8:  # type: ignore[union-attr]
            raise HttpError(400, "bad_request", "ciphertext length does not match the requester key")
        audit = self._assert(body, approve_challenge(req.id, req.secret, req.command, req.pubkey_der))
        self.app.queue.approve(req.id, ciphertext, audit)
        self.send_json(200, {"status": "approved"})

    def route_deny(self, req_id: str) -> None:
        # Denying needs no signature: the worst outcome is that a request is not used (see design.md).
        self.read_object()
        self._request(req_id)
        self.app.queue.deny(req_id)
        self.send_json(200, {"status": "denied"})

    # ---------- first-time setup ----------
    def route_setup(self) -> None:
        body = self.read_object()
        vault = self.app.vault
        if vault.initialized:
            raise HttpError(409, "already_initialized", "the vault already exists")
        nonce = self._consume_nonce(body, "setup")
        if not vault.check_setup_code(body.get("setup_code")):
            self.app.audit.write("setup_rejected", reason="bad_setup_code")
            raise HttpError(403, "bad_setup_code", "wrong setup code")
        name = _label(body.get("name"))
        cred = self._register(body, nonce, name)
        vault.initialize(cred)
        self.app.audit.write("vault_initialized", credential_id=cred["id"], credential_name=name, aaguid=cred["aaguid"])
        self.send_json(201, {"status": "initialized", "credential_id": cred["id"]})

    # ---------- items ----------
    def route_put_item(self) -> None:
        body = self.read_object()
        name = body.get("name")
        if not isinstance(name, str) or not SECRET_NAME_RE.fullmatch(name):
            raise HttpError(400, "invalid_secret_name", "name must match [A-Za-z0-9._-]{1,64}")
        for field in ("site", "account"):
            problem = validate_meta(body.get(field), field)
            if problem:
                raise HttpError(400, "bad_request", problem)
        iv, ct = _b64(body.get("iv"), "iv"), _b64(body.get("ct"), "ct")
        if len(iv) != 12 or not 17 <= len(ct) <= MAX_ITEM_CT:
            raise HttpError(400, "bad_request", "iv must be 12 bytes and ct 17-1040 bytes")
        nonce = self._consume_nonce(body, "put-item")
        site, account = body["site"], body["account"]
        audit = self._assert(body, op_challenge("put-item", nonce, name, site, account))
        self.app.vault.put_item(name, {"site": site, "account": account, "iv": body["iv"], "ct": body["ct"]})
        self.app.audit.write("item_put", name=name, site=site, account=account, **audit)
        self.send_json(200, {"status": "ok"})

    def route_delete_item(self, name: str) -> None:
        body = self.read_object()
        if not SECRET_NAME_RE.fullmatch(name) or self.app.vault.item(name) is None:
            raise HttpError(404, "unknown_secret", "no such item")
        nonce = self._consume_nonce(body, "delete-item")
        audit = self._assert(body, op_challenge("delete-item", nonce, name))
        self.app.vault.delete_item(name)
        self.app.audit.write("item_deleted", name=name, **audit)
        self.send_json(200, {"status": "ok"})

    # ---------- passkeys ----------
    def route_add_credential(self) -> None:
        body = self.read_object()
        name = _label(body.get("name"))
        nonce = self._consume_nonce(body, "add-credential")
        new = self._register(body, nonce, name)
        existing = {c["id"] for c in self.app.vault.snapshot()["credentials"]}
        audit = self._assert(body, op_challenge("add-credential", nonce, b64url_decode(new["id"]), name), existing)
        self.app.vault.add_credential(new)
        self.app.audit.write("credential_added", new_credential_id=new["id"], new_credential_name=name,
                             aaguid=new["aaguid"], **audit)
        self.send_json(201, {"status": "ok", "credential_id": new["id"]})

    def route_delete_credential(self, cred_id: str) -> None:
        body = self.read_object()
        if self.app.vault.credential(cred_id) is None:
            raise HttpError(404, "unknown_credential", "no such passkey")
        nonce = self._consume_nonce(body, "delete-credential")
        audit = self._assert(body, op_challenge("delete-credential", nonce, _b64(cred_id, "id")))
        self.app.vault.delete_credential(cred_id)
        self.app.audit.write("credential_deleted", deleted_credential_id=cred_id, **audit)
        self.send_json(200, {"status": "ok"})

    routes = [
        ("GET", re.compile(r"/api/state"), route_state),
        ("POST", re.compile(r"/api/nonce"), route_nonce),
        ("POST", re.compile(r"/api/setup"), route_setup),
        ("GET", re.compile(r"/api/requests/([^/]+)"), route_get_request),
        ("POST", re.compile(r"/api/requests/([^/]+)/approve"), route_approve),
        ("POST", re.compile(r"/api/requests/([^/]+)/deny"), route_deny),
        ("POST", re.compile(r"/api/items"), route_put_item),
        ("POST", re.compile(r"/api/items/([^/]+)/delete"), route_delete_item),
        ("POST", re.compile(r"/api/credentials"), route_add_credential),
        ("POST", re.compile(r"/api/credentials/([^/]+)/delete"), route_delete_credential),
        ("GET", re.compile(r"/(?!api/).*"), route_static),
    ]
