"""Approver door: static approval page + approver API (internal; docs/openapi/approver.yaml).

Assume anyone who can reach this door can call it. Therefore every call that changes the vault
requires a signature by a registered passkey (with user verification) over a challenge that binds a
single-use nonce and the content of the operation.

Audit: approvals and denials are written before they take effect (in the request queue); vault
changes are recorded right after they are saved.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import ApiError
from .formats import approve_challenge, b64url_decode, b64url_encode, op_challenge, validate_meta
from .http_common import BaseHandler, require_request_id, require_secret_name
from .requests_queue import Request
from .vault import Signer
from .webauthn_check import verify_assertion, verify_registration

NONCE_OPS = {"setup", "add-credential", "put-item", "delete-item", "delete-credential"}
MIN_ITEM_CT, MAX_ITEM_CT = 17, 1024 + 16  # at least 1 byte of secret plus the 16-byte GCM tag
MAX_LABEL = 64
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
        raise ApiError(400, "bad_request", f"{field} must be base64url") from None


def _passkey_name(value: Any) -> str:
    problem = validate_meta(value, "name")
    if problem or not value.strip() or len(value) > MAX_LABEL:
        raise ApiError(400, "bad_request", problem or f"name must be 1-{MAX_LABEL} characters")
    return value


class ApproverHandler(BaseHandler):
    def check_request(self) -> None:
        # CSRF defence in depth. The passkey signature is the real gate for state changes.
        if self.command == "POST" and self.headers.get("Origin") != self.app.config.origin:
            raise ApiError(403, "bad_origin", "origin not allowed")

    # ---------- helpers ----------
    def _consume_nonce(self, body: dict[str, Any], op: str) -> bytes:
        nonce = _b64(body.get("nonce"), "nonce")
        if not self.app.nonces.consume(nonce, op):
            raise ApiError(400, "invalid_nonce", "nonce is unknown or expired; start again")
        return nonce

    def _assert(self, doc: dict[str, Any], body: dict[str, Any], challenge: bytes,
                allowed: set[str] | None = None) -> tuple[dict[str, Any], Signer]:
        cfg = self.app.config
        return verify_assertion(doc, body.get("assertion"), challenge, cfg.rp_id, cfg.origin, allowed)

    def _register(self, body: dict[str, Any], nonce: bytes, name: str) -> dict[str, Any]:
        cfg = self.app.config
        return verify_registration(body.get("registration"), op_challenge("register", nonce, name),
                                   cfg.rp_id, cfg.origin, name, body.get("wrapped_master_key"))

    def _request(self, req_id: str) -> Request:
        return self.app.queue.get(require_request_id(req_id))

    # ---------- static ----------
    def route_static(self) -> None:
        entry = self.app.static.get(urlsplit(self.path).path)
        if entry is None:
            raise ApiError(404, "not_found", "not found")
        self.send_bytes(200, *entry)

    # ---------- reads ----------
    def route_state(self) -> None:
        doc = self.app.vault.snapshot()
        self.send_json(200, {
            "initialized": bool(doc),
            "rp_id": self.app.config.rp_id,
            "credentials": [{k: c[k] for k in ("id", "name", "created_at", "wrapped_master_key")}
                            for c in doc.get("credentials", [])],
            "items": [{"name": n, "site": it["site"], "account": it["account"], "updated_at": it["updated_at"]}
                      for n, it in sorted(doc.get("items", {}).items())],
            "pending": [{k: v[k] for k in ("id", "secret", "command", "expires_at", "expires_in")}
                        for v in self.app.queue.pending_views()],
        })

    def route_nonce(self) -> None:
        op = self.read_object().get("op")
        if op not in NONCE_OPS:
            raise ApiError(400, "bad_request", "unknown op")
        if op == "setup":
            self.app.vault.require_uninitialized()
        else:
            self.app.vault.require_initialized()
        self.send_json(200, {"nonce": b64url_encode(self.app.nonces.issue(op))})

    def route_get_request(self, req_id: str) -> None:
        req = self._request(req_id)
        view = self.app.queue.view(req)
        item = self.app.vault.item(req.secret)
        view["item"] = None if item is None else {
            "name": req.secret, "site": item["site"], "account": item["account"], "iv": item["iv"], "ct": item["ct"],
        }
        self.send_json(200, view)

    # ---------- approve / deny ----------
    def route_approve(self, req_id: str) -> None:
        body = self.read_object()
        req = self._request(req_id)
        if req.status != "pending":  # cheap early exit before verifying a signature
            raise ApiError(409, "not_pending", f"request is already {req.visible_status}")
        ciphertext = _b64(body.get("ciphertext"), "ciphertext")
        if len(ciphertext) != req.key_bytes:
            raise ApiError(400, "bad_request", "ciphertext length does not match the requester key")
        doc = self.app.vault.require_initialized()
        audit, signer = self._assert(doc, body, approve_challenge(req.id, req.secret, req.command, req.pubkey_der))
        self.app.vault.record_signature(signer)
        self.app.queue.approve(req.id, ciphertext, audit)
        self.send_json(200, {"status": "approved"})

    def route_deny(self, req_id: str) -> None:
        # Denying needs no signature: the worst outcome is that a request is not used (see design.md).
        self.read_object()
        self.app.queue.deny(require_request_id(req_id))
        self.send_json(200, {"status": "denied"})

    # ---------- first-time setup ----------
    def route_setup(self) -> None:
        body = self.read_object()
        vault = self.app.vault
        vault.require_uninitialized()
        nonce = self._consume_nonce(body, "setup")
        if not vault.check_setup_code(body.get("setup_code")):
            self.app.audit.record("setup_rejected", reason="bad_setup_code")
            raise ApiError(403, "bad_setup_code", "wrong setup code")
        name = _passkey_name(body.get("name"))
        cred = self._register(body, nonce, name)
        vault.initialize(cred)
        self.app.audit.record("vault_initialized", credential_id=cred["id"], credential_name=name, aaguid=cred["aaguid"])
        self.send_json(201, {"status": "initialized", "credential_id": cred["id"]})

    # ---------- items ----------
    def route_put_item(self) -> None:
        body = self.read_object()
        name = require_secret_name(body.get("name"), "name")
        for field in ("site", "account"):
            problem = validate_meta(body.get(field), field)
            if problem:
                raise ApiError(400, "bad_request", problem)
        iv, ct = _b64(body.get("iv"), "iv"), _b64(body.get("ct"), "ct")
        if len(iv) != 12 or not MIN_ITEM_CT <= len(ct) <= MAX_ITEM_CT:
            raise ApiError(400, "bad_request", f"iv must be 12 bytes and ct {MIN_ITEM_CT}-{MAX_ITEM_CT} bytes")
        doc = self.app.vault.require_initialized()
        nonce = self._consume_nonce(body, "put-item")
        site, account = body["site"], body["account"]
        audit, signer = self._assert(doc, body, op_challenge("put-item", nonce, name, site, account))
        self.app.vault.put_item(name, {"site": site, "account": account, "iv": body["iv"], "ct": body["ct"]}, signer)
        self.app.audit.record("item_put", name=name, site=site, account=account, **audit)
        self.send_json(200, {"status": "ok"})

    def route_delete_item(self, name: str) -> None:
        body = self.read_object()
        doc = self.app.vault.require_initialized()
        if not isinstance(name, str) or name not in doc["items"]:
            raise ApiError(404, "unknown_secret", "no such item")
        nonce = self._consume_nonce(body, "delete-item")
        audit, signer = self._assert(doc, body, op_challenge("delete-item", nonce, name))
        self.app.vault.delete_item(name, signer)
        self.app.audit.record("item_deleted", name=name, **audit)
        self.send_json(200, {"status": "ok"})

    # ---------- passkeys ----------
    def route_add_credential(self) -> None:
        body = self.read_object()
        name = _passkey_name(body.get("name"))
        doc = self.app.vault.require_initialized()
        nonce = self._consume_nonce(body, "add-credential")
        new = self._register(body, nonce, name)
        existing = {c["id"] for c in doc["credentials"]}
        audit, signer = self._assert(doc, body, op_challenge("add-credential", nonce, b64url_decode(new["id"]), name),
                                     existing)
        self.app.vault.add_credential(new, signer)
        self.app.audit.record("credential_added", new_credential_id=new["id"], new_credential_name=name,
                              aaguid=new["aaguid"], **audit)
        self.send_json(201, {"status": "ok", "credential_id": new["id"]})

    def route_delete_credential(self, cred_id: str) -> None:
        body = self.read_object()
        doc = self.app.vault.require_initialized()
        if not any(c["id"] == cred_id for c in doc["credentials"]):
            raise ApiError(404, "unknown_credential", "no such passkey")
        nonce = self._consume_nonce(body, "delete-credential")
        audit, signer = self._assert(doc, body, op_challenge("delete-credential", nonce, _b64(cred_id, "id")))
        self.app.vault.delete_credential(cred_id, signer)
        self.app.audit.record("credential_deleted", deleted_credential_id=cred_id, **audit)
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
