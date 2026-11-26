"""Request mailbox (in memory): 5-minute expiry, single delivery of the ciphertext, long polling.

Requests are intentionally not persisted: they are short-lived, and a restart simply makes the
requester ask again. Running several server processes would need a shared mailbox (not provided).
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field

from .audit import AuditLog, utc_now_iso
from .config import MAX_PENDING_REQUESTS, NONCE_TTL_SECONDS, REQUEST_TTL_SECONDS
from .formats import b64url_encode

PURGE_AFTER_SECONDS = 600  # how long finished requests are remembered (for 410 / final status)


@dataclass
class Request:
    id: str
    secret: str
    command: str
    pubkey_der: bytes
    created: float
    expires: float
    status: str = "pending"  # pending | approved | denied | expired | consumed
    ciphertext: bytes | None = field(default=None, repr=False)
    finished: float | None = None

    @property
    def pubkey_sha256(self) -> str:
        return hashlib.sha256(self.pubkey_der).hexdigest()

    def public_view(self) -> dict:
        return {
            "id": self.id, "secret": self.secret, "command": self.command, "pubkey": b64url_encode(self.pubkey_der),
            "created_at": utc_now_iso(self.created), "expires_at": utc_now_iso(self.expires), "status": self.status,
        }


class QueueError(Exception):
    def __init__(self, code: str, message: str, status: int) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class RequestQueue:
    def __init__(self, audit: AuditLog, ttl: float = REQUEST_TTL_SECONDS, clock=time.time) -> None:
        self._audit = audit
        self._ttl = ttl
        self._clock = clock
        self._items: dict[str, Request] = {}
        self._cond = threading.Condition()

    def _refresh(self, now: float) -> None:  # call with the lock held
        for r in list(self._items.values()):
            if r.status in ("pending", "approved") and now >= r.expires:
                r.status, r.ciphertext, r.finished = "expired", None, now
                self._audit.write("request_expired", id=r.id, secret=r.secret)
            if r.finished is not None and now - r.finished > PURGE_AFTER_SECONDS:
                del self._items[r.id]

    def _lookup(self, req_id: str) -> Request:  # call with the lock held
        self._refresh(self._clock())
        r = self._items.get(req_id)
        if r is None:
            raise QueueError("not_found", "no such request", 404)
        return r

    def create(self, secret: str, command: str, pubkey_der: bytes) -> Request:
        with self._cond:
            now = self._clock()
            self._refresh(now)
            if sum(r.status == "pending" for r in self._items.values()) >= MAX_PENDING_REQUESTS:
                raise QueueError("too_many_pending", "too many pending requests", 429)
            req = Request(id=secrets.token_urlsafe(16), secret=secret, command=command,
                          pubkey_der=pubkey_der, created=now, expires=now + self._ttl)
            self._items[req.id] = req
            self._audit.write("request_created", id=req.id, secret=secret, command=command,
                              pubkey_sha256=req.pubkey_sha256, expires_at=utc_now_iso(req.expires))
            return req

    def get(self, req_id: str) -> Request:
        with self._cond:
            return self._lookup(req_id)

    def pending(self) -> list[Request]:
        with self._cond:
            self._refresh(self._clock())
            return [r for r in self._items.values() if r.status == "pending"]

    def _get_pending(self, req_id: str) -> Request:  # call with the lock held
        r = self._lookup(req_id)
        if r.status != "pending":
            raise QueueError("not_pending", f"request is already {r.status}", 409)
        return r

    def approve(self, req_id: str, ciphertext: bytes, audit_fields: dict) -> None:
        with self._cond:
            r = self._get_pending(req_id)
            r.status, r.ciphertext = "approved", ciphertext
            self._audit.write("request_approved", id=r.id, secret=r.secret, command=r.command,
                              pubkey_sha256=r.pubkey_sha256, **audit_fields)
            self._cond.notify_all()

    def deny(self, req_id: str) -> None:
        with self._cond:
            r = self._get_pending(req_id)
            r.status, r.finished = "denied", self._clock()
            self._audit.write("request_denied", id=r.id, secret=r.secret)
            self._cond.notify_all()

    def collect(self, req_id: str, wait: float) -> dict:
        """Requester pickup. An approved ciphertext is returned exactly once, then dropped."""
        with self._cond:
            deadline = self._clock() + wait
            while True:
                r = self._lookup(req_id)
                now = self._clock()
                if r.status == "consumed":
                    raise QueueError("consumed", "the ciphertext was already delivered", 410)
                if r.status == "approved":
                    ct = r.ciphertext
                    r.status, r.ciphertext, r.finished = "consumed", None, now
                    self._audit.write("request_delivered", id=r.id, secret=r.secret)
                    return {"status": "approved", "ciphertext": b64url_encode(ct)}
                if r.status in ("denied", "expired"):
                    return {"status": r.status}
                remaining = min(deadline, r.expires) - now
                if remaining <= 0:
                    return {"status": "pending"}
                self._cond.wait(timeout=remaining)


class NonceStore:
    """Single-use nonces for operation challenges, bound to the operation name."""

    MAX = 200

    def __init__(self, ttl: float = NONCE_TTL_SECONDS, clock=time.time) -> None:
        self._ttl = ttl
        self._clock = clock
        self._items: OrderedDict[bytes, tuple[str, float]] = OrderedDict()
        self._lock = threading.Lock()

    def issue(self, op: str) -> bytes:
        with self._lock:
            now = self._clock()
            for k in [k for k, (_, exp) in self._items.items() if exp <= now]:
                del self._items[k]
            while len(self._items) >= self.MAX:
                self._items.popitem(last=False)
            nonce = secrets.token_bytes(16)
            self._items[nonce] = (op, now + self._ttl)
            return nonce

    def consume(self, nonce: bytes, op: str) -> bool:
        with self._lock:
            v = self._items.pop(nonce, None)
            return v is not None and v[0] == op and v[1] > self._clock()
