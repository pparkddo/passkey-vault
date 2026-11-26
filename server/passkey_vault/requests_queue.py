"""Request mailbox (in memory): 5-minute expiry, single delivery of the ciphertext, long polling.

Requests are intentionally not persisted: they are short-lived, and a restart simply makes the
requester ask again. Running several server processes would need a shared mailbox (not provided).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import sys
import threading
import time
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
    status: str = "pending"  # pending | approved | delivering | consumed | denied | expired
    ciphertext: bytes | None = field(default=None, repr=False)
    finished: float | None = None

    @property
    def pubkey_sha256(self) -> str:
        return hashlib.sha256(self.pubkey_der).hexdigest()

    def public_view(self, now: float | None = None) -> dict:
        now = time.time() if now is None else now
        return {
            "id": self.id, "secret": self.secret, "command": self.command, "pubkey": b64url_encode(self.pubkey_der),
            "created_at": utc_now_iso(self.created), "expires_at": utc_now_iso(self.expires),
            # Remaining lifetime by the server's clock, so clients never depend on their own clock.
            "expires_in": max(0, round(self.expires - now)), "status": self.status,
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

    def _best_effort_audit(self, event: str, **fields: object) -> None:
        """For events that have already happened: a failing audit sink must not fail the caller."""
        try:
            self._audit.write(event, **fields)
        except Exception as e:  # noqa: BLE001
            sys.stderr.write(f"audit write failed for {event}: {e!r}\n")

    def _refresh(self, now: float) -> None:  # call with the lock held
        for r in list(self._items.values()):
            if r.status in ("pending", "approved", "delivering") and now >= r.expires:
                r.status, r.ciphertext, r.finished = "expired", None, now
                self._best_effort_audit("request_expired", id=r.id, secret=r.secret)
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
            # Audit first: if the record cannot be written, the request does not exist.
            self._audit.write("request_created", id=req.id, secret=secret, command=command,
                              pubkey_sha256=req.pubkey_sha256, expires_at=utc_now_iso(req.expires))
            self._items[req.id] = req
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
            # Audit first: an approval that cannot be recorded does not happen.
            self._audit.write("request_approved", id=r.id, secret=r.secret, command=r.command,
                              pubkey_sha256=r.pubkey_sha256, **audit_fields)
            r.status, r.ciphertext = "approved", ciphertext
            self._cond.notify_all()

    def deny(self, req_id: str) -> None:
        with self._cond:
            r = self._get_pending(req_id)
            self._audit.write("request_denied", id=r.id, secret=r.secret)
            r.status, r.finished = "denied", self._clock()
            self._cond.notify_all()

    def collect(self, req_id: str, wait: float) -> dict:
        """Requester pickup. An approved request moves to "delivering" and the caller MUST then call
        finish_delivery(): the ciphertext is dropped only once the response was actually sent, so a
        failed send can be retried, and two concurrent polls never both receive it."""
        with self._cond:
            deadline = self._clock() + wait
            while True:
                r = self._lookup(req_id)
                now = self._clock()
                if r.status == "consumed":
                    raise QueueError("consumed", "the ciphertext was already delivered", 410)
                if r.status == "approved":
                    r.status = "delivering"
                    return {"status": "approved", "ciphertext": b64url_encode(r.ciphertext)}
                if r.status in ("denied", "expired"):
                    return {"status": r.status}
                remaining = min(deadline, r.expires) - now  # pending, or another poll is delivering
                if remaining <= 0:
                    return {"status": "pending"}
                self._cond.wait(timeout=remaining)

    def finish_delivery(self, req_id: str, delivered: bool) -> None:
        with self._cond:
            r = self._items.get(req_id)
            if r is None or r.status != "delivering":
                return
            if delivered:
                r.status, r.ciphertext, r.finished = "consumed", None, self._clock()
                self._best_effort_audit("request_delivered", id=r.id, secret=r.secret)
            else:
                r.status = "approved"
            self._cond.notify_all()


class NonceStore:
    """Single-use nonces for operation challenges, bound to the operation name.

    Nonces are self-authenticating (random || expiry || HMAC), so issuing them stores nothing and a
    flood of requests for nonces cannot evict one that the approver is about to use. Only consumed
    nonces are remembered, until they expire.
    """

    def __init__(self, ttl: float = NONCE_TTL_SECONDS, clock=time.time) -> None:
        self._ttl = ttl
        self._clock = clock
        self._key = secrets.token_bytes(32)
        self._used: dict[bytes, float] = {}
        self._lock = threading.Lock()

    def _mac(self, op: str, body: bytes) -> bytes:
        return hmac.new(self._key, op.encode() + b"\x00" + body, hashlib.sha256).digest()[:16]

    def issue(self, op: str) -> bytes:
        body = secrets.token_bytes(16) + struct.pack(">Q", int(self._clock() + self._ttl))
        return body + self._mac(op, body)

    def consume(self, nonce: bytes, op: str) -> bool:
        if len(nonce) != 40:
            return False
        body, tag = nonce[:24], nonce[24:]
        expires = struct.unpack(">Q", body[16:])[0]
        now = self._clock()
        if not hmac.compare_digest(tag, self._mac(op, body)) or expires <= now:
            return False
        with self._lock:
            for k in [k for k, exp in self._used.items() if exp <= now]:
                del self._used[k]
            if nonce in self._used:
                return False
            self._used[nonce] = expires
            return True
