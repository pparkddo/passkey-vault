"""Request queue (in memory): 5-minute expiry, single delivery of the ciphertext, long polling.

Requests are intentionally not persisted: they are short-lived, and a restart simply makes the
requester ask again. This is also why one vault is served by one server process.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from .audit import AuditLog, utc_now_iso
from .config import MAX_PENDING_REQUESTS, NONCE_TTL_SECONDS, REQUEST_TTL_SECONDS
from .errors import ApiError
from .formats import b64url_encode

PURGE_AFTER_SECONDS = 600  # how long finished requests are remembered (for 410 / final status)


def _not_found() -> ApiError:
    return ApiError(404, "not_found", "no such request")


@dataclass
class Request:
    id: str
    secret: str
    command: str
    pubkey_der: bytes
    key_bytes: int  # requester RSA modulus size; an RSA-OAEP ciphertext has exactly this length
    created: float
    expires: float
    # pending | approved | delivering (internal: being sent to the requester) | consumed | denied | expired
    status: str = "pending"
    ciphertext: bytes | None = field(default=None, repr=False)
    finished: float | None = None

    @property
    def pubkey_sha256(self) -> str:
        return hashlib.sha256(self.pubkey_der).hexdigest()

    @property
    def expires_at(self) -> str:
        return utc_now_iso(self.expires)

    @property
    def visible_status(self) -> str:
        return "approved" if self.status == "delivering" else self.status

    def public_view(self, now: float) -> dict[str, Any]:
        """now: the queue's clock, so expires_in agrees with how the queue decides expiry."""
        return {
            "id": self.id,
            "secret": self.secret,
            "command": self.command,
            "pubkey": b64url_encode(self.pubkey_der),
            "created_at": utc_now_iso(self.created),
            "expires_at": self.expires_at,
            # Remaining lifetime by the server's clock, so clients never depend on their own clock.
            "expires_in": max(0, round(self.expires - now)),
            "status": self.visible_status,
        }


class RequestQueue:
    def __init__(
        self, audit: AuditLog, ttl: float = REQUEST_TTL_SECONDS, clock: Callable[[], float] = time.time
    ) -> None:
        self._audit = audit
        self._ttl = ttl
        self._clock = clock
        self._items: dict[str, Request] = {}
        self._cond = threading.Condition()

    def _refresh(self, now: float) -> None:  # call with the lock held
        for r in list(self._items.values()):
            if r.status in ("pending", "approved", "delivering") and now >= r.expires:
                r.status, r.ciphertext, r.finished = "expired", None, now
                self._audit.record("request_expired", id=r.id, secret=r.secret)
            if r.finished is not None and now - r.finished > PURGE_AFTER_SECONDS:
                del self._items[r.id]

    def _lookup(self, req_id: str) -> Request:  # call with the lock held
        self._refresh(self._clock())
        r = self._items.get(req_id)
        if r is None:
            raise _not_found()
        return r

    def _get_pending(self, req_id: str) -> Request:  # call with the lock held
        r = self._lookup(req_id)
        if r.status != "pending":
            raise ApiError(409, "not_pending", f"request is already {r.visible_status}")
        return r

    def create(self, secret: str, command: str, pubkey_der: bytes, key_bytes: int) -> Request:
        with self._cond:
            now = self._clock()
            self._refresh(now)
            if sum(r.status == "pending" for r in self._items.values()) >= MAX_PENDING_REQUESTS:
                raise ApiError(429, "too_many_pending", "too many pending requests")
            req = Request(
                id=secrets.token_urlsafe(16),
                secret=secret,
                command=command,
                pubkey_der=pubkey_der,
                key_bytes=key_bytes,
                created=now,
                expires=now + self._ttl,
            )
            # Audit first: if the record cannot be written, the request does not exist.
            self._audit.write(
                "request_created",
                id=req.id,
                secret=secret,
                command=command,
                pubkey_sha256=req.pubkey_sha256,
                expires_at=req.expires_at,
            )
            self._items[req.id] = req
            return req

    def get(self, req_id: str) -> Request:
        with self._cond:
            return self._lookup(req_id)

    def view(self, req: Request) -> dict[str, Any]:
        return req.public_view(self._clock())

    def pending_views(self) -> list[dict[str, Any]]:
        with self._cond:
            now = self._clock()
            self._refresh(now)
            pending = [r for r in self._items.values() if r.status == "pending"]
        return [r.public_view(now) for r in pending]  # built outside the lock

    def approve(self, req_id: str, ciphertext: bytes, audit_fields: dict[str, Any]) -> None:
        with self._cond:
            r = self._get_pending(req_id)
            # Audit first: an approval that cannot be recorded does not happen.
            self._audit.write(
                "request_approved",
                id=r.id,
                secret=r.secret,
                command=r.command,
                pubkey_sha256=r.pubkey_sha256,
                **audit_fields,
            )
            r.status, r.ciphertext = "approved", ciphertext
            self._cond.notify_all()

    def deny(self, req_id: str) -> None:
        with self._cond:
            r = self._get_pending(req_id)
            self._audit.write("request_denied", id=r.id, secret=r.secret)
            r.status, r.finished = "denied", self._clock()
            self._cond.notify_all()

    def _take(self, req_id: str, wait: float) -> dict[str, Any]:
        """Wait up to `wait` seconds; an approved request moves to "delivering"."""
        with self._cond:
            deadline = self._clock() + wait
            while True:
                r = self._lookup(req_id)
                now = self._clock()
                if r.status == "consumed":
                    raise ApiError(410, "consumed", "the ciphertext was already delivered")
                if r.status == "approved":
                    assert r.ciphertext is not None
                    r.status = "delivering"
                    return {"status": "approved", "ciphertext": b64url_encode(r.ciphertext)}
                if r.status in ("denied", "expired"):
                    return {"status": r.status}
                remaining = min(deadline, r.expires) - now  # pending, or another poll is delivering
                if remaining <= 0:
                    return {"status": "pending"}
                self._cond.wait(timeout=remaining)

    def _settle(self, req_id: str, delivered: bool) -> None:
        with self._cond:
            r = self._items.get(req_id)
            if r is None or r.status != "delivering":
                return
            if delivered:
                r.status, r.ciphertext, r.finished = "consumed", None, self._clock()
                self._audit.record("request_delivered", id=r.id, secret=r.secret)
            else:
                r.status = "approved"
            self._cond.notify_all()

    @contextmanager
    def deliver(self, req_id: str, wait: float) -> Iterator[dict[str, Any]]:
        """Requester pickup:  with queue.deliver(id, wait) as result: send(result)

        An approved ciphertext is dropped only if the block finishes, i.e. the response was sent.
        If sending raises, the request goes back to approved and can be collected again. Concurrent
        polls never both receive it."""
        result = self._take(req_id, wait)
        delivered = False
        try:
            yield result
            delivered = True
        finally:
            if result["status"] == "approved":
                self._settle(req_id, delivered)


class NonceStore:
    """Single-use nonces for operation challenges, bound to the operation name.

    Nonces are self-authenticating (random || expiry || HMAC), so issuing them stores nothing and a
    flood of requests for nonces cannot evict one that the approver is about to use. Only consumed
    nonces are remembered, until they expire.
    """

    def __init__(self, ttl: float = NONCE_TTL_SECONDS, clock: Callable[[], float] = time.time) -> None:
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
