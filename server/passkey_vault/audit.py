"""Audit log: append-only. Never contains secrets, plaintext or RSA ciphertext."""

from __future__ import annotations

import time

from .storage import AuditSink


def utc_now_iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if ts is None else ts))


class AuditLog:
    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def write(self, event: str, **fields: object) -> None:
        self._sink.append({"ts": utc_now_iso(), "event": event, **fields})
