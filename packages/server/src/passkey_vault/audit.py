"""Audit log: append-only. Never contains secrets, plaintext or RSA ciphertext.

Two ways to write, by when the event takes effect:
- write():  before the state change. If it fails, the caller aborts and the event does not happen.
- record(): after the state change. The event already happened, so a failing sink is logged and the
            caller carries on.
"""

from __future__ import annotations

import logging
import time

from .storage import AuditSink

log = logging.getLogger(__name__)


def utc_now_iso(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if ts is None else ts))


class AuditLog:
    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def write(self, event: str, **fields: object) -> None:
        self._sink.append({"ts": utc_now_iso(), "event": event, **fields})

    def record(self, event: str, **fields: object) -> None:
        try:
            self.write(event, **fields)
        except Exception:
            log.exception("audit write failed for %s", event)
