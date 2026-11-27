"""Default backend: a JSON file for the vault and a JSON Lines file for the audit log."""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import threading
from pathlib import Path
from typing import Any

from .base import Document, StoreConflict


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Write via temp file + fsync + rename, then fsync the directory."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


class JsonFileVaultStore:
    """The revision is kept inside the file. Compare-and-swap holds an exclusive flock on a sidecar
    lock file, so it is safe across threads and processes on one host (not across network filesystems)."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock_path = path.with_name(f".{path.name}.lock")
        self._lock = threading.Lock()

    def load(self) -> tuple[Document | None, int]:
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None, 0
        return raw["doc"], int(raw["revision"])

    def save(self, doc: Document, expected_revision: int) -> int:
        with self._lock:
            fd = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                _, current = self.load()
                if current != expected_revision:
                    raise StoreConflict(f"revision is {current}, expected {expected_revision}")
                new = current + 1
                body = json.dumps({"revision": new, "doc": doc}, ensure_ascii=False, indent=2) + "\n"
                atomic_write(self._path, body.encode("utf-8"))
                return new
            finally:
                os.close(fd)  # releases the flock

    def close(self) -> None:
        pass


class JsonlAuditSink:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> None:
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)

    def close(self) -> None:
        pass
