"""Pluggable storage for the vault document and the audit log.

    file (default)              <data-dir>/vault.json + <data-dir>/audit.log
    postgresql://...            PostgreSQL (extra: postgres)
    mongodb://...               MongoDB    (extra: mongodb)

To add a backend, implement VaultStore and AuditSink (storage/base.py), register the URL scheme in
open_storage, and run tests/test_storage.py against it.
"""

from __future__ import annotations

from pathlib import Path

from .base import AuditSink, Document, StoreConflict, VaultStore
from .files import JsonFileVaultStore, JsonlAuditSink, atomic_write

__all__ = ["AuditSink", "Document", "StoreConflict", "VaultStore", "atomic_write", "open_storage"]


def open_storage(url: str | None, data_dir: Path) -> tuple[VaultStore, AuditSink]:
    if not url or url == "file":
        return JsonFileVaultStore(data_dir / "vault.json"), JsonlAuditSink(data_dir / "audit.log")
    scheme = url.split(":", 1)[0].lower()
    if scheme in ("postgres", "postgresql"):
        from .postgres import open_postgres

        return open_postgres(url)
    if scheme in ("mongodb", "mongodb+srv"):
        from .mongodb import open_mongodb

        return open_mongodb(url)
    raise ValueError(f"unsupported storage URL scheme: {scheme!r}")
