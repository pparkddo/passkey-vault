"""Storage interfaces.

The vault is small (a handful of credentials and items), so it is stored as ONE document with a
monotonically increasing revision. Writers use compare-and-swap on the revision, which maps cleanly
onto a file, a single PostgreSQL row, or a single MongoDB document, and stays correct if several
server processes share one database.

Backends only ever see ciphertext and metadata. Confidentiality does not depend on the backend;
integrity and availability do (see docs/threat-model.md, "Storage backends").
"""

from __future__ import annotations

from typing import Any, Protocol

Document = dict[str, Any]


class StoreConflict(Exception):
    """The stored revision is not the one the writer expected."""


class VaultStore(Protocol):
    def load(self) -> tuple[Document | None, int]:
        """Return (document, revision). (None, 0) when nothing has been stored yet."""

    def save(self, doc: Document, expected_revision: int) -> int:
        """Store doc if the current revision equals expected_revision; return the new revision.

        Raises StoreConflict otherwise. expected_revision == 0 means "create".
        """

    def close(self) -> None: ...


class AuditSink(Protocol):
    def append(self, record: dict[str, Any]) -> None:
        """Durably append one audit record. Records are never updated or deleted by the server."""

    def close(self) -> None: ...
