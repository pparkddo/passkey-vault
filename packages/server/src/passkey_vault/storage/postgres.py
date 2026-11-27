"""PostgreSQL backend (optional dependency: psycopg 3).

    --storage postgresql://user@host/dbname

Tables (created if missing):
    passkey_vault_state(id = 1 only, revision bigint, doc jsonb)
    passkey_vault_audit(id bigserial, recorded_at timestamptz, record jsonb)

Compare-and-swap is a single UPDATE ... WHERE revision = expected, so it is atomic without
explicit transactions.
"""

from __future__ import annotations

import threading
from typing import Any

from .base import Document, StoreConflict

STATE_TABLE = "passkey_vault_state"
AUDIT_TABLE = "passkey_vault_audit"

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS {STATE_TABLE} (
    id       smallint PRIMARY KEY CHECK (id = 1),
    revision bigint   NOT NULL,
    doc      jsonb    NOT NULL
);
CREATE TABLE IF NOT EXISTS {AUDIT_TABLE} (
    id          bigserial   PRIMARY KEY,
    recorded_at timestamptz NOT NULL DEFAULT now(),
    record      jsonb       NOT NULL
);
"""


def _import_psycopg() -> Any:
    try:
        import psycopg
        from psycopg.types.json import Jsonb
    except ImportError as e:  # pragma: no cover - depends on installed extras
        raise RuntimeError("PostgreSQL storage needs psycopg: install the 'postgres' extra") from e
    return psycopg, Jsonb


class _Connection:
    """One autocommit connection shared by the store and the audit sink, reconnecting on failure."""

    def __init__(self, dsn: str) -> None:
        self._psycopg, self.Jsonb = _import_psycopg()
        self._dsn = dsn
        self._lock = threading.Lock()
        self._conn: Any = None
        self.execute(SCHEMA)

    def execute(self, sql: str, params: tuple[Any, ...] = (), retry: bool = True) -> tuple[list[tuple[Any, ...]], int]:
        """Run one statement; return (rows, rowcount). On a broken connection, reconnect and (only if
        retry) run it again. Non-idempotent statements pass retry=False: the first try may have committed."""
        broken = (self._psycopg.OperationalError, self._psycopg.InterfaceError)
        with self._lock:
            for attempt in (1, 2):
                if self._conn is None or self._conn.closed:
                    self._conn = self._psycopg.connect(self._dsn, autocommit=True)
                try:
                    with self._conn.cursor() as cur:
                        cur.execute(sql, params)
                        return (cur.fetchall() if cur.description else []), cur.rowcount
                except broken:
                    self._conn = None
                    if attempt == 2 or not retry:
                        raise
        raise AssertionError("unreachable")  # the loop always returns or raises

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


class PostgresVaultStore:
    def __init__(self, conn: _Connection) -> None:
        self._db = conn

    def load(self) -> tuple[Document | None, int]:
        rows, _ = self._db.execute(f"SELECT doc, revision FROM {STATE_TABLE} WHERE id = 1")
        return (rows[0][0], int(rows[0][1])) if rows else (None, 0)

    def save(self, doc: Document, expected_revision: int) -> int:
        new = expected_revision + 1
        if expected_revision == 0:
            _, count = self._db.execute(
                f"INSERT INTO {STATE_TABLE} (id, revision, doc) VALUES (1, %s, %s) ON CONFLICT (id) DO NOTHING",
                (new, self._db.Jsonb(doc)),
            )
        else:
            _, count = self._db.execute(
                f"UPDATE {STATE_TABLE} SET revision = %s, doc = %s WHERE id = 1 AND revision = %s",
                (new, self._db.Jsonb(doc), expected_revision),
            )
        if count != 1:
            raise StoreConflict(f"revision changed (expected {expected_revision})")
        return new

    def close(self) -> None:
        self._db.close()


class PostgresAuditSink:
    def __init__(self, conn: _Connection) -> None:
        self._db = conn

    def append(self, record: dict[str, Any]) -> None:
        self._db.execute(f"INSERT INTO {AUDIT_TABLE} (record) VALUES (%s)", (self._db.Jsonb(record),), retry=False)

    def close(self) -> None:
        self._db.close()


def open_postgres(dsn: str) -> tuple[PostgresVaultStore, PostgresAuditSink]:
    conn = _Connection(dsn)
    return PostgresVaultStore(conn), PostgresAuditSink(conn)
