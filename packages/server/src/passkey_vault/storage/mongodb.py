"""MongoDB backend (optional dependency: pymongo).

    --storage mongodb://user@host/dbname        (database defaults to "passkey_vault")

Collections:
    vault_state  one document {_id: "vault", revision, doc_json}
    audit        one document per record {recorded_at, record}

The vault document is stored as a JSON string (doc_json) rather than a nested document because
item names may contain "." which MongoDB treats specially in field paths. Nothing queries inside
the document, so nothing is lost. Writes use majority write concern with journaling.
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

from .base import Document, StoreConflict

DEFAULT_DB = "passkey_vault"
STATE_COLLECTION = "vault_state"
AUDIT_COLLECTION = "audit"


def _import_pymongo() -> Any:
    try:
        import pymongo
        from pymongo.errors import DuplicateKeyError
    except ImportError as e:  # pragma: no cover - depends on installed extras
        raise RuntimeError("MongoDB storage needs pymongo: install the 'mongodb' extra") from e
    return pymongo, DuplicateKeyError


class MongoVaultStore:
    def __init__(self, db: Any, client: Any, duplicate_key_error: type[Exception]) -> None:
        self._col = db[STATE_COLLECTION]
        self._client = client
        self._dup = duplicate_key_error

    def load(self) -> tuple[Document | None, int]:
        found = self._col.find_one({"_id": "vault"})
        return (json.loads(found["doc_json"]), int(found["revision"])) if found else (None, 0)

    def save(self, doc: Document, expected_revision: int) -> int:
        new = expected_revision + 1
        body = json.dumps(doc, ensure_ascii=False)
        if expected_revision == 0:
            try:
                self._col.insert_one({"_id": "vault", "revision": new, "doc_json": body})
            except self._dup:
                raise StoreConflict("vault already exists") from None
        else:
            res = self._col.update_one(
                {"_id": "vault", "revision": expected_revision}, {"$set": {"revision": new, "doc_json": body}}
            )
            if res.matched_count != 1:
                raise StoreConflict(f"revision changed (expected {expected_revision})")
        return new

    def close(self) -> None:
        self._client.close()


class MongoAuditSink:
    def __init__(self, db: Any, client: Any) -> None:
        self._col = db[AUDIT_COLLECTION]
        self._client = client

    def append(self, record: dict[str, Any]) -> None:
        self._col.insert_one({"recorded_at": dt.datetime.now(dt.UTC), "record": json.dumps(record, ensure_ascii=False)})

    def close(self) -> None:
        self._client.close()


def open_mongodb(uri: str) -> tuple[MongoVaultStore, MongoAuditSink]:
    pymongo, dup = _import_pymongo()
    from pymongo.write_concern import WriteConcern

    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000)
    db = client.get_default_database(default=DEFAULT_DB).with_options(write_concern=WriteConcern(w="majority", j=True))
    client.admin.command("ping")
    return MongoVaultStore(db, client, dup), MongoAuditSink(db, client)
