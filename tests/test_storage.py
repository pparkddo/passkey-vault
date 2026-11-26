"""Storage backend contract tests.

The file backend always runs. Database backends run when a URL is given:

    PV_TEST_POSTGRES_URL=postgresql://postgres:pw@127.0.0.1:5432/postgres \
    PV_TEST_MONGODB_URL=mongodb://127.0.0.1:27017/passkey_vault_test \
    uv run --extra postgres --extra mongodb python -m unittest tests/test_storage.py -v

Database tests DROP the passkey-vault tables/collections in that database. Use a scratch database.
"""

from __future__ import annotations

import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tests"))

from passkey_vault.storage import StoreConflict, open_storage  # noqa: E402
from passkey_vault.storage.mongodb import AUDIT_COLLECTION, DEFAULT_DB, STATE_COLLECTION  # noqa: E402
from passkey_vault.storage.postgres import AUDIT_TABLE, STATE_TABLE  # noqa: E402
from test_server import ApprovalFlowTests, ApproverApiTests  # noqa: E402,F401  (reused below)

POSTGRES_URL = os.environ.get("PV_TEST_POSTGRES_URL")
MONGODB_URL = os.environ.get("PV_TEST_MONGODB_URL")


def reset_backend(url: str | None) -> None:
    """Remove everything the backend stored, so each test starts empty."""
    if url and url.startswith("postgres"):
        import psycopg

        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute(f"DROP TABLE IF EXISTS {STATE_TABLE}, {AUDIT_TABLE}")
    elif url and url.startswith("mongodb"):
        import pymongo

        client = pymongo.MongoClient(url)
        db = client.get_default_database(default=DEFAULT_DB)
        db.drop_collection(STATE_COLLECTION)
        db.drop_collection(AUDIT_COLLECTION)
        client.close()


def read_audit(url: str | None, data_dir: Path) -> list[dict]:
    import json

    if not url:
        return [json.loads(line) for line in (data_dir / "audit.log").read_text().splitlines()]
    if url.startswith("postgres"):
        import psycopg

        with psycopg.connect(url) as conn:
            return [row[0] for row in conn.execute(f"SELECT record FROM {AUDIT_TABLE} ORDER BY id")]
    import pymongo

    client = pymongo.MongoClient(url)
    try:
        col = client.get_default_database(default=DEFAULT_DB)[AUDIT_COLLECTION]
        return [json.loads(d["record"]) for d in col.find().sort("_id", 1)]
    finally:
        client.close()


class StoreContract:
    """Mixed into a TestCase per backend. Subclasses set `url`."""

    url: str | None = None

    def setUp(self) -> None:
        reset_backend(self.url)
        self.tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmp.name)
        self.store, self.audit = open_storage(self.url, self.data_dir)

    def tearDown(self) -> None:
        self.store.close()
        self.audit.close()
        self.tmp.cleanup()

    def test_empty(self) -> None:
        self.assertEqual(self.store.load(), (None, 0))

    def test_create_update_and_conflicts(self) -> None:
        doc = {"items": {"a.b": {"site": "x"}}, "n": 1}  # dotted key on purpose
        self.assertEqual(self.store.save(doc, 0), 1)
        with self.assertRaises(StoreConflict):
            self.store.save(doc, 0)  # create twice
        self.assertEqual(self.store.load(), (doc, 1))
        doc2 = {**doc, "n": 2}
        self.assertEqual(self.store.save(doc2, 1), 2)
        with self.assertRaises(StoreConflict):
            self.store.save({**doc, "n": 3}, 1)  # stale revision
        self.assertEqual(self.store.load(), (doc2, 2))

    def test_unicode_round_trip(self) -> None:
        doc = {"items": {"x": {"account": "üser ✓ 🔑"}}}
        self.store.save(doc, 0)
        self.assertEqual(self.store.load()[0], doc)

    def test_concurrent_writers_exactly_one_wins(self) -> None:
        self.store.save({"n": 0}, 0)
        others = [open_storage(self.url, self.data_dir)[0] for _ in range(8)]
        wins, barrier = [], threading.Barrier(len(others))

        def writer(i: int, store) -> None:
            barrier.wait()
            try:
                store.save({"n": i}, 1)
                wins.append(i)
            except StoreConflict:
                pass

        threads = [threading.Thread(target=writer, args=(i, s)) for i, s in enumerate(others)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for s in others:
            s.close()
        self.assertEqual(len(wins), 1)
        self.assertEqual(self.store.load(), ({"n": wins[0]}, 2))

    def test_audit_append(self) -> None:
        self.audit.append({"event": "a", "n": 1})
        self.audit.append({"event": "b", "text": "✓"})
        self.assertEqual(read_audit(self.url, self.data_dir), [{"event": "a", "n": 1}, {"event": "b", "text": "✓"}])


class FileStoreTests(StoreContract, unittest.TestCase):
    url = None


@unittest.skipUnless(POSTGRES_URL, "set PV_TEST_POSTGRES_URL")
class PostgresStoreTests(StoreContract, unittest.TestCase):
    url = POSTGRES_URL


@unittest.skipUnless(MONGODB_URL, "set PV_TEST_MONGODB_URL")
class MongoStoreTests(StoreContract, unittest.TestCase):
    url = MONGODB_URL


# The whole server flow again, on each database backend.
class _OnBackend:
    def setUp(self) -> None:
        reset_backend(self.storage)
        super().setUp()

    def test_secrets_never_on_disk(self) -> None:  # file-specific; covered by the file backend run
        self.skipTest("file backend only")


@unittest.skipUnless(POSTGRES_URL, "set PV_TEST_POSTGRES_URL")
class PostgresApprovalFlow(_OnBackend, ApprovalFlowTests):
    storage = POSTGRES_URL


@unittest.skipUnless(POSTGRES_URL, "set PV_TEST_POSTGRES_URL")
class PostgresApproverApi(_OnBackend, ApproverApiTests):
    storage = POSTGRES_URL


@unittest.skipUnless(MONGODB_URL, "set PV_TEST_MONGODB_URL")
class MongoApprovalFlow(_OnBackend, ApprovalFlowTests):
    storage = MONGODB_URL


@unittest.skipUnless(MONGODB_URL, "set PV_TEST_MONGODB_URL")
class MongoApproverApi(_OnBackend, ApproverApiTests):
    storage = MONGODB_URL


del ApprovalFlowTests, ApproverApiTests  # do not run the file-backend suites twice from this module

if __name__ == "__main__":
    unittest.main()
