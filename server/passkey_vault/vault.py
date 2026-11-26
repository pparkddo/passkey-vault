"""Vault rules on top of a VaultStore. The server only ever holds ciphertext and metadata.

Every change reads the latest document, applies the rule, and saves with compare-and-swap on the
revision, retrying on conflict. That keeps the rules correct even when several server processes
share one database backend.
"""

from __future__ import annotations

import hmac
import secrets
from pathlib import Path
from typing import Any, Callable

from .audit import utc_now_iso
from .storage import Document, StoreConflict, VaultStore, atomic_write

FORMAT = "passkey-vault/vault/v1"
_SETUP_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"  # no 0/O/1/I/L/U
_CAS_RETRIES = 5


class VaultError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.code, self.message, self.status = code, message, status


class Vault:
    def __init__(self, store: VaultStore, setup_code_path: Path, rp_id: str) -> None:
        self._store = store
        self._setup_code_path = setup_code_path
        self._rp_id = rp_id
        doc, _ = store.load()
        if doc is not None:
            if doc.get("format") != FORMAT:
                raise RuntimeError(f"unknown vault format: {doc.get('format')!r}")
            if doc.get("rp_id") != rp_id:
                raise RuntimeError(f"vault RP ID ({doc.get('rp_id')}) differs from configured RP ID ({rp_id})")

    # ---- reads (always from the store, so other processes' writes are visible) ----
    def snapshot(self) -> Document:
        return self._store.load()[0] or {}

    @property
    def initialized(self) -> bool:
        return self._store.load()[0] is not None

    def credential(self, cred_id_b64: str) -> dict[str, Any] | None:
        return next((c for c in self.snapshot().get("credentials", []) if c["id"] == cred_id_b64), None)

    def item(self, name: str) -> dict[str, Any] | None:
        return self.snapshot().get("items", {}).get(name)

    # ---- setup code: a local secret, readable only by the service account (and root) ----
    def ensure_setup_code(self) -> str | None:
        """Create (or read) the setup code while the vault does not exist yet."""
        if self.initialized:
            return None
        if self._setup_code_path.exists():
            return self._setup_code_path.read_text(encoding="ascii").strip()
        raw = "".join(secrets.choice(_SETUP_ALPHABET) for _ in range(20))
        code = "-".join(raw[i:i + 5] for i in range(0, 20, 5))
        atomic_write(self._setup_code_path, (code + "\n").encode("ascii"))
        return code

    def check_setup_code(self, given: object) -> bool:
        if not isinstance(given, str) or not self._setup_code_path.exists():
            return False

        def norm(s: str) -> bytes:
            return "".join(ch for ch in s.upper() if ch not in " -\n\t").encode("utf-8")

        expected = self._setup_code_path.read_text(encoding="ascii")
        return hmac.compare_digest(norm(given), norm(expected))

    # ---- writes ----
    def _mutate(self, change: Callable[[Document], bool | None]) -> None:
        """Apply change(doc) and save. change returns False to skip saving."""
        for _ in range(_CAS_RETRIES):
            doc, revision = self._store.load()
            if doc is None:
                raise VaultError("vault_not_initialized", "the vault has not been set up yet", 409)
            if change(doc) is False:
                return
            try:
                self._store.save(doc, revision)
                return
            except StoreConflict:
                continue
        raise VaultError("storage_conflict", "the vault is being changed concurrently; try again", 503)

    def initialize(self, credential: dict[str, Any]) -> None:
        doc = {"format": FORMAT, "rp_id": self._rp_id, "created_at": utc_now_iso(),
               "credentials": [credential], "items": {}}
        try:
            self._store.save(doc, 0)
        except StoreConflict:
            raise VaultError("already_initialized", "the vault already exists", 409) from None
        self._setup_code_path.unlink(missing_ok=True)

    def update_sign_count(self, cred_id_b64: str, sign_count: int) -> None:
        def change(doc: Document) -> bool:
            for c in doc["credentials"]:
                if c["id"] == cred_id_b64 and c["sign_count"] != sign_count:
                    c["sign_count"] = sign_count
                    return True
            return False

        self._mutate(change)

    def add_credential(self, credential: dict[str, Any]) -> None:
        def change(doc: Document) -> None:
            if any(c["id"] == credential["id"] for c in doc["credentials"]):
                raise VaultError("duplicate_credential", "this passkey is already registered", 409)
            doc["credentials"].append(credential)

        self._mutate(change)

    def delete_credential(self, cred_id_b64: str) -> None:
        def change(doc: Document) -> None:
            remaining = [c for c in doc["credentials"] if c["id"] != cred_id_b64]
            if len(remaining) == len(doc["credentials"]):
                raise VaultError("unknown_credential", "no such passkey", 404)
            if not remaining:
                raise VaultError("last_credential", "the last passkey cannot be deleted", 409)
            doc["credentials"] = remaining

        self._mutate(change)

    def put_item(self, name: str, item: dict[str, Any]) -> None:
        def change(doc: Document) -> None:
            doc["items"][name] = {**item, "updated_at": utc_now_iso()}

        self._mutate(change)

    def delete_item(self, name: str) -> None:
        def change(doc: Document) -> None:
            if name not in doc["items"]:
                raise VaultError("unknown_secret", "no such item", 404)
            del doc["items"][name]

        self._mutate(change)
