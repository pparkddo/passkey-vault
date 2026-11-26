"""Vault rules on top of a VaultStore. The server only ever holds ciphertext and metadata.

Every change reads the latest document, applies the rule, and saves with compare-and-swap on the
revision, retrying on conflict, so concurrent writers never lose an update.

Signed changes also carry the passkey's new signature counter (`signer`). It is checked and stored
in the same compare-and-swap as the change itself: one write per operation, and a counter can never
be moved backwards by a stale read.
"""

from __future__ import annotations

import hmac
import secrets
from pathlib import Path
from typing import Any, Callable

from .audit import utc_now_iso
from .errors import ApiError
from .storage import Document, StoreConflict, VaultStore, atomic_write

FORMAT = "passkey-vault/vault/v1"
_SETUP_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ23456789"  # no 0/O/1/I/L/U
_CAS_RETRIES = 5

Signer = tuple[str, int]  # (credential id, new signature counter)


def _not_initialized() -> ApiError:
    return ApiError(409, "vault_not_initialized", "the vault has not been set up yet")


def _apply_signer(doc: Document, signer: Signer | None) -> bool:
    """Check and store the signer's new counter; return True if the document changed."""
    if signer is None:
        return False
    cred_id, count = signer
    cred = next((c for c in doc["credentials"] if c["id"] == cred_id), None)
    if cred is None:
        raise ApiError(403, "unknown_credential", "this passkey is not registered")
    if (count or cred["sign_count"]) and count <= cred["sign_count"]:
        raise ApiError(400, "invalid_webauthn", "signature counter did not increase; possible cloned authenticator")
    changed = cred["sign_count"] != count
    cred["sign_count"] = count
    return changed


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
        """The current document, or {} before setup. Load once per request and reuse it."""
        return self._store.load()[0] or {}

    @property
    def initialized(self) -> bool:
        return bool(self.snapshot())

    def require_initialized(self) -> Document:
        doc = self.snapshot()
        if not doc:
            raise _not_initialized()
        return doc

    def require_uninitialized(self) -> None:
        if self.snapshot():
            raise ApiError(409, "already_initialized", "the vault already exists")

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
    def _mutate(self, change: Callable[[Document], None] | None, signer: Signer | None) -> None:
        """Apply signer and change, then save. With no change and an unchanged counter, nothing is written."""
        for _ in range(_CAS_RETRIES):
            doc, revision = self._store.load()
            if doc is None:
                raise _not_initialized()
            counter_changed = _apply_signer(doc, signer)
            if change is None and not counter_changed:
                return
            if change is not None:
                change(doc)
            try:
                self._store.save(doc, revision)
                return
            except StoreConflict:
                continue
        raise ApiError(503, "storage_conflict", "the vault is being changed concurrently; try again")

    def initialize(self, credential: dict[str, Any]) -> None:
        doc = {"format": FORMAT, "rp_id": self._rp_id, "created_at": utc_now_iso(),
               "credentials": [credential], "items": {}}
        try:
            self._store.save(doc, 0)
        except StoreConflict:
            raise ApiError(409, "already_initialized", "the vault already exists") from None
        self._setup_code_path.unlink(missing_ok=True)

    def record_signature(self, signer: Signer) -> None:
        """For signed actions that change nothing else in the vault (approvals)."""
        self._mutate(None, signer)

    def add_credential(self, credential: dict[str, Any], signer: Signer) -> None:
        def change(doc: Document) -> None:
            if any(c["id"] == credential["id"] for c in doc["credentials"]):
                raise ApiError(409, "duplicate_credential", "this passkey is already registered")
            doc["credentials"].append(credential)

        self._mutate(change, signer)

    def delete_credential(self, cred_id_b64: str, signer: Signer) -> None:
        def change(doc: Document) -> None:
            remaining = [c for c in doc["credentials"] if c["id"] != cred_id_b64]
            if len(remaining) == len(doc["credentials"]):
                raise ApiError(404, "unknown_credential", "no such passkey")
            if not remaining:
                raise ApiError(409, "last_credential", "the last passkey cannot be deleted")
            doc["credentials"] = remaining

        self._mutate(change, signer)

    def put_item(self, name: str, item: dict[str, Any], signer: Signer) -> None:
        def change(doc: Document) -> None:
            doc["items"][name] = {**item, "updated_at": utc_now_iso()}

        self._mutate(change, signer)

    def delete_item(self, name: str, signer: Signer) -> None:
        def change(doc: Document) -> None:
            if name not in doc["items"]:
                raise ApiError(404, "unknown_secret", "no such item")
            del doc["items"][name]

        self._mutate(change, signer)
