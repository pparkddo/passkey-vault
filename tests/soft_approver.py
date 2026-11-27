"""A fake approver for tests: a software WebAuthn authenticator (ES256, "none" attestation,
PRF emulation) plus the same cryptography as the approval page (web/js), in Python.
The real page code is exercised by the E2E test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import struct
from dataclasses import dataclass, field

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_der_public_key

from passkey_vault import formats as f
from support import http_json, oaep, wrap_key

FLAG_UP, FLAG_UV, FLAG_BE, FLAG_BS, FLAG_AT = 0x01, 0x04, 0x08, 0x10, 0x40


@dataclass
class SoftCredential:
    id: bytes = field(default_factory=lambda: secrets.token_bytes(20))
    key: ec.EllipticCurvePrivateKey = field(default_factory=lambda: ec.generate_private_key(ec.SECP256R1()))
    prf_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    sign_count: int = 0

    def prf(self, salt: bytes) -> bytes:
        # Like CTAP hmac-secret: HMAC with a per-credential secret over SHA-256("WebAuthn PRF\0" || input).
        return hmac.new(self.prf_secret, hashlib.sha256(b"WebAuthn PRF\x00" + salt).digest(), hashlib.sha256).digest()


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str, uv: bool = True) -> None:
        self.rp_id, self.origin, self.uv = rp_id, origin, uv

    def _client_data(self, typ: str, challenge: bytes, origin: str | None = None) -> bytes:
        return json.dumps({"type": typ, "challenge": f.b64url_encode(challenge),
                           "origin": origin or self.origin, "crossOrigin": False}).encode()

    def _flags(self) -> int:
        return FLAG_UP | (FLAG_UV if self.uv else 0) | FLAG_BE | FLAG_BS

    def create(self, challenge: bytes, origin: str | None = None) -> tuple[SoftCredential, dict]:
        cred = SoftCredential()
        nums = cred.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([self._flags() | FLAG_AT])
                     + struct.pack(">I", 0) + bytes(16) + struct.pack(">H", len(cred.id)) + cred.id + cose)
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = f.b64url_encode(cred.id)
        return cred, {
            "id": cid, "rawId": cid, "type": "public-key", "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {"clientDataJSON": f.b64url_encode(self._client_data("webauthn.create", challenge, origin)),
                         "attestationObject": f.b64url_encode(att), "transports": ["internal"]},
        }

    def get(self, cred: SoftCredential, challenge: bytes) -> dict:
        auth_data = (hashlib.sha256(self.rp_id.encode()).digest() + bytes([self._flags()])
                     + struct.pack(">I", cred.sign_count))
        cdj = self._client_data("webauthn.get", challenge)
        sig = cred.key.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        cid = f.b64url_encode(cred.id)
        return {
            "id": cid, "rawId": cid, "type": "public-key", "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {"clientDataJSON": f.b64url_encode(cdj), "authenticatorData": f.b64url_encode(auth_data),
                         "signature": f.b64url_encode(sig), "userHandle": None},
        }


class SoftApprover:
    """Plays the approval page: talks to the approver door over HTTP."""

    def __init__(self, base: str, rp_id: str, origin: str) -> None:
        self.base, self.origin = base.rstrip("/"), origin
        self.auth = SoftAuthenticator(rp_id, origin)
        self.creds: list[SoftCredential] = []

    # ---- HTTP ----
    def call(self, method: str, path: str, body: dict | None = None, origin: str | None = "default") -> tuple[int, dict]:
        origin = self.origin if origin == "default" else origin
        return http_json(method, self.base + path, body, timeout=10, headers={"Origin": origin} if origin else None)

    def sign_op(self, op: str, by: SoftCredential, *fields: str | bytes) -> dict:
        """{nonce, assertion} for an operation challenge, like signOnly() in web/js/manage.js."""
        nonce = self.nonce(op)
        return {"nonce": f.b64url_encode(nonce), "assertion": self.auth.get(by, f.op_challenge(op, nonce, *fields))}

    def nonce(self, op: str) -> bytes:
        st, body = self.call("POST", "/api/nonce", {"op": op})
        assert st == 200, body
        return f.b64url_decode(body["nonce"])

    def state(self) -> dict:
        return self.call("GET", "/api/state")[1]

    # ---- vault ----
    def _master_key(self, cred: SoftCredential) -> bytes:
        entry = next(c for c in self.state()["credentials"] if c["id"] == f.b64url_encode(cred.id))
        w = entry["wrapped_master_key"]
        return AESGCM(wrap_key(cred.prf(f.PRF_SALT))).decrypt(
            f.b64url_decode(w["iv"]), f.b64url_decode(w["ct"]), f.wrap_aad(cred.id))

    @staticmethod
    def _wrap(cred: SoftCredential, master: bytes) -> dict:
        iv = secrets.token_bytes(12)
        ct = AESGCM(wrap_key(cred.prf(f.PRF_SALT))).encrypt(iv, master, f.wrap_aad(cred.id))
        return {"iv": f.b64url_encode(iv), "ct": f.b64url_encode(ct)}

    def setup(self, setup_code: str, name: str = "soft-approver") -> tuple[int, dict]:
        nonce = self.nonce("setup")
        cred, reg = self.auth.create(f.op_challenge("register", nonce, name))
        master = secrets.token_bytes(32)
        st, body = self.call("POST", "/api/setup", {
            "setup_code": setup_code, "nonce": f.b64url_encode(nonce), "name": name,
            "registration": reg, "wrapped_master_key": self._wrap(cred, master)})
        if st == 201:
            self.creds.append(cred)
        return st, body

    def put_item(self, name: str, site: str, account: str, secret: str, cred: SoftCredential | None = None,
                 tamper: dict | None = None) -> tuple[int, dict]:
        cred = cred or self.creds[0]
        nonce = self.nonce("put-item")
        assertion = self.auth.get(cred, f.op_challenge("put-item", nonce, name, site, account))
        master = self._master_key(cred)
        iv = secrets.token_bytes(12)
        ct = AESGCM(master).encrypt(iv, secret.encode(), f.item_aad(name, site, account))
        body = {"nonce": f.b64url_encode(nonce), "name": name, "site": site, "account": account,
                "iv": f.b64url_encode(iv), "ct": f.b64url_encode(ct), "assertion": assertion, **(tamper or {})}
        return self.call("POST", "/api/items", body)

    def approve(self, req_id: str, cred: SoftCredential | None = None, approve_with: dict | None = None) -> tuple[int, dict]:
        """Approve like the page does. approve_with overrides the fields that get signed (for negative tests)."""
        cred = cred or self.creds[0]
        st, req = self.call("GET", f"/api/requests/{req_id}")
        assert st == 200, req
        pub_der = f.b64url_decode(req["pubkey"])
        fields = {"id": req["id"], "secret": req["secret"], "command": req["command"], **(approve_with or {})}
        challenge = f.approve_challenge(fields["id"], fields["secret"], fields["command"], pub_der)
        assertion = self.auth.get(cred, challenge)
        master = self._master_key(cred)
        it = req["item"]
        plaintext = AESGCM(master).decrypt(f.b64url_decode(it["iv"]), f.b64url_decode(it["ct"]),
                                           f.item_aad(it["name"], it["site"], it["account"]))
        label = f.oaep_label(req["id"], req["command"], pub_der)
        ct = load_der_public_key(pub_der).encrypt(plaintext, oaep(label))  # type: ignore[union-attr]
        return self.call("POST", f"/api/requests/{req_id}/approve",
                         {"assertion": assertion, "ciphertext": f.b64url_encode(ct)})

    def deny(self, req_id: str) -> tuple[int, dict]:
        return self.call("POST", f"/api/requests/{req_id}/deny", {})

    def add_credential(self, name: str = "second", by: SoftCredential | None = None) -> tuple[int, dict]:
        by = by or self.creds[0]
        nonce = self.nonce("add-credential")
        new, reg = self.auth.create(f.op_challenge("register", nonce, name))
        assertion = self.auth.get(by, f.op_challenge("add-credential", nonce, new.id, name))
        master = self._master_key(by)
        st, body = self.call("POST", "/api/credentials", {
            "nonce": f.b64url_encode(nonce), "name": name, "registration": reg,
            "wrapped_master_key": self._wrap(new, master), "assertion": assertion})
        if st == 201:
            self.creds.append(new)
        return st, body

    def delete_credential(self, target: SoftCredential, by: SoftCredential) -> tuple[int, dict]:
        return self.call("POST", f"/api/credentials/{f.b64url_encode(target.id)}/delete",
                         self.sign_op("delete-credential", by, target.id))

    def delete_item(self, name: str, by: SoftCredential | None = None) -> tuple[int, dict]:
        return self.call("POST", f"/api/items/{name}/delete", self.sign_op("delete-item", by or self.creds[0], name))
