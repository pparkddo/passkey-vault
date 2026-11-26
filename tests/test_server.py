"""Integration tests: real server (both doors) <-> reference requester <-> fake approver."""

from __future__ import annotations

import http.client
import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tests"))

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: E402

from passkey_vault import formats as f  # noqa: E402
from passkey_vault.app import App  # noqa: E402
from passkey_vault.config import Config  # noqa: E402
from passkey_vault.requests_queue import RequestQueue  # noqa: E402
from ref_client import OneShotRequest, RequesterError  # noqa: E402
from soft_approver import SoftAuthenticator, SoftApprover  # noqa: E402

ORIGIN = "http://localhost:8740"
SECRET = "correct horse battery staple ✓"
DUMMY_WRAPPED = {"iv": f.b64url_encode(bytes(12)), "ct": f.b64url_encode(bytes(48))}


def raw_request(port: int, method: str, path: str, body: bytes | None = None,
                headers: dict | None = None) -> tuple[int, dict, dict]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request(method, path, body=body, headers=headers or {})
    r = conn.getresponse()
    data = r.read()
    conn.close()
    try:
        parsed = json.loads(data) if data else {}
    except json.JSONDecodeError:
        parsed = {"_raw": data}
    return r.status, parsed, dict(r.getheaders())


def make_config(data_dir: Path, storage: str | None = None, origin: str = ORIGIN, approver_port: int = 0) -> Config:
    return Config(data_dir=data_dir, rp_id="localhost", origin=origin, storage=storage,
                  approver_port=approver_port, requester_port=0, dev=True, access_log=False)


class ServerTestBase(unittest.TestCase):
    storage: str | None = None

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.app = App(make_config(Path(self.tmp.name) / "data", self.storage))
        self.app.start()
        self.approver_port, self.requester_port = self.app.ports
        self.setup_code = self.app.vault.ensure_setup_code()
        self.approver = SoftApprover(f"http://127.0.0.1:{self.approver_port}", "localhost", ORIGIN)

    @property
    def requester_url(self) -> str:
        return f"http://127.0.0.1:{self.app.ports[1]}"

    def tearDown(self) -> None:
        self.app.stop()
        self.tmp.cleanup()

    def init_vault(self) -> None:
        st, body = self.approver.setup(self.setup_code)
        self.assertEqual(st, 201, body)
        st, body = self.approver.put_item("github", "github.com", "me@example.com", SECRET)
        self.assertEqual(st, 200, body)

    def new_request(self, command: str = "printenv PASSKEY_VAULT_SECRET", secret: str = "github",
                    bits: int = 2048) -> OneShotRequest:
        req = OneShotRequest(self.requester_url, secret, command, bits=bits)
        req.create()
        return req

    def approve_raw(self, req: OneShotRequest, cred, ciphertext: bytes) -> tuple[int, dict]:
        """Sign the real challenge with `cred` but upload an arbitrary ciphertext."""
        challenge = f.approve_challenge(req.id, req.secret, req.command, req.pubkey_der)
        return self.approver.call("POST", f"/api/requests/{req.id}/approve",
                                  {"assertion": self.approver.auth.get(cred, challenge),
                                   "ciphertext": f.b64url_encode(ciphertext)})


class SetupTests(ServerTestBase):
    def test_setup_requires_code(self) -> None:
        st, body = self.approver.setup("WRONG-CODE")
        self.assertEqual((st, body["error"]), (403, "bad_setup_code"))
        self.assertFalse(self.app.vault.initialized)
        st, body = self.approver.setup(self.setup_code.lower().replace("-", ""))  # case and dashes ignored
        self.assertEqual(st, 201, body)
        self.assertFalse(self.app.config.setup_code_path.exists(), "the setup code is deleted after use")
        self.assertEqual(self.approver.call("POST", "/api/nonce", {"op": "setup"})[0], 409)

    def test_setup_rejects_wrong_origin_and_missing_uv(self) -> None:
        for auth, origin in ((SoftAuthenticator("localhost", ORIGIN), "http://evil.localhost"),
                             (SoftAuthenticator("localhost", ORIGIN, uv=False), None)):
            nonce = self.approver.nonce("setup")
            _, reg = auth.create(f.op_challenge("register", nonce, "x"), origin=origin)
            st, body = self.approver.call("POST", "/api/setup", {
                "setup_code": self.setup_code, "nonce": f.b64url_encode(nonce), "name": "x",
                "registration": reg, "wrapped_master_key": DUMMY_WRAPPED})
            self.assertEqual((st, body["error"]), (400, "invalid_webauthn"))
        self.assertFalse(self.app.vault.initialized)

    def test_request_before_setup(self) -> None:
        with self.assertRaises(RequesterError) as cm:
            self.new_request()
        self.assertIn("vault_not_initialized", str(cm.exception))


class ApprovalFlowTests(ServerTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.init_vault()

    def test_full_flow_and_single_delivery(self) -> None:
        req = self.new_request()
        self.assertTrue(req.approve_url.startswith(f"{ORIGIN}/approve?id="))
        self.assertEqual(req.poll(wait=0), {"status": "pending"})
        st, body = self.approver.approve(req.id)
        self.assertEqual(st, 200, body)
        st, body, _ = raw_request(self.requester_port, "GET", f"/requests/{req.id}")
        self.assertEqual((st, body["status"]), (200, "approved"))
        self.assertEqual(req.decrypt(f.b64url_decode(body["ciphertext"])).decode(), SECRET)
        st, body, _ = raw_request(self.requester_port, "GET", f"/requests/{req.id}")
        self.assertEqual((st, body["error"]), (410, "consumed"), "the ciphertext is delivered once")

    def test_long_poll_wakes_on_approval(self) -> None:
        req = self.new_request(bits=3072)
        threading.Timer(0.3, lambda: self.approver.approve(req.id)).start()
        t0 = time.monotonic()
        self.assertEqual(req.wait_result().decode(), SECRET)
        self.assertLess(time.monotonic() - t0, 5)

    def test_wrong_label_cannot_decrypt(self) -> None:
        req = self.new_request(command="echo one")
        self.approver.approve(req.id)
        body = req.poll(0)
        req.command = "echo two"  # using the secret for another command changes the label
        with self.assertRaises(ValueError):
            req.decrypt(f.b64url_decode(body["ciphertext"]))

    def test_approval_bound_to_request_contents(self) -> None:
        req = self.new_request(command="echo safe")
        st, body = self.approver.approve(req.id, approve_with={"command": "echo other"})
        self.assertEqual((st, body["error"]), (400, "invalid_webauthn"), "a signature over another command")
        other = self.new_request()
        st, body = self.approver.approve(req.id, approve_with={"id": other.id})
        self.assertEqual((st, body["error"]), (400, "invalid_webauthn"), "a signature over another request")
        self.assertEqual(req.poll(0)["status"], "pending")

    def test_replayed_assertion_rejected(self) -> None:
        req = self.new_request()
        assertion = self.approver.auth.get(self.approver.creds[0], f.approve_challenge(req.id, "github", req.command, req.pubkey_der))
        req2 = self.new_request()
        st, _ = self.approver.call("POST", f"/api/requests/{req2.id}/approve",
                                {"assertion": assertion, "ciphertext": f.b64url_encode(bytes(256))})
        self.assertEqual(st, 400)

    def test_unknown_credential_rejected(self) -> None:
        req = self.new_request()
        stranger, _ = SoftAuthenticator("localhost", ORIGIN).create(b"x" * 32)
        st, body = self.approve_raw(req, stranger, bytes(256))
        self.assertEqual((st, body["error"]), (403, "unknown_credential"))

    def test_ciphertext_length_checked(self) -> None:
        req = self.new_request()
        self.assertEqual(self.approve_raw(req, self.approver.creds[0], bytes(100))[0], 400)

    def test_deny_is_final(self) -> None:
        req = self.new_request()
        self.assertEqual(self.approver.deny(req.id)[0], 200)
        self.assertEqual(req.poll(0), {"status": "denied"})
        self.assertEqual(self.approver.deny(req.id)[0], 409, "cannot deny twice")
        st, body = self.approve_raw(req, self.approver.creds[0], bytes(256))
        self.assertEqual((st, body["error"]), (409, "not_pending"), "cannot approve after deny")

    def test_expiry(self) -> None:
        now = [1000.0]
        self.app.queue = RequestQueue(self.app.audit, ttl=300, clock=lambda: now[0])
        req = self.new_request()
        now[0] += 301
        self.assertEqual(req.poll(0), {"status": "expired"})
        self.assertEqual(self.approver.deny(req.id)[0], 409)

    def test_approved_but_uncollected_expires(self) -> None:
        now = [1000.0]
        self.app.queue = RequestQueue(self.app.audit, ttl=300, clock=lambda: now[0])
        req = self.new_request()
        self.assertEqual(self.approver.approve(req.id)[0], 200)
        now[0] += 301
        self.assertEqual(req.poll(0), {"status": "expired"})

    def test_failed_audit_blocks_approval(self) -> None:
        req = self.new_request()
        sink = self.app.audit_sink
        original = sink.append

        def failing(record):
            if record["event"] == "request_approved":
                raise OSError("disk full")
            original(record)

        sink.append = failing
        try:
            self.assertEqual(self.approver.approve(req.id)[0], 500)
        finally:
            sink.append = original
        self.assertEqual(req.poll(0), {"status": "pending"}, "an approval that cannot be audited does not happen")
        self.assertEqual(self.approver.approve(req.id)[0], 200)

    def test_failed_send_keeps_ciphertext_for_retry(self) -> None:
        req = self.new_request()
        self.approver.approve(req.id)
        with self.assertRaises(BrokenPipeError):
            with self.app.queue.deliver(req.id, 0) as first:  # e.g. the requester disconnected
                self.assertEqual(first["status"], "approved")
                with self.app.queue.deliver(req.id, 0) as concurrent:
                    self.assertEqual(concurrent, {"status": "pending"}, "a concurrent poll waits")
                raise BrokenPipeError
        self.assertEqual(req.decrypt(f.b64url_decode(req.poll(0)["ciphertext"])).decode(), SECRET)
        self.assertEqual(raw_request(self.requester_port, "GET", f"/requests/{req.id}")[0], 410)

    def test_approval_with_zero_counter_writes_nothing(self) -> None:
        req = self.new_request()
        _, before = self.app.store.load()
        self.assertEqual(self.approver.approve(req.id)[0], 200)
        self.assertEqual(self.app.store.load()[1], before, "an unchanged counter does not rewrite the vault")

    def test_expires_in_follows_the_queue_clock(self) -> None:
        now = [1000.0]
        self.app.queue = RequestQueue(self.app.audit, ttl=300, clock=lambda: now[0])
        req = self.new_request()
        now[0] += 100
        self.assertEqual(self.approver.call("GET", f"/api/requests/{req.id}")[1]["expires_in"], 200)
        self.assertEqual(self.approver.state()["pending"][0]["expires_in"], 200)

    def test_expires_in_uses_server_clock(self) -> None:
        req = self.new_request()
        view = self.approver.call("GET", f"/api/requests/{req.id}")[1]
        self.assertTrue(295 <= view["expires_in"] <= 300)
        self.assertTrue(295 <= self.approver.state()["pending"][0]["expires_in"] <= 300)

    def test_too_many_pending(self) -> None:
        for _ in range(20):
            self.new_request()
        with self.assertRaises(RequesterError) as cm:
            self.new_request()
        self.assertIn("too_many_pending", str(cm.exception))

    def test_secrets_never_on_disk(self) -> None:
        req = self.new_request()
        self.approver.approve(req.id)
        req.wait_result()
        for p in self.app.config.data_dir.iterdir():
            self.assertNotIn(SECRET.encode(), p.read_bytes(), p.name)
            self.assertEqual(p.stat().st_mode & 0o077, 0, f"{p.name} must be owner-only")
        audit = [json.loads(line) for line in (self.app.config.data_dir / "audit.log").read_text().splitlines()]
        approved = [a for a in audit if a["event"] == "request_approved"]
        self.assertEqual(len(approved), 1)
        self.assertIn("signature", approved[0])
        self.assertIn("client_data_json", approved[0])
        self.assertTrue(any(a["event"] == "request_delivered" for a in audit))


class RequesterApiValidationTests(ServerTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.init_vault()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pub = f.b64url_encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                                 serialization.PublicFormat.SubjectPublicKeyInfo))

    def post(self, body: dict) -> tuple[int, dict]:
        return raw_request(self.requester_port, "POST", "/requests", json.dumps(body).encode(),
                           {"Content-Type": "application/json"})[:2]

    def test_errors(self) -> None:
        ok = {"secret": "github", "command": "ls", "pubkey": self.pub}
        spki = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        small = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key().public_bytes(*spki)
        ecpub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(*spki)
        cases = [
            ({**ok, "secret": "../x"}, 400, "invalid_secret_name"),
            ({**ok, "secret": "nope"}, 404, "unknown_secret"),
            ({**ok, "command": "a\nb"}, 400, "invalid_command"),
            ({**ok, "command": "echo \u202e"}, 400, "invalid_command"),
            ({**ok, "command": "echo \u061c\u200b"}, 400, "invalid_command"),
            ({**ok, "command": "\ud800"}, 400, "invalid_command"),
            ({**ok, "pubkey": "!!"}, 400, "invalid_pubkey"),
            ({**ok, "pubkey": f.b64url_encode(small)}, 400, "key_too_small"),
            ({**ok, "pubkey": f.b64url_encode(ecpub)}, 400, "invalid_pubkey"),
            ({"secret": "github"}, 400, "invalid_command"),
        ]
        for body, status, code in cases:
            st, resp = self.post(body)
            self.assertEqual((st, resp.get("error")), (status, code), body)
        self.assertEqual(self.post(ok)[0], 201)

    def test_host_content_type_and_limits(self) -> None:
        body = json.dumps({"secret": "github", "command": "ls", "pubkey": self.pub}).encode()
        json_ct = {"Content-Type": "application/json"}
        st, resp, _ = raw_request(self.requester_port, "POST", "/requests", body, {**json_ct, "Host": "evil.example:80"})
        self.assertEqual((st, resp["error"]), (421, "bad_host"))
        st, resp, _ = raw_request(self.requester_port, "POST", "/requests", body, {"Content-Type": "text/plain"})
        self.assertEqual((st, resp["error"]), (415, "unsupported_media_type"))
        st, resp, _ = raw_request(self.requester_port, "POST", "/requests", b"x" * 70000, json_ct)
        self.assertEqual((st, resp["error"]), (413, "payload_too_large"))
        self.assertEqual(raw_request(self.requester_port, "GET", "/requests/AAAAAAAAAAAAAAAAAAAAAA?wait=31")[0], 400)
        st, resp, _ = raw_request(self.requester_port, "GET", "/requests/AAAAAAAAAAAAAAAAAAAAAA")
        self.assertEqual((st, resp["error"]), (404, "not_found"))
        self.assertEqual(raw_request(self.requester_port, "DELETE", "/requests")[0], 405)

    def test_requester_door_has_no_approver_api(self) -> None:
        self.assertEqual(raw_request(self.requester_port, "GET", "/api/state")[0], 404)


class ApproverApiTests(ServerTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.init_vault()

    def test_static_and_headers(self) -> None:
        for path in ("/", "/approve", "/js/formats.js"):
            st, _, headers = raw_request(self.approver_port, "GET", path)
            self.assertEqual(st, 200, path)
            self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        for path in ("/../pyproject.toml", "/js/../../server/passkey_vault/vault.py", "/nope.js", "/.hidden"):
            self.assertEqual(raw_request(self.approver_port, "GET", path)[0], 404, path)

    def test_state_has_no_plaintext(self) -> None:
        st = self.approver.state()
        self.assertTrue(st["initialized"])
        self.assertEqual(st["items"][0]["name"], "github")
        self.assertNotIn(SECRET, json.dumps(st, ensure_ascii=False))

    def test_post_requires_origin(self) -> None:
        st, body = self.approver.call("POST", "/api/nonce", {"op": "put-item"}, origin=None)
        self.assertEqual((st, body["error"]), (403, "bad_origin"))
        self.assertEqual(self.approver.call("POST", "/api/nonce", {"op": "put-item"}, origin="https://evil.example")[0], 403)

    def test_put_item_needs_valid_assertion_and_nonce(self) -> None:
        st, body = self.approver.put_item("github", "github.com", "me", "x", tamper={"site": "evil.com"})
        self.assertEqual((st, body["error"]), (400, "invalid_webauthn"), "signed fields differ from sent fields")
        nonce = self.approver.nonce("put-item")
        a = self.approver.auth.get(self.approver.creds[0], f.op_challenge("put-item", nonce, "n", "s", "a"))
        body = {"nonce": f.b64url_encode(nonce), "name": "n", "site": "s", "account": "a",
                "iv": f.b64url_encode(bytes(12)), "ct": f.b64url_encode(bytes(32)), "assertion": a}
        self.assertEqual(self.approver.call("POST", "/api/items", body)[0], 200)
        self.assertEqual(self.approver.call("POST", "/api/items", body)[1]["error"], "invalid_nonce", "nonce reuse")
        body["nonce"] = f.b64url_encode(self.approver.nonce("delete-item"))
        self.assertEqual(self.approver.call("POST", "/api/items", body)[1]["error"], "invalid_nonce", "nonce of another op")

    def test_item_tamper_detected_by_approver(self) -> None:
        # Changing the displayed account in storage must make decryption in the approver fail.
        doc, rev = self.app.store.load()
        doc["items"]["github"]["account"] = "attacker@example.com"
        self.app.store.save(doc, rev)
        req = self.new_request()
        with self.assertRaises(InvalidTag):
            self.approver.approve(req.id)

    def test_credentials_add_use_delete(self) -> None:
        st, body = self.approver.add_credential("YubiKey")
        self.assertEqual(st, 201, body)
        first, second = self.approver.creds
        req = self.new_request()
        self.assertEqual(self.approver.approve(req.id, cred=second)[0], 200, "the new passkey can approve")
        self.assertEqual(req.wait_result().decode(), SECRET)
        self.assertEqual(self.approver.delete_credential(first, by=second)[0], 200)
        st, body = self.approver.delete_credential(second, by=second)
        self.assertEqual((st, body["error"]), (409, "last_credential"))
        st, body = self.approve_raw(self.new_request(), first, bytes(256))
        self.assertEqual((st, body["error"]), (403, "unknown_credential"), "a deleted passkey is useless")

    def test_add_credential_requires_existing_signature(self) -> None:
        nonce = self.approver.nonce("add-credential")
        new, reg = self.approver.auth.create(f.op_challenge("register", nonce, "evil"))
        a = self.approver.auth.get(new, f.op_challenge("add-credential", nonce, new.id, "evil"))  # self-signed
        st, body = self.approver.call("POST", "/api/credentials", {
            "nonce": f.b64url_encode(nonce), "name": "evil", "registration": reg,
            "wrapped_master_key": DUMMY_WRAPPED, "assertion": a})
        self.assertEqual((st, body["error"]), (403, "unknown_credential"))
        self.assertEqual(len(self.approver.state()["credentials"]), 1)

    def test_nonces_survive_floods_and_reject_forgery(self) -> None:
        nonces = self.app.nonces
        keep = nonces.issue("put-item")
        for _ in range(1000):
            nonces.issue("put-item")
        self.assertFalse(nonces.consume(keep, "delete-item"), "bound to its operation")
        self.assertFalse(nonces.consume(keep[:-1] + bytes([keep[-1] ^ 1]), "put-item"), "forged tag")
        self.assertTrue(nonces.consume(keep, "put-item"), "a flood does not evict an issued nonce")
        self.assertFalse(nonces.consume(keep, "put-item"), "single use")
        from passkey_vault.requests_queue import NonceStore

        now = [1000.0]
        short = NonceStore(ttl=10, clock=lambda: now[0])
        n = short.issue("setup")
        now[0] += 11
        self.assertFalse(short.consume(n, "setup"), "expired")

    def test_delete_item(self) -> None:
        self.assertEqual(self.approver.delete_item("github")[0], 200)
        self.assertEqual(self.approver.state()["items"], [])

    def test_keep_alive_after_post(self) -> None:
        # Regression: a POST whose body is not read must not corrupt the next request on the connection.
        req = self.new_request()
        conn = http.client.HTTPConnection("127.0.0.1", self.approver_port, timeout=10)
        conn.request("POST", f"/api/requests/{req.id}/deny", body=b"{}",
                     headers={"Content-Type": "application/json", "Origin": ORIGIN})
        r = conn.getresponse()
        r.read()
        self.assertEqual(r.status, 200)
        conn.request("POST", "/api/nonce", body=b"{}", headers={"Content-Type": "text/plain", "Origin": ORIGIN})
        r = conn.getresponse()
        r.read()
        self.assertEqual(r.status, 415)
        self.assertEqual(r.getheader("Connection"), "close", "error responses with an unread body close the connection")
        conn.close()

    def test_sign_count_regression_rejected(self) -> None:
        cred = self.approver.creds[0]
        cred.sign_count = 5
        self.assertEqual(self.approver.delete_item("github")[0], 200)
        cred.sign_count = 6
        self.assertEqual(self.approver.put_item("github", "github.com", "me", SECRET)[0], 200)
        cred.sign_count = 3  # counter went backwards: possible cloned authenticator
        st, body = self.approver.delete_item("github")
        self.assertEqual((st, body["error"]), (400, "invalid_webauthn"))


class ConfigTests(unittest.TestCase):
    def test_origin_is_normalized_like_browsers(self) -> None:
        from passkey_vault.config import normalize_origin, parse_args

        self.assertEqual(normalize_origin("https://Vault.Example.com:443/"), "https://vault.example.com")
        self.assertEqual(normalize_origin("https://vault.example.com:8443"), "https://vault.example.com:8443")
        cfg = parse_args(["--origin", "HTTPS://Vault.example.com:443", "--data-dir", "/tmp/x",
                          "--requester-hosts", "Vault.internal:8741, other"])
        self.assertEqual((cfg.origin, cfg.rp_id), ("https://vault.example.com", "vault.example.com"))
        self.assertEqual(cfg.requester_hosts, ("vault.internal", "other"))


class PersistenceTests(ServerTestBase):
    def test_restart_keeps_vault_and_drops_requests(self) -> None:
        self.init_vault()
        req = self.new_request()
        self.app.stop()
        self.app = App(self.app.config)
        self.app.start()
        self.approver_port, self.requester_port = self.app.ports
        self.approver.base = f"http://127.0.0.1:{self.approver_port}"
        self.assertTrue(self.app.vault.initialized)
        self.assertIsNone(self.app.vault.ensure_setup_code())
        req.base = self.requester_url
        with self.assertRaises(RequesterError):
            req.poll(0)
        req2 = self.new_request("true")
        self.assertEqual(self.approver.approve(req2.id)[0], 200)
        self.assertEqual(req2.wait_result().decode(), SECRET)

    def test_rp_id_mismatch_refuses_start(self) -> None:
        self.init_vault()
        cfg = Config(data_dir=self.app.config.data_dir, rp_id="other.example", origin="https://other.example",
                     approver_port=0, requester_port=0)
        with self.assertRaises(RuntimeError):
            App(cfg)


if __name__ == "__main__":
    unittest.main()
