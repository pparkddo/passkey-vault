"""E2E: real server + real approval page (web/) + Chromium virtual authenticators with PRF + reference requester.

    uv run python tests/e2e_virtual_authenticator.py
    PV_SCREENSHOTS=/tmp/shots uv run python tests/e2e_virtual_authenticator.py   # also save screenshots

Uses the Chromium that Playwright installed; set PV_CHROMIUM to pick an executable explicitly.
Virtual authenticators are not real devices; see docs/verification.md for manual device tests.
"""

from __future__ import annotations

import os
import re
import socket
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tests"))

from playwright.sync_api import Page, sync_playwright  # noqa: E402

from passkey_vault.app import App  # noqa: E402
from passkey_vault.config import Config  # noqa: E402
from ref_client import OneShotRequest, RequesterError  # noqa: E402

PASSWORD = "e2e-pässwörd-✓-0123"
TIMEOUT = 15_000
SHOTS = os.environ.get("PV_SCREENSHOTS")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def chromium_path() -> str | None:
    if os.environ.get("PV_CHROMIUM"):
        return os.environ["PV_CHROMIUM"]
    cache = Path.home() / "Library/Caches/ms-playwright"
    found = sorted(cache.glob("chromium-*/chrome-mac*/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing"))
    return str(found[-1]) if found else None  # None: let Playwright use its own default


def add_authenticator(page: Page, prf: bool = True, transport: str = "internal") -> tuple[object, str]:
    """transport="internal" plays a platform authenticator (phone/laptop), "usb" a security key.
    Chromium allows only one internal authenticator per environment."""
    cdp = page.context.new_cdp_session(page)
    cdp.send("WebAuthn.enable")
    res = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "ctap2Version": "ctap2_1", "transport": transport, "hasResidentKey": True,
        "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True, "hasPrf": prf}})
    return cdp, res["authenticatorId"]


def start_app(port: int, tmp: str) -> App:
    app = App(Config(data_dir=Path(tmp) / "data", rp_id="localhost", origin=f"http://localhost:{port}",
                     approver_port=port, requester_port=0, dev=True, access_log=False))
    app.start()
    return app


class E2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        port = free_port()
        cls.origin = f"http://localhost:{port}"
        cls.app = start_app(port, cls.tmp.name)
        cls.requester = f"http://127.0.0.1:{cls.app.ports[1]}"
        cls.setup_code = cls.app.vault.ensure_setup_code()
        cls.pw = sync_playwright().start()
        cls.browser = cls.pw.chromium.launch(executable_path=chromium_path(), headless=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.browser.close()
        cls.pw.stop()
        cls.app.stop()
        cls.tmp.cleanup()

    def setUp(self) -> None:
        # iPhone-sized viewport: the approval link is usually opened on a phone.
        self.context = self.browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
        self.page = self.context.new_page()
        self.page.set_default_timeout(TIMEOUT)
        self.console: list[str] = []
        self.page.on("console", lambda m: self.console.append(f"{m.type}: {m.text}"))
        self.page.on("pageerror", lambda e: self.console.append(f"pageerror: {e}"))
        # Test-only hook: call self.before_get right before navigator.credentials.get. Used only to choose
        # which of two virtual authenticators answers (like a person picking up another device).
        self.before_get = None
        self.page.expose_function("pvBeforeGet", lambda: self.before_get and self.before_get())
        self.page.add_init_script("""(() => {
            const orig = navigator.credentials.get.bind(navigator.credentials);
            navigator.credentials.get = async (opts) => { await window.pvBeforeGet(); return orig(opts); };
        })()""")

    def tearDown(self) -> None:
        problems = [m for m in self.console if "Content Security Policy" in m or "pageerror" in m]
        self.context.close()
        self.assertEqual(problems, [], "no CSP violations or page errors")

    def shot(self, name: str) -> None:
        if SHOTS:
            Path(SHOTS).mkdir(parents=True, exist_ok=True)
            self.page.screenshot(path=f"{SHOTS}/{name}.png", full_page=True)

    def status(self, pattern: str) -> None:
        loc = self.page.locator("#status .notice").filter(has_text=re.compile(pattern))
        try:
            loc.wait_for()
        except Exception:  # noqa: BLE001
            shown = self.page.locator("#status").inner_text(timeout=1000)
            self.fail(f"waited for status {pattern!r}, page shows {shown!r}; console: {self.console}")

    def request(self, command: str) -> tuple[OneShotRequest, dict, threading.Thread]:
        req = OneShotRequest(self.requester, "github", command, bits=2048)
        req.create()
        result: dict = {}

        def wait() -> None:
            try:
                result["secret"] = req.wait_result(total_timeout=60).decode()
            except RequesterError as e:
                result["error"] = str(e)

        t = threading.Thread(target=wait)
        t.start()
        return req, result, t

    def test_full_flow(self) -> None:
        page = self.page
        cdp, auth_a = add_authenticator(page)

        # 1) first-time setup
        page.goto(self.origin + "/")
        self.shot("01-setup")
        page.fill("#setup-code", self.setup_code)
        page.fill("#setup-name", "Laptop")
        page.click("#f-setup button[type=submit]")
        self.status("Vault created")
        self.assertTrue(self.app.vault.initialized)
        self.assertFalse(page.locator("#passkey-advice").is_hidden(), "with one passkey, suggest adding another")

        # 2) add a secret
        page.click("#item-panel summary")
        page.fill("#item-name", "github")
        page.fill("#item-site", "github.com")
        page.fill("#item-account", "me@example.com")
        page.fill("#item-secret", PASSWORD)
        page.click("#f-item button[type=submit]")
        self.status("Saved github")
        self.assertEqual(page.input_value("#item-secret"), "", "the password field is cleared")
        disk = b"".join(p.read_bytes() for p in self.app.config.data_dir.iterdir())
        self.assertNotIn(PASSWORD.encode(), disk)

        # 3) approve: reference requester -> approval page -> decrypt
        req, result, t = self.request("gh auth login --with-token <<< \"$PASSKEY_VAULT_SECRET\"")
        page.goto(self.origin + "/")
        page.locator("#pending-list a").first.wait_for()
        self.shot("02-manage")
        page.goto(req.approve_url)
        self.assertEqual(page.inner_text("#r-command"), req.command)
        self.assertEqual(page.inner_text("#r-site"), "github.com")
        self.assertEqual(page.inner_text("#r-account"), "me@example.com")
        self.shot("03-approve")
        page.click("#b-approve")
        self.status("Approved")
        self.shot("04-approved")
        t.join(30)
        self.assertEqual(result, {"secret": PASSWORD})

        page.goto(req.approve_url)
        self.status("already")
        self.assertTrue(page.locator("#decision").is_hidden(), "a used request cannot be approved again")

        # 4) deny
        req, result, t = self.request("echo denied")
        page.goto(req.approve_url)
        page.click("#b-deny")
        self.status("Denied")
        t.join(30)
        self.assertIn("denied", result.get("error", ""))

        # 5) add a second passkey (a security key), then approve with it alone.
        #    With two virtual authenticators, Chromium lets the one with presence simulation answer, so step 1
        #    (create) may use B, and step 2 (confirm with an existing passkey) must use A.
        _, auth_b = add_authenticator(page, transport="usb")
        presence = lambda aid, on: cdp.send("WebAuthn.setAutomaticPresenceSimulation", {"authenticatorId": aid, "enabled": on})  # noqa: E731
        self.before_get = lambda: presence(auth_b, False)
        page.goto(self.origin + "/")
        page.click("#passkeys summary")
        page.fill("#passkey-name", "Security key")
        page.click("#f-passkey button[type=submit]")
        self.status("Added passkey")
        self.before_get = None
        presence(auth_b, True)
        self.assertEqual([c["name"] for c in self.app.vault.snapshot()["credentials"]], ["Laptop", "Security key"])
        cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": auth_a})  # the first device is lost
        req, result, t = self.request("echo with-the-second-passkey")
        page.goto(req.approve_url)
        page.click("#b-approve")
        self.status("Approved")
        t.join(30)
        self.assertEqual(result, {"secret": PASSWORD}, "the second passkey alone opens the vault (recovery)")

        # 6) tampered storage (displayed account changed) -> decryption fails in the browser
        doc, rev = self.app.store.load()
        doc["items"]["github"]["account"] = "attacker@example.com"
        self.app.store.save(doc, rev)
        req, result, t = self.request("echo tampered")
        page.goto(req.approve_url)
        page.click("#b-approve")
        self.status("Decryption failed")
        self.assertEqual(req.poll(0)["status"], "pending", "a tampered item is never approved")
        page.click("#b-deny")
        t.join(30)

    def test_prf_unsupported_authenticator_rejected(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        port = free_port()
        app = start_app(port, tmp.name)
        try:
            add_authenticator(self.page, prf=False)
            self.page.goto(f"http://localhost:{port}/")
            self.page.fill("#setup-code", app.vault.ensure_setup_code())
            self.page.click("#f-setup button[type=submit]")
            self.status("PRF")
            self.assertFalse(app.vault.initialized)
        finally:
            app.stop()
            tmp.cleanup()

    def test_bad_link(self) -> None:
        self.page.goto(self.origin + "/approve?id=../../x")
        self.status("incomplete")

    def test_csp_blocks_inline_script(self) -> None:
        resp = self.page.goto(self.origin + "/approve")
        self.assertIn("script-src 'self'", resp.headers["content-security-policy"])
        ran = self.page.evaluate("""() => {
            const s = document.createElement('script');
            s.textContent = 'window.__inlineRan = true';
            document.body.append(s);
            return window.__inlineRan === true;
        }""")
        self.assertFalse(ran, "inline scripts are blocked by the CSP")
        self.assertTrue(any("Content Security Policy" in m for m in self.console), "the browser reports the block")
        self.console.clear()  # the expected CSP report


if __name__ == "__main__":
    unittest.main(verbosity=2)
