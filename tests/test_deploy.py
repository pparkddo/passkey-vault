"""Tests for the macOS deploy script in test mode (no root, chown or launchctl).

Downloads wheels from PyPI, so it is skipped unless enabled:

    PV_DEPLOY_TEST=1 uv run python -m unittest tests/test_deploy.py -v
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from support import free_port, wait_for_url  # noqa: E402
DEPLOY = ROOT / "deploy" / "macos" / "deploy.sh"
PLIST = ROOT / "deploy" / "macos" / "com.passkey-vault.server.plist"


def head() -> str:
    return subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()


@unittest.skipUnless(os.environ.get("PV_DEPLOY_TEST") == "1", "set PV_DEPLOY_TEST=1 (needs network)")
class DeployTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.prefix = Path(self.tmp.name) / "PasskeyVault"
        for d in ("releases", "venvs", "data", "logs", "bin"):
            (self.prefix / d).mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def deploy(self, commit: str) -> subprocess.CompletedProcess:
        env = {"PATH": "/usr/bin:/bin", "PV_TEST_MODE": "1", "PV_PREFIX": str(self.prefix),
               "PV_PYTHON": sys.executable, "PV_ASSUME_YES": "1"}
        return subprocess.run(["/bin/bash", str(DEPLOY), str(ROOT), commit], env=env,
                              capture_output=True, text=True, timeout=600)

    def test_deploy_and_run_like_launchd(self) -> None:
        commit = head()
        r = self.deploy(commit)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("first deployment", r.stdout)
        current = self.prefix / "current"
        self.assertEqual(os.readlink(current), f"releases/{commit}")
        self.assertTrue((current / "server/passkey_vault/app.py").is_file())
        self.assertFalse((current / "tests").exists(), "only server/, web/ and deploy/ are deployed")
        self.assertRegex(os.readlink(self.prefix / "venv"), r"^venvs/py3\.15-[0-9a-f]{16}$")
        self.assertIn(commit, (self.prefix / "deploy.log").read_text())

        # Same commit again: virtualenv reused, empty diff.
        r = self.deploy(commit)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("installing dependencies", r.stdout)
        self.assertIn("changed lines: 0", r.stdout)

        # Start the server exactly as the LaunchDaemon would.
        port = free_port()
        filled = (PLIST.read_text().replace("__PREFIX__", str(self.prefix)).replace("__SERVICE_USER__", "_passkeyvault")
                  .replace("__ORIGIN__", "https://vault.example.com")
                  .replace("<string>8740</string>", f"<string>{port}</string>")
                  .replace("<string>8741</string>", f"<string>{port + 1}</string>"))
        subprocess.run(["plutil", "-lint", "-"], input=filled.encode(), check=True, capture_output=True)
        plist = plistlib.loads(filled.encode())
        proc = subprocess.Popen(plist["ProgramArguments"], env=plist["EnvironmentVariables"],
                                cwd=plist["WorkingDirectory"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            body = wait_for_url(f"http://127.0.0.1:{port}/", timeout=10)
            self.assertIn(b"passkey-vault", body.lower())
            code_file = self.prefix / "data/setup-code"
            setup = code_file.read_text().strip()
            self.assertRegex(setup, r"^[A-Z2-9]{5}(-[A-Z2-9]{5}){3}$")
            self.assertEqual(code_file.stat().st_mode & 0o777, 0o600)
        finally:
            proc.terminate()
            out, _ = proc.communicate(timeout=10)
        self.assertNotIn(setup, out, "outside dev mode the setup code is never logged")
        self.assertFalse(list((current / "server").rglob("__pycache__")), "no bytecode is written into the release")

    def test_rejects_bad_input(self) -> None:
        self.assertNotEqual(self.deploy("HEAD").returncode, 0)
        self.assertNotEqual(self.deploy(head()[:12]).returncode, 0)
        self.assertNotEqual(self.deploy("0" * 40).returncode, 0)
        r = subprocess.run(["/bin/bash", str(DEPLOY), str(ROOT), head()], env={"PATH": "/usr/bin:/bin"},
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, "refuses to run when neither root nor in test mode")
        self.assertIn("root", r.stderr)


if __name__ == "__main__":
    unittest.main()
