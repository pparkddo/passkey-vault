"""The `pkv` CLI end to end: a real server, a fake approver, and `pkv` as a subprocess."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_server import SECRET, ServerTestBase  # noqa: E402

PKV = shutil.which("pkv") or "pkv"
SECRET_SHA = hashlib.sha256(SECRET.encode()).hexdigest()


class CliTests(ServerTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.init_vault()

    def pkv(self, *args: str, decide: str | None = "approve") -> subprocess.CompletedProcess:
        """Run pkv; meanwhile, approve or deny the request it creates (decide=None: do nothing)."""
        seen: dict = {}
        earlier = {p["id"] for p in self.approver.state()["pending"]}  # left over from previous calls

        def approver() -> None:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                pending = [p for p in self.approver.state()["pending"] if p["id"] not in earlier]
                if pending:
                    seen["command"] = pending[0]["command"]
                    req_id = pending[0]["id"]
                    if decide == "approve":
                        self.approver.approve(req_id)
                    else:
                        self.approver.deny(req_id)
                    return
                time.sleep(0.05)

        thread = threading.Thread(target=approver) if decide else None
        if thread:
            thread.start()
        env = {**os.environ, "PKV_SERVER": self.requester_url}
        result = subprocess.run([PKV, *args], env=env, capture_output=True, text=True, timeout=60)
        if thread:
            thread.join()
        result.shown = seen.get("command")  # type: ignore[attr-defined]
        return result

    def test_argv_mode_puts_the_secret_in_the_environment(self) -> None:
        code = 'import hashlib, os; print(hashlib.sha256(os.environ["PKV_SECRET"].encode()).hexdigest())'
        r = self.pkv("run", "github", "--key-bits", "2048", "--", sys.executable, "-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), SECRET_SHA)
        self.assertEqual(r.shown, f"{sys.executable} -c '{code}'", "the approver sees the exact argv, shell-quoted")
        self.assertIn("approve using github for this command: http://localhost:8740/approve?id=", r.stderr)
        self.assertNotIn(SECRET, r.stderr + r.stdout)

    def test_stdin_mode_and_custom_variable(self) -> None:
        code = "import hashlib, sys, os; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest(), 'PKV_SECRET' in os.environ)"
        r = self.pkv("run", "github", "--stdin", "--key-bits", "2048", "--", sys.executable, "-c", code)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), [SECRET_SHA, "False"])
        r = self.pkv("run", "github", "--env", "GH_TOKEN", "--key-bits", "2048", "--",
                     sys.executable, "-c", 'import os; print(len(os.environ["GH_TOKEN"]))')
        self.assertEqual(r.stdout.strip(), str(len(SECRET)))

    def test_shell_mode(self) -> None:
        command = f'printf %s "$PKV_SECRET" | {sys.executable} -c "import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"'
        r = self.pkv("run", "github", "--key-bits", "2048", "-c", command)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), SECRET_SHA)
        self.assertEqual(r.shown, command)

    def test_exit_codes(self) -> None:
        r = self.pkv("run", "github", "--key-bits", "2048", "--", "true", decide="deny")
        self.assertEqual(r.returncode, 3, r.stderr)
        r = self.pkv("run", "nope", "--", "true", decide=None)
        self.assertEqual(r.returncode, 5)
        self.assertIn("unknown_secret", r.stderr)
        r = self.pkv("run", "github", "--timeout", "1", "--key-bits", "2048", "--", "true", decide=None)
        self.assertEqual(r.returncode, 4)
        self.assertEqual(self.pkv("run", "github", decide=None).returncode, 2, "no command")
        self.assertEqual(self.pkv("run", "github", "-c", "true", "--", "true", decide=None).returncode, 2, "both forms")
        r = self.pkv("run", "github", "--key-bits", "2048", "--", "definitely-not-a-command-xyz")
        self.assertEqual(r.returncode, 127)

    def test_unreachable_server(self) -> None:
        env = {**os.environ, "PKV_SERVER": "http://127.0.0.1:9"}
        r = subprocess.run([PKV, "run", "github", "--", "true"], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 5)
        self.assertIn("cannot reach", r.stderr)


if __name__ == "__main__":
    unittest.main()
