"""Container tests: build the image and run the whole approval flow against `docker compose`.

    PV_DOCKER_TEST=1 uv run python -m unittest tests/test_docker.py -v

Needs a running Docker daemon and free ports 8740/8741. Uses its own compose project name and
removes its containers and volumes afterwards.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(ROOT / "tests"))

from ref_client import OneShotRequest  # noqa: E402
from soft_approver import SoftApprover  # noqa: E402

PROJECT = "passkey-vault-test"
ORIGIN = "http://localhost:8740"
SECRET = "container secret ✓"


def _compose_cmd() -> list[str]:
    """`docker compose` (plugin) if available, else the standalone `docker-compose`."""
    if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0:
        return ["docker", "compose"]
    return [shutil.which("docker-compose") or "docker-compose"]


def compose(*args: str, env: dict | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run([*_compose_cmd(), "-p", PROJECT, *args], cwd=ROOT, env={**os.environ, **(env or {})},
                          capture_output=True, text=True, check=check, timeout=900)


def wait_healthy(timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{ORIGIN}/api/state", timeout=2) as r:
                if r.status == 200:
                    return
        except OSError:
            pass
        time.sleep(1)
    raise AssertionError("server did not come up:\n" + compose("logs", check=False).stdout[-3000:])


@unittest.skipUnless(os.environ.get("PV_DOCKER_TEST") == "1", "set PV_DOCKER_TEST=1 (needs Docker)")
class DockerTests(unittest.TestCase):
    def run_flow(self, env: dict, profile: str | None = None) -> None:
        profile_args = ["--profile", profile] if profile else []
        try:
            compose(*profile_args, "up", "-d", "--build", env=env)
            wait_healthy()
            code = compose("exec", "-T", "passkey-vault", "cat", "/data/setup-code", env=env).stdout.strip()
            approver = SoftApprover(ORIGIN.replace("localhost", "127.0.0.1"), "localhost", ORIGIN)
            self.assertEqual(approver.setup(code)[0], 201)
            self.assertEqual(approver.put_item("github", "github.com", "me", SECRET)[0], 200)
            req = OneShotRequest("http://127.0.0.1:8741", "github", "echo from-container", bits=2048)
            req.create()
            self.assertEqual(approver.approve(req.id)[0], 200)
            self.assertEqual(req.wait_result().decode(), SECRET)

            # Hardening: unprivileged user, read-only root filesystem.
            self.assertEqual(compose("exec", "-T", "passkey-vault", "id", "-u", env=env).stdout.strip(), "10001")
            touch = compose("exec", "-T", "passkey-vault", "touch", "/app/server/x", env=env, check=False)
            self.assertNotEqual(touch.returncode, 0, "the image filesystem is read-only")
            ps = json.loads("[" + ",".join(compose("ps", "--format", "json", env=env).stdout.split("\n")[:-1]) + "]")
            self.assertTrue(any(c.get("Health") in ("healthy", "starting") for c in ps if c["Service"] == "passkey-vault"))
        finally:
            compose(*profile_args, "down", "-v", env=env, check=False)

    def test_file_storage(self) -> None:
        self.run_flow({"PASSKEY_VAULT_STORAGE": ""})

    def test_postgres_storage(self) -> None:
        self.run_flow({"POSTGRES_PASSWORD": "pvtest",
                       "PASSKEY_VAULT_STORAGE": "postgresql://passkey_vault:pvtest@postgres/passkey_vault"}, "postgres")

    def test_mongodb_storage(self) -> None:
        self.run_flow({"PASSKEY_VAULT_STORAGE": "mongodb://mongodb/passkey_vault"}, "mongodb")


if __name__ == "__main__":
    unittest.main()
