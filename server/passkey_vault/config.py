"""Runtime configuration."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

REPO_WEB_DIR = Path(__file__).resolve().parents[2] / "web"

REQUEST_TTL_SECONDS = 300
NONCE_TTL_SECONDS = 300
MAX_PENDING_REQUESTS = 20
MAX_BODY_BYTES = 64 * 1024
MAX_WAIT_SECONDS = 30


@dataclass(frozen=True)
class Config:
    data_dir: Path
    rp_id: str
    origin: str
    storage: str | None = None  # None/"file", postgresql://..., mongodb://...
    requester_hosts: tuple[str, ...] = ()  # extra Host names accepted by the requester door
    approver_port: int = 8740
    requester_port: int = 8741
    bind: str = "127.0.0.1"
    web_dir: Path = REPO_WEB_DIR
    dev: bool = False
    access_log: bool = True

    @property
    def setup_code_path(self) -> Path:
        return self.data_dir / "setup-code"


def parse_args(argv: list[str] | None = None) -> Config:
    p = argparse.ArgumentParser(prog="passkey_vault", description="passkey-vault approval server")
    p.add_argument("--origin", help="origin the approval page is served from, e.g. https://vault.example.com")
    p.add_argument("--data-dir", type=Path,
                   help="directory for the setup code (and for the vault and audit log with file storage)")
    p.add_argument("--storage", default=None,
                   help="file (default), postgresql://... or mongodb://... ; also read from PASSKEY_VAULT_STORAGE "
                        "so that credentials stay out of the process list")
    p.add_argument("--requester-hosts", default=None,
                   help="comma-separated host names (besides loopback) that requesters use to reach the requester "
                        "door; also read from PASSKEY_VAULT_REQUESTER_HOSTS")
    p.add_argument("--bind", default="127.0.0.1",
                   help="address for both doors (default 127.0.0.1; use 0.0.0.0 only inside a container)")
    p.add_argument("--approver-port", type=int, default=8740)
    p.add_argument("--requester-port", type=int, default=8741)
    p.add_argument("--web-dir", type=Path, default=REPO_WEB_DIR)
    p.add_argument("--dev", action="store_true",
                   help="development mode: origin=http://localhost:<approver-port>, data-dir=./data, print the setup code")
    a = p.parse_args(argv)

    if a.dev:
        origin = a.origin or f"http://localhost:{a.approver_port}"
        data_dir = a.data_dir or Path("data")
    else:
        if not a.origin or not a.data_dir:
            p.error("--origin and --data-dir are required (use --dev for local development)")
        origin, data_dir = a.origin, a.data_dir

    parts = urlsplit(origin)
    if parts.scheme not in ("https", "http") or not parts.hostname or parts.path not in ("", "/"):
        p.error("--origin must look like https://host[:port]")
    if parts.scheme == "http" and parts.hostname != "localhost":
        p.error("an http origin is only allowed for localhost (WebAuthn needs a secure context)")
    return Config(
        data_dir=data_dir.resolve(), rp_id=parts.hostname, origin=origin.rstrip("/"),
        storage=a.storage or os.environ.get("PASSKEY_VAULT_STORAGE") or None,
        requester_hosts=tuple(h.strip().lower() for h in
                              (a.requester_hosts or os.environ.get("PASSKEY_VAULT_REQUESTER_HOSTS") or "").split(",")
                              if h.strip()),
        approver_port=a.approver_port, requester_port=a.requester_port, bind=a.bind, web_dir=a.web_dir.resolve(), dev=a.dev,
    )
