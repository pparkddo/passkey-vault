"""pkv settings: where the server is and the requester token.

Precedence, highest first: command-line option, environment variable (PKV_SERVER, PKV_TOKEN), the
config file written by `pkv setup`, the built-in default.

The file is JSON so that it can be read on every supported Python (tomllib needs 3.11). It holds the
requester token, so it is written with mode 0600 inside a 0700 directory.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .client import DEFAULT_URL


def config_path() -> Path:
    if os.environ.get("PKV_CONFIG"):
        return Path(os.environ["PKV_CONFIG"])
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "pkv" / "config.json"


@dataclass(frozen=True)
class Settings:
    server: str = DEFAULT_URL
    token: str | None = None


def load_file() -> Settings | None:
    path = config_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    return Settings(server=data.get("server") or DEFAULT_URL, token=data.get("token") or None)


def resolve(server_option: str | None) -> Settings:
    saved = load_file() or Settings()
    return Settings(
        server=server_option or os.environ.get("PKV_SERVER") or saved.server,
        token=os.environ.get("PKV_TOKEN") or saved.token,
    )


def save(settings: Settings) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    body = json.dumps({"server": settings.server, "token": settings.token}, indent=2) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".config.", suffix=".tmp")  # created 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(body)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path
