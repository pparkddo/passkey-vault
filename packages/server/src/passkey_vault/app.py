"""Wires storage, vault, mailbox and the two HTTP doors together."""

from __future__ import annotations

import logging
import os
import secrets
import threading
from http.server import ThreadingHTTPServer

from .approver_api import ApproverHandler, load_static
from .audit import AuditLog
from .config import Config
from .requester_api import RequesterHandler
from .requests_queue import NonceStore, RequestQueue
from .storage import atomic_write, open_storage
from .vault import Vault

log = logging.getLogger(__name__)

MIN_TOKEN_LENGTH = 32


def load_requester_token(config: Config) -> str | None:
    """The token requesters must send, or None when requester authentication is turned off.

    An explicitly configured token wins; otherwise one is generated on first start and kept in the data
    directory (mode 0600), like the setup code."""
    if not config.requester_auth:
        return None
    if config.requester_token:
        if len(config.requester_token) < MIN_TOKEN_LENGTH:
            raise ValueError(f"the requester token must be at least {MIN_TOKEN_LENGTH} characters")
        return config.requester_token
    path = config.requester_token_path
    if path.exists():
        return path.read_text(encoding="ascii").strip()
    token = "pkvr_" + secrets.token_urlsafe(32)
    atomic_write(path, (token + "\n").encode("ascii"))
    return token


class App:
    def __init__(self, config: Config) -> None:
        self.config = config
        config.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(config.data_dir, 0o700)
        self.store, self.audit_sink = open_storage(config.storage, config.data_dir)
        self.audit = AuditLog(self.audit_sink)
        self.vault = Vault(self.store, config.setup_code_path, config.rp_id)
        self.requester_token = load_requester_token(config)
        self.queue = RequestQueue(self.audit)
        self.nonces = NonceStore()
        self.static = load_static(config.web_dir)
        self.servers: list[ThreadingHTTPServer] = []

    def _make_server(self, handler: type, port: int) -> ThreadingHTTPServer:
        bound = type(handler.__name__, (handler,), {"app": self})
        srv = ThreadingHTTPServer((self.config.bind, port), bound)
        srv.daemon_threads = True
        return srv

    def start(self) -> None:
        """Serve both doors on background threads (used by main and by tests)."""
        self.servers = [
            self._make_server(ApproverHandler, self.config.approver_port),
            self._make_server(RequesterHandler, self.config.requester_port),
        ]
        for srv in self.servers:
            threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()

    @property
    def ports(self) -> tuple[int, int]:
        return self.servers[0].server_address[1], self.servers[1].server_address[1]

    def stop(self) -> None:
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()
        self.store.close()
        self.audit_sink.close()

    def announce(self) -> None:
        cfg = self.config
        backend = (cfg.storage or "file").split(":", 1)[0]
        log.info("passkey-vault: rp_id=%s origin=%s storage=%s", cfg.rp_id, cfg.origin, backend)
        log.info("approver door  http://%s:%d (serve it through an HTTPS reverse proxy)", cfg.bind, self.ports[0])
        hosts = ", ".join(cfg.requester_hosts) or "loopback only"
        log.info("requester door http://%s:%d (accepted host names: %s)", cfg.bind, self.ports[1], hosts)
        if self.requester_token is None:
            log.warning("requester token disabled: anyone who can reach the requester door can create requests")
        elif cfg.requester_token:
            log.info("requester token: taken from the configuration")
        else:
            log.info("requester token file: %s", cfg.requester_token_path)
            if cfg.dev:
                log.info("[dev] requester token: %s", self.requester_token)
        code = self.vault.ensure_setup_code()
        if code:
            log.info("no vault yet; setup code file: %s", cfg.setup_code_path)
            if cfg.dev:
                log.info("[dev] setup code: %s", code)
        self.audit.record("server_started", rp_id=cfg.rp_id, origin=cfg.origin, initialized=self.vault.initialized)
