"""Wires storage, vault, mailbox and the two HTTP doors together."""

from __future__ import annotations

import os
import sys
import threading
from http.server import ThreadingHTTPServer

from .audit import AuditLog
from .config import Config
from .approver_api import ApproverHandler, load_static
from .requester_api import RequesterHandler
from .requests_queue import NonceStore, RequestQueue
from .storage import open_storage
from .vault import Vault


class App:
    def __init__(self, config: Config) -> None:
        self.config = config
        config.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(config.data_dir, 0o700)
        self.store, self.audit_sink = open_storage(config.storage, config.data_dir)
        self.audit = AuditLog(self.audit_sink)
        self.vault = Vault(self.store, config.setup_code_path, config.rp_id)
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
        cfg, log = self.config, sys.stderr
        backend = (cfg.storage or "file").split(":", 1)[0]
        log.write(f"passkey-vault: rp_id={cfg.rp_id} origin={cfg.origin} storage={backend}\n")
        log.write(f"  approver door  http://{cfg.bind}:{self.ports[0]}  (put an HTTPS reverse proxy in front)\n")
        log.write(f"  requester door http://{cfg.bind}:{self.ports[1]}  (requesters only; never expose it)\n")
        code = self.vault.ensure_setup_code()
        if code:
            log.write(f"  no vault yet. setup code file: {cfg.setup_code_path}\n")
            if cfg.dev:
                log.write(f"  [dev] setup code: {code}\n")
        self.audit.write("server_started", rp_id=cfg.rp_id, origin=cfg.origin, initialized=self.vault.initialized)
        log.flush()
