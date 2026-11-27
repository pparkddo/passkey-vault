"""python -m passkey_vault [--dev | --origin https://... --data-dir ... [--storage URL]]"""

from __future__ import annotations

import logging
import os
import signal
import threading

from .app import App
from .config import parse_args


def main() -> None:
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = App(parse_args())
    app.vault.ensure_setup_code()  # exists before the server accepts connections (and before `up -d` returns usefully)
    app.start()
    app.announce()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    app.stop()


if __name__ == "__main__":
    main()
