"""HTTP plumbing shared by both doors: security headers, body limits, JSON responses, routing."""

from __future__ import annotations

import json
import re
import sys
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import parse_qs, urlsplit

from .config import MAX_BODY_BYTES

if TYPE_CHECKING:
    from .app import App

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class HttpError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


Route = tuple[str, re.Pattern[str], Callable[..., Any]]


class BaseHandler(BaseHTTPRequestHandler):
    server_version = "passkey-vault"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    routes: list[Route] = []
    app: "App"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - request line only, never bodies
        if self.app.config.access_log:
            sys.stderr.write(f"[{self.__class__.__name__}] {self.address_string()} {format % args}\n")

    # ---- responses ----
    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # If the request body was not fully read (errors etc.), close the connection so leftover
        # bytes cannot be parsed as the next request on a keep-alive connection.
        if self.close_connection or (self.command == "POST" and not self._body_read):
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status: int, obj: Any) -> None:
        self.send_bytes(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def send_error_json(self, status: int, code: str, message: str) -> None:
        self.close_connection = True
        self.send_json(status, {"error": code, "message": message})

    # ---- requests ----
    def read_json(self) -> Any:
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            raise HttpError(415, "unsupported_media_type", "Content-Type must be application/json")
        if self.headers.get("Transfer-Encoding"):
            raise HttpError(400, "bad_request", "Transfer-Encoding is not supported")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise HttpError(411, "length_required", "Content-Length is required") from None
        if length < 0 or length > MAX_BODY_BYTES:
            raise HttpError(413, "payload_too_large", f"body must be at most {MAX_BODY_BYTES} bytes")
        raw = self.rfile.read(length)
        self._body_read = True
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HttpError(400, "bad_request", "body is not valid JSON") from None

    def read_object(self) -> dict[str, Any]:
        body = self.read_json()
        if not isinstance(body, dict):
            raise HttpError(400, "bad_request", "body must be a JSON object")
        return body

    def query(self) -> dict[str, list[str]]:
        return parse_qs(urlsplit(self.path).query, keep_blank_values=True)

    def check_request(self) -> None:
        """Per-door checks (Host header, Origin, ...). Overridden by subclasses."""

    def dispatch(self) -> None:
        self._body_read = False
        try:
            self.check_request()
            path = urlsplit(self.path).path
            method = "GET" if self.command == "HEAD" else self.command
            path_matched = False
            for m, pattern, fn in self.routes:
                match = pattern.fullmatch(path)
                if not match:
                    continue
                path_matched = True
                if m == method:
                    fn(self, *match.groups())
                    return
            if path_matched:
                raise HttpError(405, "method_not_allowed", "method not allowed")
            raise HttpError(404, "not_found", "not found")
        except Exception as e:  # noqa: BLE001
            # HttpError and the domain errors (VaultError, QueueError) all carry status/code/message
            if all(hasattr(e, a) for a in ("status", "code", "message")):
                self.send_error_json(e.status, e.code, e.message)  # type: ignore[attr-defined]
            else:
                self.log_message("internal error: %r", e)
                self.send_error_json(500, "internal_error", "internal error")

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = dispatch  # type: ignore[assignment]

    def do_OPTIONS(self) -> None:  # never grant CORS preflights
        self._body_read = False
        self.send_error_json(405, "method_not_allowed", "method not allowed")
