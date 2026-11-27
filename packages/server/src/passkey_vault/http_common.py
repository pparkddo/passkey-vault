"""HTTP plumbing shared by both doors: security headers, body limits, JSON responses, routing."""

from __future__ import annotations

import json
import logging
import re
from http.server import BaseHTTPRequestHandler
from typing import TYPE_CHECKING, Any, Callable, ClassVar
from urllib.parse import parse_qs, urlsplit

from .config import MAX_BODY_BYTES
from .errors import ApiError
from .formats import REQUEST_ID_RE, SECRET_NAME_RE

if TYPE_CHECKING:
    from .app import App

access_log = logging.getLogger("passkey_vault.access")
log = logging.getLogger(__name__)
SOCKET_TIMEOUT = 30  # seconds per socket read/write; bounds slow or idle clients (long polls wait in-process)

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

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

Route = tuple[str, re.Pattern[str], Callable[..., Any]]


def require_secret_name(value: object, field: str = "secret") -> str:
    if not isinstance(value, str) or not SECRET_NAME_RE.fullmatch(value):
        raise ApiError(400, "invalid_secret_name", f"{field} must match {SECRET_NAME_RE.pattern}")
    return value


def require_request_id(value: str) -> str:
    if not REQUEST_ID_RE.fullmatch(value):
        raise ApiError(404, "not_found", "no such request")
    return value


class BaseHandler(BaseHTTPRequestHandler):
    server_version = "passkey-vault"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    routes: ClassVar[list[Route]] = []
    app: "App"
    timeout = SOCKET_TIMEOUT

    def log_message(self, format: str, *args: Any) -> None:
        if self.app.config.access_log:
            access_log.info("%s %s %s", self.__class__.__name__, self.address_string(), format % args)

    # ---- responses ----
    def _unread_body(self) -> bool:
        """True if the client sent a body that was not read. On a keep-alive connection its bytes
        would be parsed as the next request, so such responses close the connection."""
        if getattr(self, "_body_read", False):
            return False
        return bool(self.headers.get("Transfer-Encoding")) or self.headers.get("Content-Length", "0").strip() not in (
            "",
            "0",
        )

    def send_bytes(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if self.close_connection or self._unread_body():
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
            raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json")
        if self.headers.get("Transfer-Encoding"):
            raise ApiError(400, "bad_request", "Transfer-Encoding is not supported")
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            raise ApiError(411, "length_required", "Content-Length is required") from None
        if length < 0 or length > MAX_BODY_BYTES:
            raise ApiError(413, "payload_too_large", f"body must be at most {MAX_BODY_BYTES} bytes")
        raw = self.rfile.read(length)
        self._body_read = True
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ApiError(400, "bad_request", "body is not valid JSON") from None

    def read_object(self) -> dict[str, Any]:
        body = self.read_json()
        if not isinstance(body, dict):
            raise ApiError(400, "bad_request", "body must be a JSON object")
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
                raise ApiError(405, "method_not_allowed", "method not allowed")
            raise ApiError(404, "not_found", "not found")
        except ApiError as e:
            self.send_error_json(e.status, e.code, e.message)
        except Exception:
            log.exception("internal error handling %s %s", self.command, urlsplit(self.path).path)
            self.send_error_json(500, "internal_error", "internal error")

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = dispatch

    def do_OPTIONS(self) -> None:  # never grant CORS preflights
        self.send_error_json(405, "method_not_allowed", "method not allowed")
