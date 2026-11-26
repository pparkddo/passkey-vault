"""The one error type the HTTP layer turns into a JSON error response."""

from __future__ import annotations


class ApiError(Exception):
    """An error with an HTTP status and a stable machine-readable code (see docs/interface.md)."""

    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
