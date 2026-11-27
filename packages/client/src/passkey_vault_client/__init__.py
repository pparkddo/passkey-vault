"""Requester SDK and `pkv` CLI for passkey-vault."""

from importlib.metadata import PackageNotFoundError, version

from .client import (
    DEFAULT_URL,
    ApprovalRequest,
    Client,
    PkvError,
    PollResult,
    RequestDenied,
    RequestExpired,
    RequestTimeout,
    SecretInfo,
    ServerError,
)

try:
    __version__ = version("passkey-vault-client")
except PackageNotFoundError:  # running from a source tree without installing
    __version__ = "0+unknown"

__all__ = [
    "DEFAULT_URL",
    "ApprovalRequest",
    "Client",
    "PkvError",
    "PollResult",
    "RequestDenied",
    "RequestExpired",
    "RequestTimeout",
    "SecretInfo",
    "ServerError",
    "__version__",
]
