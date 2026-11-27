"""pkv: run one command with one secret, after a passkey approval.

    pkv run github -- gh auth login --with-token          # argv, no shell
    pkv run github -c 'curl -u "me:$PKV_SECRET" https://example.com'   # through the shell
    pkv run github --stdin -- gh auth login --with-token  # secret on stdin instead of an env var

The approver sees the command exactly as it will run. The secret is put in the environment of that
one process (default variable PKV_SECRET) or written to its stdin, and nowhere else.
"""

from __future__ import annotations

import argparse
import os
import re
import shlex
import signal
import subprocess
import sys
from typing import NoReturn

from . import __version__
from .client import DEFAULT_URL, Client, PkvError, RequestDenied, RequestExpired, RequestTimeout

EXIT_DENIED = 3
EXIT_EXPIRED = 4  # expired or timed out
EXIT_ERROR = 5  # server, network or protocol error
EXIT_NOT_FOUND = 127
EXIT_INTERRUPTED = 130

ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
WINDOWS = os.name == "nt"


def _say(message: str) -> None:
    print(f"pkv: {message}", file=sys.stderr, flush=True)


def _env_name(value: str) -> str:
    if not ENV_NAME_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(f"not a valid environment variable name: {value!r}")
    return value


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkv", description="Use one passkey-vault secret for one command, after approval.")
    p.add_argument("--version", action="version", version=f"pkv {__version__}")
    sub = p.add_subparsers(dest="action", required=True)

    shell = "cmd /c" if WINDOWS else "/bin/sh -c"
    run = sub.add_parser(
        "run",
        help="request a secret and run one command with it",
        description="Request SECRET for one command, wait for approval, then run the command once.",
        epilog="Give the command after --, e.g.  pkv run github -- gh auth login --with-token",
    )
    run.add_argument("secret", help="name of the vault item")
    run.add_argument("-c", dest="shell_command", metavar="COMMAND", help=f"run COMMAND with {shell}")
    run.add_argument(
        "--server",
        default=os.environ.get("PKV_SERVER", DEFAULT_URL),
        help=f"requester endpoint (env PKV_SERVER, default {DEFAULT_URL})",
    )
    run.add_argument(
        "--env",
        type=_env_name,
        default="PKV_SECRET",
        metavar="NAME",
        help="environment variable that receives the secret (default PKV_SECRET)",
    )
    run.add_argument("--stdin", action="store_true", help="write the secret to the command's stdin instead")
    run.add_argument(
        "--timeout",
        type=float,
        default=330,
        metavar="SECONDS",
        help="give up waiting for a decision after this long (default 330)",
    )
    run.add_argument(
        "--key-bits",
        type=int,
        default=3072,
        choices=(2048, 3072, 4096),
        help="size of the one-time RSA key (default 3072)",
    )
    return p


def _command(args: argparse.Namespace, argv: list[str], parser: argparse.ArgumentParser) -> tuple[str, list[str]]:
    """Return (the command as shown to the approver, the argv to execute)."""
    if bool(argv) == bool(args.shell_command):
        parser.error("give the command either after -- or with -c, not both")
    if args.shell_command:
        shell = [os.environ.get("COMSPEC", "cmd.exe"), "/c"] if WINDOWS else ["/bin/sh", "-c"]
        return args.shell_command, [*shell, args.shell_command]
    return shlex.join(argv), argv


def _exec_with_env(argv: list[str], env: dict[str, str]) -> NoReturn:
    """Replace this process with the command: signals and the exit status are the command's own,
    and nothing of pkv (including its copy of the secret) outlives the exec."""
    try:
        os.execvpe(argv[0], argv, env)
    except FileNotFoundError:
        _say(f"command not found: {argv[0]}")
        raise SystemExit(EXIT_NOT_FOUND) from None


def _run_child(argv: list[str], env: dict[str, str] | None, stdin_data: bytes | None) -> int:
    """Run the command as a child, forwarding termination signals to it."""
    try:
        child = subprocess.Popen(argv, env=env, stdin=subprocess.PIPE if stdin_data is not None else None)
    except FileNotFoundError:
        _say(f"command not found: {argv[0]}")
        return EXIT_NOT_FOUND
    forwarded = [signal.SIGTERM, *([signal.SIGHUP] if hasattr(signal, "SIGHUP") else [])]
    previous = {s: signal.signal(s, lambda signum, _frame: child.send_signal(signum)) for s in forwarded}
    try:
        if stdin_data is not None:
            child.communicate(stdin_data)
        while True:
            try:
                return child.wait()
            except KeyboardInterrupt:  # Ctrl-C reaches the child through the terminal; keep waiting
                continue
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Everything after the first "--" is the command, verbatim; only what comes before is pkv's own.
    own, command = (argv[: argv.index("--")], argv[argv.index("--") + 1 :]) if "--" in argv else (argv, [])
    parser = _parser()
    args = parser.parse_args(own)
    shown, exec_argv = _command(args, command, parser)

    try:
        request = Client(args.server).request(args.secret, shown, key_bits=args.key_bits)
        _say(f"approve using {args.secret} for this command: {request.approve_url}")
        _say(f"waiting (the link expires at {request.expires_at})")
        secret = request.wait(timeout=args.timeout)
    except RequestDenied as e:
        _say(str(e))
        return EXIT_DENIED
    except (RequestExpired, RequestTimeout) as e:
        _say(str(e))
        return EXIT_EXPIRED
    except PkvError as e:
        _say(str(e))
        return EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED

    _say("approved; running the command once")
    if args.stdin:
        return _run_child(exec_argv, None, secret)
    env = {**os.environ, args.env: secret.decode("utf-8")}
    if WINDOWS:  # exec on Windows starts a new process and exits; a child behaves better there
        return _run_child(exec_argv, env, None)
    _exec_with_env(exec_argv, env)


if __name__ == "__main__":
    raise SystemExit(main())
