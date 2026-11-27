"""pkv: run one command with one secret, after a passkey approval.

    pkv run github -- gh auth login --with-token          # argv, no shell
    pkv run github -c 'curl -u "me:$PKV_SECRET" https://example.com'   # through /bin/sh -c
    pkv run github --stdin -- gh auth login --with-token  # secret on stdin instead of an env var

The approver sees the command exactly as it will run. The secret is put in the environment of that
one process (default variable PKV_SECRET) or written to its stdin, and nowhere else.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys

from . import __version__
from .client import DEFAULT_URL, Client, PkvError, RequestDenied, RequestExpired, RequestTimeout

EXIT_DENIED = 3
EXIT_EXPIRED = 4  # expired or timed out
EXIT_ERROR = 5    # server, network or protocol error


def _say(message: str) -> None:
    print(f"pkv: {message}", file=sys.stderr, flush=True)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pkv", description="Use one passkey-vault secret for one command, after approval.")
    p.add_argument("--version", action="version", version=f"pkv {__version__}")
    sub = p.add_subparsers(dest="action", required=True)

    run = sub.add_parser("run", help="request a secret and run one command with it",
                         description="Request SECRET for one command, wait for approval, then run the command once.")
    run.add_argument("secret", help="name of the vault item")
    run.add_argument("-c", dest="shell_command", metavar="COMMAND", help="run COMMAND with /bin/sh -c")
    run.add_argument("--server", default=os.environ.get("PKV_SERVER", DEFAULT_URL),
                     help=f"requester endpoint (env PKV_SERVER, default {DEFAULT_URL})")
    run.add_argument("--env", default="PKV_SECRET", metavar="NAME",
                     help="environment variable that receives the secret (default PKV_SECRET)")
    run.add_argument("--stdin", action="store_true", help="write the secret to the command's stdin instead")
    run.add_argument("--timeout", type=float, default=330, metavar="SECONDS",
                     help="give up waiting for a decision after this long (default 330)")
    run.add_argument("--key-bits", type=int, default=3072, choices=(2048, 3072, 4096),
                     help="size of the one-time RSA key (default 3072)")
    run.epilog = "Give the command after --, e.g.  pkv run github -- gh auth login --with-token"
    return p


def _command(args: argparse.Namespace, argv: list[str], parser: argparse.ArgumentParser) -> tuple[str, list[str]]:
    """Return (the command as shown to the approver, the argv to execute)."""
    if bool(argv) == bool(args.shell_command):
        parser.error("give the command either after -- or with -c, not both")
    if args.shell_command:
        return args.shell_command, ["/bin/sh", "-c", args.shell_command]
    return shlex.join(argv), argv


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # Everything after the first "--" is the command, verbatim; only what comes before is pkv's own.
    own, command = (argv[:argv.index("--")], argv[argv.index("--") + 1:]) if "--" in argv else (argv, [])
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
        return 130

    _say("approved; running the command once")
    try:
        if args.stdin:
            return subprocess.run(exec_argv, input=secret).returncode
        env = {**os.environ, args.env: secret.decode("utf-8")}
        return subprocess.run(exec_argv, env=env).returncode
    except FileNotFoundError:
        _say(f"command not found: {exec_argv[0]}")
        return 127
    except KeyboardInterrupt:
        return 130
    finally:
        del secret


if __name__ == "__main__":
    raise SystemExit(main())
