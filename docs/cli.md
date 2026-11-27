# `pkv` and the Python SDK

`pkv` is the requester side of passkey-vault. It asks the server for one secret for one command,
waits while you approve the request with a passkey, then runs that command once with the secret.

## Install

```sh
uv tool install passkey-vault-client
# or: pipx install passkey-vault-client
```

Requires Python 3.10 or later. The only dependency is `cryptography`.

## `pkv setup`

Run once on the machine where requesters run. It asks for the server URL and the requester token
(input hidden), checks both against the server, and saves them only if the check passes.

```sh
pkv setup                                                              # interactive: asks for both
PKV_TOKEN=<requester-token> pkv setup --server http://127.0.0.1:8741   # non-interactive (agents, scripts)
pkv setup --server http://<server-lan-ip>:8741 --token-stdin < token.txt
```

The URL is the server's **requester door** (port 8741 by default), not the approval page's address.
Without a terminal, `pkv setup` does not prompt: give the token in `PKV_TOKEN` or with `--token-stdin`.

The token is in the server's data directory: `docker compose exec passkey-vault cat /data/requester-token`,
or the value the operator configured.

Settings are read in this order: command-line option, environment (`PKV_SERVER`, `PKV_TOKEN`), the
config file, the default `http://127.0.0.1:8741`. The config file is
`$XDG_CONFIG_HOME/pkv/config.json` (usually `~/.config/pkv/config.json`; `%APPDATA%\pkv\config.json`
on Windows; `PKV_CONFIG` overrides the path), written with mode 0600.

## `pkv list`

```sh
pkv list            # NAME  SITE  ACCOUNT
pkv list --json
```

Shows what the vault holds. Never shows values; reading a value always goes through `pkv run` and an
approval.

## `pkv run`

```
pkv run [options] SECRET -- COMMAND [ARG...]
pkv run [options] SECRET -c 'SHELL COMMAND'
```

| Form | What runs | What the approver sees |
|---|---|---|
| `-- COMMAND [ARG...]` | the program directly, no shell | the arguments, shell-quoted (`shlex.join`) |
| `-c 'SHELL COMMAND'` | `/bin/sh -c` (`cmd /c` on Windows) | the string exactly as given |

Use `--` when you can; use `-c` when you need pipes, redirection or here-strings.

| Option | Default | Meaning |
|---|---|---|
| `--env NAME` | `PKV_SECRET` | environment variable that receives the secret |
| `--stdin` | off | write the secret to the command's stdin instead of an environment variable |
| `--server URL` | `$PKV_SERVER`, the config file, else `http://127.0.0.1:8741` | the server's requester endpoint |
| `--timeout SECONDS` | `330` | stop waiting for a decision after this long |
| `--key-bits N` | `3072` | size of the one-time RSA key (2048, 3072 or 4096) |

Everything after the first `--` belongs to the command, so options for `pkv` go before it.

`pkv` prints its progress, including the approval link, on stderr. The command's own stdout and stderr
pass through untouched.

With the secret in an environment variable, `pkv` replaces itself with the command (`exec`), so signals,
the exit status and the process ID are the command's own. With `--stdin` (and on Windows), the command
runs as a child; `pkv` forwards `SIGTERM` and `SIGHUP` to it and exits with its status.

Requests to a loopback server never go through `HTTP_PROXY`/`HTTPS_PROXY` from the environment.

### Exit codes

| Code | Meaning |
|---|---|
| the command's code | approved, and the command ran |
| 2 | usage error |
| 3 | the approver denied the request |
| 4 | the request expired, or `--timeout` passed |
| 5 | server, network or protocol error (for example `unknown_secret`) |
| 127 | the command was not found |
| 130 | interrupted |

## How the secret is handled

- A new RSA key pair is generated in memory for every request and dropped after decryption.
- The secret reaches only the one process you asked to run: through its environment (`--env`) or its
  stdin (`--stdin`). It is never printed, logged or written to disk by `pkv`.
- Anything that can inspect that process (the same user, root) can read the secret while it runs.
  `--stdin` avoids leaving it in the process environment.
- The approver sees the command exactly as it will run, and the ciphertext can only be decrypted for
  that exact command string (see the [requester interface](interface.md)).

## Python SDK

```python
from passkey_vault_client import Client, RequestDenied, RequestExpired

client = Client.from_config()  # PKV_SERVER / PKV_TOKEN, else what `pkv setup` saved
# or explicitly: Client("http://127.0.0.1:8741", token="<requester-token>")
request = client.request("github", "gh auth login --with-token")
print("Approve at", request.approve_url)

try:
    secret = request.wait(timeout=330)  # bytes
except (RequestDenied, RequestExpired):
    ...
```

| Name | Description |
|---|---|
| `Client(base_url, token=None, http_timeout=10)` | connection to the requester endpoint |
| `Client.from_config(server=None)` | a client configured like `pkv` (environment, then the config file) |
| `Client.list_secrets()` | the vault's items as `SecretInfo(name, site, account, updated_at)` |
| `Client.request(secret, command, key_bits=3072)` | create a request; returns an `ApprovalRequest` |
| `ApprovalRequest.approve_url`, `.expires_at`, `.id` | what to show the approver |
| `ApprovalRequest.poll(wait=30)` | one long poll; returns a `PollResult(status, ciphertext)` |
| `ApprovalRequest.wait(timeout=330)` | block until decided; returns the secret as bytes |
| `PkvError` | base class; `ServerError` (with `.status` and `.code`), `RequestDenied`, `RequestExpired`, `RequestTimeout` |

Only run the exact `command` string you passed to `request()`: the approver approved that string, and
the ciphertext is bound to it.
