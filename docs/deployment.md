# Deployment

## Checklist

- [ ] The server runs where requesters cannot modify it (see [the requirement](threat-model.md#deployment-requirement)).
- [ ] An HTTPS reverse proxy serves the approval origin and forwards to the approver door (8740).
- [ ] Nothing else is hosted on that host name.
- [ ] The requester door (8741) is reachable only by requesters: loopback, or a private network.
- [ ] Storage is chosen and backed up (backups contain ciphertext only).
- [ ] At least two passkeys are registered.

## Run with Docker

```sh
PASSKEY_VAULT_ORIGIN=https://vault.example.com docker compose up -d
docker compose exec passkey-vault cat /data/setup-code     # one-time setup code
```

The image runs as an unprivileged user on a read-only filesystem and writes only to the `/data`
volume. Dependencies are installed from hash-pinned lock files, wheels only. Both ports are published
on `127.0.0.1`.

Other storage backends:

```sh
POSTGRES_PASSWORD=change-me \
PASSKEY_VAULT_STORAGE=postgresql://passkey_vault:change-me@postgres/passkey_vault \
  docker compose --profile postgres up -d

PASSKEY_VAULT_STORAGE=mongodb://mongodb/passkey_vault \
  docker compose --profile mongodb up -d
```

Or point `PASSKEY_VAULT_STORAGE` at an existing database. With a database backend, `/data` still
holds the setup code until setup is complete. The server may restart a few times while the database
starts. Run a single server instance per vault: pending requests live in its memory.

## Run without Docker

```sh
uv tool install "passkey-vault-server[postgres,mongodb] @ git+https://github.com/pparkddo/passkey-vault#subdirectory=packages/server"
passkey-vault --origin https://vault.example.com --data-dir /var/lib/passkey-vault
```

Drop `[postgres,mongodb]` if you use file storage.

| Option | Environment | Default |
|---|---|---|
| `--origin` | | required (except with `--dev`) |
| `--data-dir` | | required (except with `--dev`) |
| `--storage` | `PASSKEY_VAULT_STORAGE` | file storage in the data directory |
| `--requester-hosts` | `PASSKEY_VAULT_REQUESTER_HOSTS` | loopback only |
| `--bind` | | `127.0.0.1` |
| `--approver-port`, `--requester-port` | | 8740, 8741 |
| `--dev` | | origin `http://localhost:8740`, data in `./data`, setup code printed |

Prefer the environment variable for `--storage` so database credentials do not appear in the process
list.

## HTTPS reverse proxy

WebAuthn needs a secure origin, and the passkeys you register are bound to its host name (the RP ID).
Choose the host name once: changing it later means registering new passkeys. Any reverse proxy works;
it only needs to forward to the approver door. For example, with Caddy:

```
vault.example.com {
	reverse_proxy 127.0.0.1:8740
}
```

Keep the proxy configuration, certificate and DNS name out of the requester's reach, and do not serve
anything else on the same host name.

## Requesters on other hosts

The requester door is loopback-only by default. To let requesters on other machines reach it:

1. Publish port 8741 on a private interface (`--bind` or `PASSKEY_VAULT_PUBLISH` for Compose).
2. List the host names they use in `--requester-hosts` / `PASSKEY_VAULT_REQUESTER_HOSTS`.
3. Prefer a private network or TLS between requesters and the server. The door releases nothing on
   its own (only ciphertext for a one-time key, after approval), but there is no reason to expose it
   publicly.

## First-time setup

1. Read the setup code from the data directory (`setup-code`).
2. Open the origin in the browser you will approve with. Enter the code and create the first passkey.
3. Add a second passkey (for example a security key) and keep it somewhere safe.
4. Add secrets. They are encrypted in the browser before they are uploaded.

## Updating

Deploy a specific, reviewed version: a commit hash or an image digest, not "latest". The approval page
is security-critical code: review its diff before deploying.

## Same host as the requester

If the server runs on the same machine as the requester (for example, an AI agent that uses your user
account on your laptop), the requirement above means:

- The server runs as a **separate OS user**, started by the system service manager, which the
  requester's account cannot stop or modify.
- The code, the approval page, the Python interpreter and the dependencies are **not writable** by the
  requester's account. Homebrew or user-installed interpreters are not acceptable.
- The requester's account cannot control the service manager, the reverse proxy, or a container
  runtime that runs the server.
- Updates are copied in by an administrator after reviewing the exact files that will be deployed.

### macOS example

[`deploy/macos/`](../deploy/macos) implements this with a role account, a LaunchDaemon and a deploy
gate that shows the file-level diff and asks for the commit hash before switching releases.

1. Install Python 3.15 with the python.org installer, then make it root-only:
   `sudo chown -R root:wheel /Library/Frameworks/Python.framework/Versions/3.15 && sudo chmod -R go-w /Library/Frameworks/Python.framework/Versions/3.15`
2. Read [`install.sh`](../deploy/macos/install.sh) and [`deploy.sh`](../deploy/macos/deploy.sh), then run
   `sudo bash deploy/macos/install.sh https://vault.example.com`.
3. Deploy a reviewed commit with the installed, root-owned copy:
   `sudo /Library/PasskeyVault/bin/deploy /path/to/passkey-vault <40-character commit>`.
4. Read the setup code with `sudo cat /Library/PasskeyVault/data/setup-code`.
5. Never allow passwordless `sudo` for the requester's account.

The example installs only the core dependencies (`deploy/requirements.lock`), so it uses file storage.

`deploy.sh` runs `git` as the invoking user (never as root), refuses symlinks in the archive, checks
that the interpreter is root-owned, builds a virtualenv per lock-file hash, and keeps old releases for
rollback (deploy an older commit).
