<div align="center">

# passkey-vault

**Give an agent one secret, for one command, after you approve it with a passkey.**

[![CI](https://github.com/pparkddo/passkey-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/pparkddo/passkey-vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PyPI: passkey-vault-client](https://img.shields.io/pypi/v/passkey-vault-client?label=pkv)](https://pypi.org/project/passkey-vault-client/)
[![PyPI: passkey-vault-server](https://img.shields.io/pypi/v/passkey-vault-server?label=server)](https://pypi.org/project/passkey-vault-server/)

[Quick start](#quick-start) · [How it works](#how-it-works) · [Documentation](#documentation) · [Security](#security)

</div>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/approve-dark.png">
    <img src="docs/images/approve-light.png" alt="Approval screen showing the secret, site, account and the exact command" width="300">
  </picture>
</p>

## Why

AI agents and scripts need credentials, but handing them a password manager session hands them
everything. passkey-vault releases secrets one at a time, and only when you say so:

- **You approve every use** with a passkey (Face ID, Touch ID, a security key).
- **You see exactly what runs.** The approval screen shows the secret, site, account and full command.
- **One approval, one use.** The secret is encrypted to a one-time key bound to that request and that
  command, and delivered once.
- **The server never sees a secret.** Decryption keys come from your passkey through the WebAuthn PRF
  extension and never leave your browser. A stolen database holds ciphertext only.

## Features

- Small Python server with no web framework; approval page with no build step and a strict CSP
- File, PostgreSQL or MongoDB storage
- Multiple passkeys per vault; a second passkey is your recovery
- Hash-pinned dependencies and a non-root, read-only container image
- Documented requester API ([OpenAPI](docs/openapi/requester.yaml)) with cross-language test vectors

## How it works

```mermaid
sequenceDiagram
    participant R as Requester (agent / CLI)
    participant S as passkey-vault server
    participant B as Your browser
    R->>R: Generate one-time RSA key pair
    R->>S: POST /requests {secret, command, pubkey}
    S-->>R: approve_url (valid 5 minutes)
    R-->>B: You open approve_url
    B->>S: Load request and encrypted item
    B->>B: Approve with passkey: PRF unlocks the master key,<br/>decrypt this item, re-encrypt to the requester's key
    B->>S: Signed approval + ciphertext
    R->>S: GET /requests/{id}?wait=30
    S-->>R: Ciphertext, exactly once
    R->>R: Decrypt, run the command once, discard
```

Read the [design](docs/design.md) for the cryptography and the [threat model](docs/threat-model.md)
for what it does and does not protect against.

## Quick start

Requirements: Docker, [uv](https://docs.astral.sh/uv/), and a browser plus passkey provider that
support the WebAuthn PRF extension (check yours with [`tools/prf-test.html`](tools/prf-test.html)).

**1. Start the server**

```sh
git clone https://github.com/pparkddo/passkey-vault && cd passkey-vault
docker compose up -d
docker compose exec passkey-vault cat /data/setup-code        # for the approval page
docker compose exec passkey-vault cat /data/requester-token   # for pkv
```

Open <http://localhost:8740>, enter the setup code, create your passkey and add a secret named `github`.
To use the published image instead of building one, start it with
`PASSKEY_VAULT_IMAGE=ghcr.io/pparkddo/passkey-vault:0.1.0 docker compose up -d --no-build`.

**2. Install and set up `pkv`** on the machine where your agent or scripts run

```sh
uv tool install passkey-vault-client       # or: pipx install passkey-vault-client
pkv setup        # server URL and requester token; checked before saving
pkv list         # what the vault holds (names only)
```

**3. Use a secret**

```sh
pkv run github --stdin -- gh auth login --with-token   # gh reads the token from stdin
```

`pkv` prints an approval link and waits. Open it, check the command, approve with your passkey, and
`pkv` runs the command once with the secret on its stdin (or in `$PKV_SECRET` without `--stdin`).

For real use, serve the approval page over HTTPS and run the server where requesters cannot modify
it. See [deployment](docs/deployment.md).

## Use cases

### Let an AI agent sign in without seeing your password store

Tell the agent how to ask, for example in `AGENTS.md` or `CLAUDE.md`:

```markdown
When a command needs a password or token, do not ask me for it. `pkv list` shows the available
secret names. Run the command through pkv:

    pkv run <secret-name> --stdin -- <command that reads the secret from stdin>
    pkv run <secret-name> -c '<shell command that uses "$PKV_SECRET">'

pkv prints an approval link on stderr. Show me that link and wait; I approve it on my phone.
Exit code 3 means I denied it: do not retry without asking.
```

The agent never holds a long-lived credential. Each use is a separate request that shows you the exact
command, and the secret goes only to that one process.

### Approve from your phone while you are away

Serve the approval page on an HTTPS name your phone can reach (your own domain, or a private network
you already use). The agent's message carries the link; tapping it opens the request, and Face ID or
Touch ID approves it. Nothing needs to be installed on the phone.

### Scripts and scheduled jobs that should not hold a token

```sh
pkv run backup-token --timeout 600 -c 'restic -r s3:example/backups backup /srv' || exit $?
```

Every run asks for approval, and the audit log records who approved which command. Exit codes
(`3` denied, `4` expired) let the script tell a refusal from a failure.

### Build your own requester

```python
from passkey_vault_client import Client

request = Client().request("github", "deploy --env production")
print("Approve at", request.approve_url)
secret = request.wait()  # bytes, for exactly this command
```

Any language works: follow the [requester interface](docs/interface.md) and check your implementation
against the [test vectors](test-vectors). Full reference: [`pkv` and the SDK](docs/cli.md).

## Configuration

| Option | Environment variable | Default |
|---|---|---|
| `--origin` | `PASSKEY_VAULT_ORIGIN` (Compose) | `http://localhost:8740` in Compose |
| `--storage` | `PASSKEY_VAULT_STORAGE` | file storage in `--data-dir` |
| `--requester-hosts` | `PASSKEY_VAULT_REQUESTER_HOSTS` | loopback only |
| requester token | `PASSKEY_VAULT_REQUESTER_TOKEN` | generated into `<data-dir>/requester-token` |
| `--no-requester-token` | `PASSKEY_VAULT_REQUESTER_AUTH=off` | token required |
| `--approver-port` / `--requester-port` | | `8740` / `8741` |

Storage URLs look like `postgresql://user:pass@host/db` or `mongodb://host/db`. All options are in
[deployment](docs/deployment.md#run-without-docker).

## Documentation

| | |
|---|---|
| [`pkv` and the SDK](docs/cli.md) | Commands, options, exit codes, Python API |
| [Design](docs/design.md) | Flow, cryptography, storage, approval page |
| [Requester interface](docs/interface.md) | The public contract, with [OpenAPI](docs/openapi/requester.yaml) |
| [Approver API](docs/openapi/approver.yaml) | Internal API used by the approval page |
| [Threat model](docs/threat-model.md) | What is protected, and what is not |
| [Deployment](docs/deployment.md) | Docker, HTTPS proxy, same-host isolation, macOS example |

## Compatibility

Approving needs a browser and passkey provider that support the WebAuthn PRF extension.

| Approver | Result |
|---|---|
| iPhone (iOS), Chrome, passkey saved in Apple Passwords | works: setup, adding secrets, approve, deny |
| Mac (macOS), Safari, the same passkey synced through iCloud | works: same PRF output, so the vault opens on both |
| Chromium with a virtual authenticator (CI) | works: full flow tested on every commit |
| Approving from another device by QR code (hybrid) | not supported: reported to give a different PRF output |

To check another browser or passkey provider, open [`tools/prf-test.html`](tools/prf-test.html) over HTTPS
on it. If PRF is missing, the approval page refuses to create a vault with that passkey.

## Security

The server, the approval page and the HTTPS proxy in front of them must run where requesters cannot
change them; a separate host is simplest. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## Repository layout

| Path | Package | Contents |
|---|---|---|
| [`packages/server`](packages/server) | `passkey-vault-server` | the server and the approval page (`passkey-vault` command) |
| [`packages/client`](packages/client) | `passkey-vault-client` | the requester SDK and the `pkv` command |
| [`docs/`](docs), [`test-vectors/`](test-vectors) | | the protocol both packages implement |
| [`deploy/`](deploy) | | lock files and the macOS example |

## Development

Requires [uv](https://docs.astral.sh/uv/) and Node.js 24.

```sh
uv sync                                                  # both packages, editable, plus dev tools
uv run passkey-vault --dev                               # http://localhost:8740, setup code printed
uv run ruff check . && uv run ruff format --check .      # lint and format
uv run mypy packages/client/src packages/server/src      # types (the client is strict)
uv run python -m unittest discover -s tests              # Python tests
node --test 'tests/js/*.test.mjs'                        # approval page crypto, in Node
uv run python tests/e2e_virtual_authenticator.py         # end to end in Chromium
```

Database, container and deployment tests are opt-in; see [CONTRIBUTING.md](CONTRIBUTING.md#optional-tests).
Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md). Changes are listed in
[CHANGELOG.md](CHANGELOG.md); releases follow [RELEASING.md](RELEASING.md).

## Status

Early (0.x). Tested end to end in CI and on real devices (see [Compatibility](#compatibility)).

## License

[MIT](LICENSE)
