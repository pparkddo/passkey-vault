<div align="center">

# passkey-vault

**Give an agent one secret, for one command, after you approve it with a passkey.**

[![CI](https://github.com/pparkddo/passkey-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/pparkddo/passkey-vault/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.15](https://img.shields.io/badge/python-3.15-blue.svg)](pyproject.toml)

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

Requirements: Docker, and a browser plus passkey provider that support the WebAuthn PRF extension
(check yours with [`tools/prf-test.html`](tools/prf-test.html)).

```sh
git clone https://github.com/pparkddo/passkey-vault && cd passkey-vault
docker compose up -d
docker compose exec passkey-vault cat /data/setup-code
```

Open <http://localhost:8740>, enter the setup code, create your passkey and add a secret.

Then ask for it from the command line with the reference requester (needs [uv](https://docs.astral.sh/uv/)):

```sh
uv run python tests/ref_client.py github 'gh auth login --with-token <<< "$PASSKEY_VAULT_SECRET"' --run
```

It prints an approval link, waits for you, then runs the command once with the secret in
`$PASSKEY_VAULT_SECRET`.

For real use, serve the approval page over HTTPS and run the server where requesters cannot modify
it. See [deployment](docs/deployment.md).

## Writing a requester

A requester is any program that follows the [requester interface](docs/interface.md):

1. Generate an RSA key pair (3072 bits recommended) in memory.
2. `POST /requests` with the secret name, the command and the public key; show `approve_url` to the user.
3. Poll `GET /requests/{id}?wait=30` until it returns `approved`, `denied` or `expired`.
4. Decrypt the ciphertext with RSA-OAEP (SHA-256) and the request's label, run the command once, and
   discard the key.

[`tests/ref_client.py`](tests/ref_client.py) is a short reference implementation. Check yours against
the [test vectors](test-vectors).

## Configuration

| Option | Environment variable | Default |
|---|---|---|
| `--origin` | `PASSKEY_VAULT_ORIGIN` (Compose) | `http://localhost:8740` in Compose |
| `--storage` | `PASSKEY_VAULT_STORAGE` | file storage in `--data-dir` |
| `--requester-hosts` | `PASSKEY_VAULT_REQUESTER_HOSTS` | loopback only |
| `--approver-port` / `--requester-port` | | `8740` / `8741` |

Storage URLs look like `postgresql://user:pass@host/db` or `mongodb://host/db`. All options are in
[deployment](docs/deployment.md#run-without-docker).

## Documentation

| | |
|---|---|
| [Design](docs/design.md) | Flow, cryptography, storage, approval page |
| [Requester interface](docs/interface.md) | The public contract, with [OpenAPI](docs/openapi/requester.yaml) |
| [Approver API](docs/openapi/approver.yaml) | Internal API used by the approval page |
| [Threat model](docs/threat-model.md) | What is protected, and what is not |
| [Deployment](docs/deployment.md) | Docker, HTTPS proxy, same-host isolation, macOS example |
| [Verification](docs/verification.md) | What the tests cover, and what still needs a real device |

## Security

The server, the approval page and the HTTPS proxy in front of them must run where requesters cannot
change them; a separate host is simplest. Report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## Development

Requires [uv](https://docs.astral.sh/uv/) and Node.js 24.

```sh
uv sync --all-extras
PYTHONPATH=server uv run python -m passkey_vault --dev   # http://localhost:8740, setup code printed
uv run python -m unittest discover -s tests              # Python tests
node --test 'tests/js/*.test.mjs'                        # approval page crypto, in Node
uv run python tests/e2e_virtual_authenticator.py         # end to end in Chromium
```

Database, container and deployment tests are opt-in; see [verification](docs/verification.md).
Contributions are welcome: read [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

Early. Automated tests cover the protocol, the server, every storage backend, the container image and
the approval page in Chromium. Checks on real devices, such as iOS Safari, are still open.

## License

[MIT](LICENSE)
