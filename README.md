# passkey-vault

Release one secret to one command, only after you approve it with a passkey.

passkey-vault is a small secret store for programs that act on your behalf, such as AI agents. A
program asks for a secret for a specific command; you see the request in your browser and approve it
with a passkey; the secret is decrypted in your browser and handed to that program, for that command,
once. The server only ever stores ciphertext.

## Why

Agents need credentials, but giving them a password manager session gives them everything. With
passkey-vault:

- **Nothing is released without you.** Decryption keys come from your passkey (WebAuthn PRF) and never
  leave your browser.
- **You see what you approve.** The approval screen shows the secret, the site, the account and the
  exact command.
- **One approval, one use.** The secret is encrypted to a one-time key bound to that request and that
  command, and delivered once.

## How it works

```
requester                    server                      your browser
POST /requests  ───────────▶ pending (5 min) ──────────▶ review, approve with passkey
                                                          PRF → unwrap master key → decrypt one item
                                                          → encrypt to the requester's one-time key
GET /requests/{id} ◀──────── ciphertext, once ◀───────── upload
decrypt, run the command, forget
```

Details: [design](docs/design.md).

## Quick start

Try it locally. The approval page needs a browser and passkey provider that support the WebAuthn PRF
extension; [`tools/prf-test.html`](tools/prf-test.html) checks yours.

```sh
docker compose up -d
docker compose exec passkey-vault cat /data/setup-code
# then open http://localhost:8740 to set up the vault and add a secret
```

Ask for a secret with the reference requester:

```sh
uv run python tests/ref_client.py github 'curl -fsS -u "me:$PASSKEY_VAULT_SECRET" https://example.com' --run
```

It prints an approval link, waits, and runs the command once with the secret in
`PASSKEY_VAULT_SECRET`. To write your own requester, follow the
[requester interface](docs/interface.md) ([OpenAPI](docs/openapi/requester.yaml)) and check it against
the [test vectors](test-vectors).

For real use, put it behind HTTPS: see [deployment](docs/deployment.md).

## Security

The server, the approval page and the HTTPS proxy in front of them must run where requesters cannot
change them; a separate host is simplest. Within that, a stolen database, a malicious requester or a
replayed approval does not reveal a secret. Read the [threat model](docs/threat-model.md) for what is
and is not covered, and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Storage

File storage by default; PostgreSQL and MongoDB are built in, and other backends implement two small
interfaces. See [design: storage](docs/design.md#storage).

## Documentation

- [Design](docs/design.md): flow, cryptography, storage, approval page
- [Requester interface](docs/interface.md) and OpenAPI for the [requester](docs/openapi/requester.yaml)
  and [approver](docs/openapi/approver.yaml) APIs
- [Threat model](docs/threat-model.md)
- [Deployment](docs/deployment.md): Docker, reverse proxy, same-host isolation, macOS example
- [Verification status](docs/verification.md): what is tested, what needs a real device

## Development

Requires [uv](https://docs.astral.sh/uv/) and Node.js 24.

```sh
uv sync --all-extras
PYTHONPATH=server uv run python -m passkey_vault --dev     # http://localhost:8740
uv run python -m unittest discover -s tests                # Python tests
node --test 'tests/js/*.test.mjs'                          # browser crypto code, in Node
uv run python tests/e2e_virtual_authenticator.py           # end to end in Chromium
```

Database, container and deploy tests are opt-in; see [verification](docs/verification.md).

## Status

Early. Automated tests cover the protocol, the server, all storage backends, the container image and
the approval page in Chromium. Real-device checks (for example iOS Safari) are still open; see
[verification](docs/verification.md).

## License

[MIT](LICENSE)
