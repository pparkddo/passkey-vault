# Design

How passkey-vault works and why. The requester-facing contract is in [interface.md](interface.md),
attacks and limits are in [threat-model.md](threat-model.md), and running it is in
[deployment.md](deployment.md).

## Roles

| Role | What it is |
|---|---|
| **Requester** | A program that needs a secret for one command, for example a CLI used by an AI agent. Not trusted. |
| **Approver** | The person who owns the secrets. Approves on any device whose browser supports passkeys with the PRF extension. |
| **Server** | Stores ciphertext, queues requests, serves the approval page. Cannot decrypt anything. |
| **Approval page** | The web page in [`packages/server/src/passkey_vault/web/`](../packages/server/src/passkey_vault/web). Does all cryptography: WebAuthn, PRF, decryption, re-encryption. |
| **Operator** | Whoever deploys the server. Often the approver. |

## Flow

```
Requester                         Server                              Approval page (approver's browser)
---------                         ------                              ----------------------------------
one-time RSA key pair (memory)
POST /requests {secret, command, pubkey}
                       ───────▶  pending request, 5 min ─────────────▶  shows secret, site, account, command
                                                                        passkey prompt (signs the request,
                                                                        evaluates PRF)
                                                                        PRF → HKDF → unwrap master key
                                                                        decrypt this one item
                                                                        RSA-OAEP to the requester key
                                  ◀──────── assertion + ciphertext ──── POST /api/requests/{id}/approve
GET /requests/{id}?wait=30
                       ◀───────  ciphertext, then deleted
decrypt with the OAEP label, run the command once, discard key and value
```

The server never sees the PRF output, the master key or a plaintext secret. Its storage holds
ciphertext and metadata only.

## Two doors

The server listens on two ports with different audiences:

| Door | Default | Who calls it | Exposure |
|---|---|---|---|
| Approver door | 8740 | the approval page | behind an HTTPS reverse proxy; its origin is the WebAuthn RP ID |
| Requester door | 8741 | requesters | loopback by default; a private network if requesters run elsewhere |

Both bind to `127.0.0.1` unless `--bind` says otherwise (the container image binds `0.0.0.0` and
publishes to loopback). The requester door only accepts `Host` names in its allow list (loopback plus
`--requester-hosts`), which stops browsers from being used against it through DNS rebinding.

Assume anyone who can reach the approver door can call its API. That is why every call that
changes the vault must carry a passkey signature (see [Approver API](#approver-api)).

## Cryptography

| Purpose | Choice |
|---|---|
| Approval | WebAuthn with the PRF extension; user verification required for create and get |
| Key derivation | PRF output → HKDF-SHA256 → AES-256-GCM wrap key (PRF output is never used directly as a key) |
| Vault items | AES-256-GCM under a 256-bit master key |
| Master key | Wrapped separately for each registered passkey with that passkey's wrap key |
| Delivery to the requester | RSA-OAEP (SHA-256, MGF1-SHA-256) to a one-time key of at least 2048 bits |
| Binding the request | OAEP label over id, command and public key; WebAuthn challenge over id, secret, command and public key |
| Recovery | Register more than one passkey. There is no separate recovery key |

RSA-OAEP was chosen because both WebCrypto and Python `cryptography` provide it natively, so no
cryptographic code is hand-written. HPKE would be nicer but is not built into browsers yet.

### Byte rules

All concatenations use length prefixes, `lp(x) = u32be(len(x)) || x`, never separators, so a field
cannot be confused with its neighbour. The first field is always a purpose tag.

| Name | Definition |
|---|---|
| OAEP label | `lp("passkey-vault/oaep-label/v1") ‖ lp(id) ‖ lp(command) ‖ lp(pubkey_der)` |
| Approve challenge | `SHA-256(lp("passkey-vault/approve/v1") ‖ lp(id) ‖ lp(secret) ‖ lp(command) ‖ lp(pubkey_der))` |
| Operation challenge | `SHA-256(lp("passkey-vault/op/v1") ‖ lp(op) ‖ lp(nonce) ‖ lp(field₁) ‖ …)` |
| PRF input | `SHA-256("passkey-vault/prf-salt/v1")` |
| Wrap key | `HKDF-SHA256(ikm = PRF output, salt = "passkey-vault/hkdf-salt/v1", info = "passkey-vault/wrap-key/v1", L = 32)` |
| Wrapped master key | `AES-256-GCM(wrap key, 12-byte IV, master key, AAD = lp("passkey-vault/wrap/v1") ‖ lp(credential_id))` |
| Item | `AES-256-GCM(master key, 12-byte IV, UTF-8 secret, AAD = lp("passkey-vault/item/v1") ‖ lp(name) ‖ lp(site) ‖ lp(account))` |

Why these choices:

- **Fixed PRF input.** With several passkeys there is no need for `evalByCredential`, which keeps
  browser support wide. PRF outputs still differ per passkey.
- **Item AAD includes name, site and account.** Moving ciphertext between items, or changing the site
  or account shown to the approver, makes decryption fail in the browser.
- **Wrap AAD includes the credential id.** A wrapped key cannot be reused under another passkey entry.
- **The page computes challenges itself** from what it displays. The server recomputes them from the
  stored request when it verifies the signature. What was shown, what was signed and what was accepted
  are therefore the same thing.

All implementations (the server's `formats.py`, the page's `js/formats.js`, the client's `protocol.py`) are checked against
[`test-vectors/`](../test-vectors).

## Lifecycles

### Request

```
pending ──approve──▶ approved ──collected once──▶ consumed (410 afterwards)
   ├──deny──▶ denied
   └──5 minutes──▶ expired        (approved but uncollected requests expire too)
```

Requests live in memory. A restart drops them and requesters simply ask again. At most 20 can be
pending at once. The ciphertext is dropped only after the response carrying it was written; if
sending fails, the request stays approved and can be collected again. Audit records for creation, approval and denial are written before the state
changes, so an event that cannot be recorded does not happen. Pages count down from the server's
`expires_in`, never from the device clock.

### First-time setup

1. On start-up without a vault, the server writes a one-time **setup code** to `<data-dir>/setup-code`
   (mode 0600). Only someone who can read the server's data directory can set the vault up. This
   prevents a requester from initialising the vault with its own keys before the approver does.
2. The page creates a passkey (PRF requested), generates a random master key, wraps it with the
   passkey's wrap key, and sends the registration and the wrapped key with the setup code.
3. The server verifies the registration and deletes the setup code.

If `create` does not return PRF output (some platforms only return it on sign-in), the page signs in
once more with the new passkey. Authenticators that report no PRF support are rejected. The rejected
passkey has already been created on the authenticator by then; the browser offers no way to delete it,
so the approver removes it from their passkey manager.

### Items and passkeys

- **Add or replace an item**: one passkey prompt signs `put-item(name, site, account)` and unlocks
  the master key; the browser encrypts the secret and uploads ciphertext.
- **Add a passkey**: create the new passkey, then sign `add-credential(new id, name)` with an existing
  one, which also unlocks the master key so it can be wrapped for the new passkey.
- **Remove a passkey or item**: one signature. The last passkey cannot be removed.
- **Master key rotation** is not implemented: it needs every passkey present at once. The plan is to
  re-encrypt all items under a new key and re-wrap it for each passkey that is presented.

## Approver API

Internal to the bundled page; specified in [openapi/approver.yaml](openapi/approver.yaml).

| Call | Needs a signature |
|---|---|
| `GET /api/state`, `GET /api/requests/{id}`, `POST /api/nonce` | no (ciphertext and metadata only) |
| `POST /api/setup` | registration + setup code |
| `POST /api/requests/{id}/approve` | approve challenge |
| `POST /api/requests/{id}/deny` | no: the worst a forged denial can do is waste a request |
| `POST /api/items`, `.../items/{name}/delete` | operation challenge |
| `POST /api/credentials`, `.../credentials/{id}/delete` | operation challenge |

Nonces are single-use, bound to one operation and valid for 5 minutes. POST requests must also carry
an `Origin` header equal to the configured origin.

## Storage

The vault is one small document with a revision number. Writers use compare-and-swap on the revision,
so concurrent writers never lose an update, even through a shared database. Requests and nonces, however,
live in process memory: run **one** server instance per vault (a second instance would not see the
first one's requests).

| Backend | `--storage` / `PASSKEY_VAULT_STORAGE` | Vault | Audit log |
|---|---|---|---|
| File (default) | empty or `file` | `<data-dir>/vault.json`, atomic replace, flock for CAS | `<data-dir>/audit.log`, JSON Lines |
| PostgreSQL | `postgresql://…` | one row, `UPDATE … WHERE revision = $n` | table `passkey_vault_audit` |
| MongoDB | `mongodb://…` | one document, conditional update, majority write concern | collection `audit` |

Item names, sites and accounts are stored in clear text so the approval screen can show them before
any passkey prompt; they are bound to the ciphertext through the item AAD. Secrets are only stored
encrypted.

To add a backend, implement `VaultStore` and `AuditSink` in
[`packages/server/src/passkey_vault/storage/`](../packages/server/src/passkey_vault/storage) and run
[`tests/test_storage.py`](../tests/test_storage.py) against it.

The audit log records request creation, approval (including the raw WebAuthn signature),
denial, expiry, delivery, setup and every item or passkey change. It never contains secrets,
plaintext or RSA ciphertext.

## Approval page

- Plain HTML and ES modules, no build step and no npm dependencies, so a diff is easy to review.
- Served only by the server itself. No external scripts, fonts or images.
- Every response carries a strict CSP (`default-src 'none'; script-src 'self'; …`), `nosniff`,
  `no-referrer`, `frame-ancestors 'none'` and `no-store`. Static files are an allow-list loaded at
  start-up.
- Untrusted strings (commands, names) are only ever inserted with `textContent`.
- Do not host anything else on the same host name: any page on that RP ID could ask for PRF output.

## Server implementation

- Python standard library HTTP server (`ThreadingHTTPServer`), one per door; long polling waits on a
  condition variable.
- WebAuthn verification uses [py_webauthn](https://github.com/duo-labs/py_webauthn) rather than
  hand-written CBOR/COSE parsing and signature checks.
- Dependencies are locked with hashes (`uv.lock`, exported to `deploy/requirements*.lock`) and
  installed as wheels only.
