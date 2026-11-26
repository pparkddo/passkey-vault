# Requester interface, v1

The contract between requesters and the server. The machine-readable version is
[openapi/requester.yaml](openapi/requester.yaml). The words MUST, MUST NOT and SHOULD are used as in
RFC 2119.

## 1. HTTP API

- Base URL: the requester door, `http://127.0.0.1:8741` by default.
- The `Host` header MUST name a host the server accepts (loopback, or one listed in
  `--requester-hosts`). Ordinary HTTP clients do this automatically.
- Request bodies MUST be `application/json` and at most 64 KiB. Responses are JSON.

### 1.1 `POST /requests`

```json
{
  "secret": "github",
  "command": "gh auth login --with-token",
  "pubkey": "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA..."
}
```

| Field | Rules |
|---|---|
| `secret` | Vault item name, `^[A-Za-z0-9._-]{1,64}$`; the item must exist |
| `command` | The command exactly as it will be shown and run. 1–4096 UTF-8 bytes. No C0/C1 control characters (so no line breaks or tabs), no bidi controls (U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), no U+2028/U+2029 |
| `pubkey` | RSA public key as SPKI DER, base64url without padding. 2048–4096 bits (a multiple of 8), exponent 65537 |

`201 Created`:

```json
{
  "id": "Q2v9b3nqk1mJt0x4H8sRZw",
  "approve_url": "https://vault.example.com/approve?id=Q2v9b3nqk1mJt0x4H8sRZw",
  "expires_at": "2026-11-27T01:05:00Z"
}
```

`id` is 128 random bits in base64url (22 characters). `expires_at` is creation time plus 5 minutes,
UTC. Give `approve_url` to the approver as is.

### 1.2 `GET /requests/{id}?wait=N`

`wait` is 0–30 seconds (default 0). While the request is pending the server holds the response for up
to `wait` seconds and answers as soon as the state changes. `200 OK` returns one of:

```json
{"status": "pending"}
{"status": "approved", "ciphertext": "<base64url>"}
{"status": "denied"}
{"status": "expired"}
```

- `approved` is returned **once**. The server deletes the ciphertext while answering; later calls get
  `410 consumed`. Requesters MUST NOT lose the first `approved` response.
- `denied` and `expired` are final.
- After a server restart, in-flight requests are gone (`404 not_found`). Create a new one.

### 1.3 Errors

Errors are `{"error": "<code>", "message": "<text>"}`. Codes are stable; messages are not.

| HTTP | `error` | Meaning |
|---|---|---|
| 400 | `bad_request` | Malformed JSON, missing fields, `wait` out of range |
| 400 | `invalid_secret_name` | `secret` does not match the pattern |
| 400 | `invalid_command` | `command` breaks the length or character rules |
| 400 | `invalid_pubkey` | Not a SPKI RSA key, exponent ≠ 65537, or larger than 4096 bits |
| 400 | `key_too_small` | RSA modulus below 2048 bits |
| 404 | `unknown_secret` | No vault item with that name |
| 404 | `not_found` | No such request (or the server restarted) |
| 405 | `method_not_allowed` | Wrong method |
| 409 | `vault_not_initialized` | The vault has not been set up |
| 410 | `consumed` | The ciphertext was already delivered |
| 411 | `length_required` | No `Content-Length` header |
| 413 | `payload_too_large` | Body over 64 KiB |
| 415 | `unsupported_media_type` | `Content-Type` is not `application/json` |
| 421 | `bad_host` | `Host` is not accepted by the requester door |
| 429 | `too_many_pending` | 20 requests are already pending |

## 2. Cryptography

### 2.1 One-time key

Requesters MUST generate a fresh RSA key pair (at least 2048 bits, 3072 recommended, exponent 65537)
for every request, keep the private key in memory only, and discard it after use.

### 2.2 RSA-OAEP

- Hash SHA-256 and MGF1 with SHA-256 (WebCrypto `{name: "RSA-OAEP", hash: "SHA-256"}`).
- Plaintext: the UTF-8 bytes of the secret. Maximum size is modulus bytes − 66 (190 bytes for 2048-bit
  keys, 318 for 3072). The approval page refuses secrets that do not fit.
- Decryption MUST use the label from 2.3.

### 2.3 Label

```
lp(x) = u32be(len(x)) || x               length in bytes, 4-byte big-endian

label = lp("passkey-vault/oaep-label/v1")
      || lp(UTF8(id))
      || lp(UTF8(command))
      || lp(pubkey_der)                  raw SPKI DER bytes, not base64url
```

`command` is the exact string the requester sent (no normalisation). If any byte differs, decryption
fails. This stops a ciphertext from being moved to another request or decrypted for a command other
than the one the approver saw. Requesters MUST run exactly the `command` they used for decryption and
nothing else. (A requester that ignores this rule already holds the plaintext; see the threat model.)

### 2.4 Approve challenge (informative)

The approver's passkey signs
`SHA-256(lp("passkey-vault/approve/v1") || lp(id) || lp(secret) || lp(command) || lp(pubkey_der))`.
Requesters do not need it; it is recorded in the audit log.

## 3. Test vectors

[`test-vectors/`](../test-vectors) contains:

| File | Content |
|---|---|
| `label.json` | id, command, public key → label bytes |
| `rsa-oaep.json` | fixed key pairs, labels and ciphertexts → expected plaintext; a changed label or command must fail |
| `approve-challenge.json` | approve challenges |
| `op-challenge.json` | operation challenges (approval page internals) |
| `keys.json` | PRF → HKDF → master key wrapping → item encryption (approval page internals) |

RSA-OAEP is randomized, so its vectors are "fixed ciphertext decrypts to this plaintext" rather than
"this input encrypts to that output". The private keys in the vectors are public test keys.

## 4. Guarantees

1. Creating a request releases nothing. The approver must see it and approve it with a passkey.
2. The ciphertext is delivered once.
3. Requests expire 5 minutes after creation, approved or not.
4. One approval is one secret for one command. There is no "always allow".

## 5. Versioning

This is v1. A change to any purpose tag (`.../v1`) is a breaking change.
