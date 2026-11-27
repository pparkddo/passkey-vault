# Threat model

## What is protected

- The plaintext of vault items (passwords, tokens).
- The master key, and the passkey **PRF output** that unwraps it. PRF output is a fixed value per
  passkey: if it leaked once, every secret could be decrypted without approval from then on. It
  therefore never leaves the approver's browser.

**Goal:** without an approval made with a registered passkey, nobody can decrypt a secret, including
the requester, the server and whoever holds the storage. One approval releases one secret for one
command.

## Actors

| Actor | Assumed capabilities |
|---|---|
| Requester (e.g. an AI agent) | Creates any request it likes. Reads and writes everything its own account can. Can reach the requester door, and possibly the approver door. |
| Network neighbour | Can reach whatever doors are exposed to it. |
| Storage holder | Reads (and possibly writes) the vault document and audit log: a backup, a DBA, a leaked dump. |
| Approver | Holds the passkeys and decides. |
| Operator | Deploys the server, the approval page and the HTTPS reverse proxy. |

**Trusted:** the approver's device, browser and passkey provider; the operator; TLS between the
approver and the reverse proxy.

## Deployment requirement

> The server, the approval page and the HTTPS reverse proxy in front of it must run where the
> requester cannot change them.

Anyone who can change the page served on the approval origin can ask the approver's passkey for PRF
output and exfiltrate it the next time the approver says yes. The same holds for anyone who can change
the reverse proxy configuration, the TLS certificate or the DNS name of that origin.

Running the server on a different host from the requester satisfies this. If they share a host, see
[deployment.md](deployment.md#same-host-as-the-requester) for the isolation that is needed.

## Attacks and defences

| Attack | Defence |
|---|---|
| Steal the vault document or a backup | It holds ciphertext and metadata only; the master key is wrapped per passkey and PRF output never reaches the server |
| Initialise the vault first with attacker keys | Setup needs a one-time code that is only readable from the server's data directory |
| Call the approver API to add a passkey or replace items | Every change needs a signature (with user verification) from a registered passkey over a challenge that binds a single-use nonce and the operation's content |
| Add a passkey to obtain the master key | Adding a passkey needs an existing passkey's signature and its PRF output to unwrap the key; the server never has it |
| Replay an approval signature for another request | The challenge covers id, secret name, command and public key; ids are random and single-use |
| Swap ciphertext between requests, or trick an honest requester into a command the approver did not see | The OAEP label covers id, command and public key; decryption fails otherwise |
| Edit storage to move item ciphertext or change the displayed site/account | The item AAD covers name, site and account; decryption fails in the browser |
| Collect the same secret twice | Delivered once, then deleted; later reads return 410 |
| Drive a browser against the requester door (CSRF, DNS rebinding) | `Host` allow-list, JSON-only bodies, no CORS |
| Strangers flood the approver with requests | Requester token on every requester call (on by default) |
| Hide or reorder text in the command shown to the approver | Control, format (bidi, zero-width), surrogate and separator characters are rejected on the server and again in the page; the page shows the whole command |
| Load attacker code into the page | No external resources; CSP `script-src 'self'`; untrusted strings rendered with `textContent` |
| Clone an authenticator | Signature counters must not go backwards (for authenticators that use counters) |

## Accepted limits

1. **A malicious requester.** The requester can ask to run a command that sends the secret somewhere
   else, and once it has decrypted the secret it can use it however it likes: the command binding
   protects honest requesters and stops other programs from using the ciphertext, but it cannot
   constrain the program that holds the plaintext. The approval screen shows the secret, site, account
   and full command; deciding whether to trust that request is the approver's job.
2. **Exposure while the approved command runs.** Anything that can inspect that process (same user,
   root) can read the secret while it runs. An approval releases the secret to that command.
3. **A compromised server host or approver device.** Out of scope.
4. **Visibility and denial of service.** Anyone who can reach the approver door can read pending
   requests (secret names, sites, accounts, commands) and deny them (denial needs no signature).
   Requesters can keep up to 20 requests pending. None of this reveals a secret.
5. **Storage integrity.** Someone who can write the vault document can delete data or rewrite the
   audit log. They still cannot decrypt anything, and tampered items fail to decrypt.
6. **Losing every passkey.** There is no recovery key. Register at least two passkeys.
7. **Metadata.** Item names, sites and accounts are stored in clear text.
8. **Memory hygiene in JavaScript.** The page zeroes PRF output and plaintext buffers after use, but
   cannot erase copies the JavaScript engine may have made.

## Platform assumptions

See [verification.md](verification.md) for what has and has not been checked on real devices.

- The browser supports the WebAuthn PRF extension for the passkeys in use.
- A synced passkey returns the same PRF output on every device it syncs to.
- Only same-device (platform or security key) use is supported. Cross-device (hybrid, QR code) flows
  have been reported to return different PRF output and are not a supported way to approve.
