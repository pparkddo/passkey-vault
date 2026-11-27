# passkey-vault-server

The passkey-vault server and its approval page. Requesters ask for a secret for one command; the
approver reviews the request in a browser and approves it with a passkey; the secret is decrypted in
the browser and delivered once, encrypted to the requester's one-time key. The server stores
ciphertext only.

```sh
uv tool install "passkey-vault-server @ git+https://github.com/pparkddo/passkey-vault#subdirectory=packages/server"
passkey-vault --origin https://vault.example.com --data-dir /var/lib/passkey-vault
```

See the [project README](https://github.com/pparkddo/passkey-vault) for the design, the threat model
and deployment.
