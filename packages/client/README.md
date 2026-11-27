# passkey-vault-client

The requester side of [passkey-vault](https://github.com/pparkddo/passkey-vault): a small Python SDK
and the `pkv` command. It asks a passkey-vault server for one secret for one command, waits while you
approve the request with a passkey, then runs the command once with the secret.

```sh
uv tool install passkey-vault-client

pkv run github --stdin -- gh auth login --with-token  # secret on stdin
pkv run api-token -c 'curl -H "Authorization: Bearer $PKV_SECRET" https://api.example.com'
```

```python
from passkey_vault_client import Client

request = Client.from_config().request("github", "gh auth login --with-token")  # settings from `pkv setup`
print("Approve at", request.approve_url)
secret = request.wait()  # bytes
```

Only depends on `cryptography`. Reference: [docs/cli.md](https://github.com/pparkddo/passkey-vault/blob/main/docs/cli.md).
