# Contributing

Issues and pull requests are welcome.

- Keep the approval page (`packages/server/src/passkey_vault/web/`) free of build steps and dependencies. Reviewers must be able to read every
  line that runs next to a passkey.
- Changes to byte-level rules need new test vectors (`test-vectors/generate.py`) and must keep the
  server, approval page and client implementations in step.
- Keep `passkey-vault-client` dependent on `cryptography` only, and working on Python 3.10.
- Run the tests listed in the README before opening a pull request. New storage backends must pass
  `tests/test_storage.py`.
- Security issues go through [SECURITY.md](SECURITY.md), not public issues.
