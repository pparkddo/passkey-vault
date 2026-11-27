# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). The server and client packages share one version.

The requester interface (`docs/interface.md`) and the byte-level rules (`test-vectors/`) are the
public contract: changing them incompatibly needs a new major version (and a new `/v2` purpose tag).

## [Unreleased]

## [0.1.0] - 2026-11-27

First release.

### Server (`passkey-vault-server`)
- Approver door with the approval page and requester door with the requester API.
- Passkey (WebAuthn PRF) approval of one secret for one command; secrets decrypted only in the
  approver's browser and delivered once, RSA-OAEP-encrypted to a one-time requester key.
- Storage backends: file (default), PostgreSQL, MongoDB.
- Requester token on by default; `GET /secrets` lists names and metadata.
- Docker image and Compose file; macOS same-host deployment example.

### Client (`passkey-vault-client`)
- Python SDK (`Client`, `ApprovalRequest`).
- `pkv` CLI: `setup`, `list`, `run`.

[Unreleased]: https://github.com/pparkddo/passkey-vault/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/pparkddo/passkey-vault/releases/tag/v0.1.0
