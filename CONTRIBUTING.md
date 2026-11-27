# Contributing

Issues and pull requests are welcome.

- Keep the approval page (`packages/server/src/passkey_vault/web/`) free of build steps and dependencies. Reviewers must be able to read every
  line that runs next to a passkey.
- Changes to byte-level rules need new test vectors (`test-vectors/generate.py`) and must keep the
  server, approval page and client implementations in step.
- Keep `passkey-vault-client` dependent on `cryptography` only, and working on Python 3.10.
- Run `uv run ruff check .`, `uv run ruff format .`, `uv run mypy packages/client/src packages/server/src`
  and the tests listed in the README before opening a pull request. New storage backends must pass
  `tests/test_storage.py`.
- Security issues go through [SECURITY.md](SECURITY.md), not public issues.
- Add a line under `## [Unreleased]` in `CHANGELOG.md` for user-visible changes.
- After changing dependencies (`uv.lock`), run `scripts/export-locks.sh`.
- Releases are cut by maintainers; see [RELEASING.md](RELEASING.md).

## Optional tests

These need extra services and are skipped unless enabled:

| Tests | Enable with |
|---|---|
| PostgreSQL and MongoDB backends (`tests/test_storage.py`) | `PV_TEST_POSTGRES_URL=postgresql://...` and/or `PV_TEST_MONGODB_URL=mongodb://...` (a scratch database: the tests drop their tables) |
| Container image with every backend (`tests/test_docker.py`) | `PV_DOCKER_TEST=1` and a running Docker daemon (ports 8740/8741 free) |
| macOS deploy script (`tests/test_deploy.py`) | `PV_DEPLOY_TEST=1` (downloads wheels from PyPI) |
| Approval page under a slow CPU (`tests/e2e_virtual_authenticator.py`) | `PV_E2E_CPU_THROTTLE=8` |

CI runs all of them except the deploy script.
