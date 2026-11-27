# Verification status

What is covered by automated tests, and what still needs a real device. Last updated 2026-11-27.

## Automated

| Area | Test | Command |
|---|---|---|
| Byte rules: server, approval page and client | `tests/test_vectors.py`, `tests/js/vectors.test.mjs`, `tests/test_client_vectors.py` (also on Python 3.10 in CI) | `uv run python -m unittest tests/test_vectors.py tests/test_client_vectors.py`, `node --test 'tests/js/*.test.mjs'` |
| `pkv` CLI against a real server: argv, stdin and shell modes, exit codes, unreachable server | `tests/test_cli.py` | `uv run python -m unittest tests/test_cli.py` |
| Both packages build; the server wheel carries the approval page | CI `uv build --all-packages` | `uv build --all-packages` |
| Server: setup, approval, denial, expiry, single delivery, signature binding, nonces, sign counters, `Host`/`Origin`/content-type checks, keep-alive handling | `tests/test_server.py` | `uv run python -m unittest tests/test_server.py` |
| Storage contract (file, PostgreSQL, MongoDB), including concurrent compare-and-swap, plus the full server flow on each database | `tests/test_storage.py` | see the file header for the database URLs |
| OpenAPI: specs valid, every route documented, real responses match the schemas | `tests/test_openapi.py` | `uv run python -m unittest tests/test_openapi.py` |
| The real approval page in Chromium with virtual authenticators (PRF on): setup, add secret, approve, deny, second passkey, recovery with the second passkey alone, tamper detection, PRF-less authenticator rejected, CSP blocks inline scripts | `tests/e2e_virtual_authenticator.py` | `uv run python tests/e2e_virtual_authenticator.py` |
| Container image with file, PostgreSQL and MongoDB storage; non-root user; read-only filesystem | `tests/test_docker.py` | `PV_DOCKER_TEST=1 uv run python -m unittest tests/test_docker.py` |
| macOS deploy script in test mode, then the server started with the LaunchDaemon's arguments | `tests/test_deploy.py` | `PV_DEPLOY_TEST=1 uv run python -m unittest tests/test_deploy.py` |

Observed while writing the tests:

- Chromium's virtual authenticator supports PRF (`hasPrf`), returns PRF output from `create`, and
  returns the same output on repeated `get` calls.
- Chromium allows only one `internal` virtual authenticator per environment; the E2E test uses a `usb`
  one as the second passkey.

## Needs a real device

| Assumption | Status | How to check |
|---|---|---|
| iOS/iPadOS Safari supports PRF with iCloud Keychain passkeys | Unverified. Community reports say iOS 18, reliably 18.4+ | Open [`tools/prf-test.html`](../tools/prf-test.html) over HTTPS on the device |
| `create` returns PRF output on Apple platforms, or only `get` does | Unverified; the page handles both | Same page, step 1 |
| A synced passkey yields the same PRF output on another device | Unverified | Compare the fingerprint shown by the PRF check on both devices |
| PRF via security keys (e.g. YubiKey) on mobile browsers | Unverified | Register one as a second passkey |
| Cross-device (QR code) approvals | Not supported; reported to return different PRF output | — |
| python.org installer file permissions on macOS | Unverified; `deploy.sh` refuses group- or world-writable files | Run the deploy and follow its message |
| Whether launchd creates the log file as root or as the service user | Unverified; both work | Check `ls -l /Library/PasskeyVault/logs` after the first start |
