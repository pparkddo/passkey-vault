# Releasing

The server (`passkey-vault-server`) and the client (`passkey-vault-client`) are released together
with one version number. Pushing a tag `vX.Y.Z` runs [`release.yml`](.github/workflows/release.yml),
which:

1. checks that the tag, both package versions and `CHANGELOG.md` agree;
2. builds both packages, smoke-tests the wheels, attests their provenance and publishes them to PyPI
   with Trusted Publishing (no API token is stored);
3. builds the `linux/amd64` and `linux/arm64` image with an SBOM and provenance, and pushes
   `ghcr.io/pparkddo/passkey-vault:X.Y.Z` and `:X.Y`;
4. creates the GitHub release with the CHANGELOG section as notes and the built files attached.

Running the workflow by hand (Actions → Release → Run workflow) is a dry run: it builds everything
and publishes nothing.

## One-time setup

- **PyPI**: add a Trusted Publisher (a "pending publisher" before the first upload) with owner
  `pparkddo`, repository `passkey-vault` and workflow `release.yml`, using a different environment for
  each project (PyPI allows one pending project per publisher configuration):

  | Project | Environment |
  |---|---|
  | `passkey-vault-server` | `pypi` |
  | `passkey-vault-client` | `pypi-client` |

- **GitHub**: create the environments `pypi` and `pypi-client` (Settings → Environments), limited to
  tags `v*`. Adding yourself as a required reviewer makes every PyPI upload wait for your approval.
- **GHCR**: after the first release, make the `passkey-vault` package public (Packages → Package
  settings) so that `docker pull` works without logging in.

## Every release

1. Pick the version (SemVer). Breaking the requester interface or the byte-level rules is a major
   version.
2. Set it and record the changes:
   ```sh
   scripts/version.sh set X.Y.Z
   ```
   Move the entries under `## [Unreleased]` in `CHANGELOG.md` to `## [X.Y.Z] - YYYY-MM-DD` and update
   the links at the bottom.
3. Check, commit and push:
   ```sh
   scripts/version.sh check
   git commit -am "Release X.Y.Z" && git push
   ```
4. Wait for CI to pass on that commit, then tag it:
   ```sh
   git tag -s vX.Y.Z -m "vX.Y.Z"      # -a instead of -s if you do not sign tags
   git push origin vX.Y.Z
   ```
5. Watch the Release workflow. Afterwards, check that `uv tool install passkey-vault-client==X.Y.Z`
   and `docker pull ghcr.io/pparkddo/passkey-vault:X.Y.Z` work.

After the first PyPI release, switch the install commands in `README.md`, `docs/cli.md`,
`docs/deployment.md` and the package READMEs from the `git+https://...` form to the package names.

## Dependencies

Dependabot opens weekly pull requests for Python packages, GitHub Actions and the base image. When
`uv.lock` changes, regenerate the server lock files used by the image and the macOS deploy script:

```sh
scripts/export-locks.sh            # CI fails with "run scripts/export-locks.sh" if you forget
```
