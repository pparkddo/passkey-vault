# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/pparkddo/passkey-vault/security/advisories/new).
Do not open a public issue.

Include what you found, how to reproduce it, and what an attacker gains. You will get an
acknowledgement within a week.

## Scope

In scope: the server, the approval page, the byte-level rules in `docs/interface.md`, the container
image and the deployment scripts.

Read [docs/threat-model.md](docs/threat-model.md) first. Its "Accepted limits" (for example, an
approver approving a malicious command, or a compromised server host) are known and not considered
vulnerabilities.
