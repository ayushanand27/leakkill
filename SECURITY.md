# Security policy

leakkill handles other people's credentials, so security reports get priority.

## Reporting a vulnerability

Please **don't open a public issue.** Report it privately through
[GitHub's private vulnerability reporting](https://github.com/ayushanand27/leakkill/security/advisories/new).
You'll get an acknowledgement within 3 days and a fix or a plan within 14 days for confirmed issues.

Especially in scope:

- a secret sent anywhere other than the provider that issued it, or followed through a redirect
- a raw secret written to output, reports, SARIF, baselines or logs (masked values and hashes are by design)
- `revoke` acting without `--yes`, or on a key that didn't verify as live
- the Claude Code guard being bypassed in a way not listed under "Known limitations" in the README
- anything that lets a malicious repository run code when it is scanned

## Supported versions

The latest release on PyPI. Fixes are released as a new patch version.
