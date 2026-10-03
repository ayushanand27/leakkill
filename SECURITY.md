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
- the AI agent guard (Claude Code, Cursor, Copilot, Codex) being bypassed in a way the README doesn't already list
- the guard repeating a raw secret back to the agent in its own message
- anything that lets a malicious repository run code when it is scanned (git's own hooks into a repo's config
  are switched off for every git call; `tests/test_real_world.py` checks this)

## Verifying a release

PyPI files carry attestations from trusted publishing. From 0.6.0 on, every GitHub release also includes a
Sigstore signature for each file (`*.sigstore.json`), made in CI with no long-lived key:

```sh
pip install sigstore
sigstore verify github leakkill-0.6.0-py3-none-any.whl \
  --bundle leakkill-0.6.0-py3-none-any.whl.sigstore.json \
  --cert-identity https://github.com/ayushanand27/leakkill/.github/workflows/publish.yml@refs/heads/main
```

## Supported versions

The latest release on PyPI. Fixes are released as a new patch version.
