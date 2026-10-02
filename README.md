# leakkill

[![PyPI](https://img.shields.io/pypi/v/leakkill)](https://pypi.org/project/leakkill/) [![CI](https://github.com/ayushanand27/leakkill/actions/workflows/ci.yml/badge.svg)](https://github.com/ayushanand27/leakkill/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ayushanand27/leakkill/badge)](https://scorecard.dev/viewer/?uri=github.com/ayushanand27/leakkill)

**Leaked a key? Find it, see if it's live, and kill it in one command. Free, local, zero dependencies.**

Free tools are great at *finding* secrets. What happens *after* a leak is usually left to paid
platforms: is this key still working, whose account is it, how do I revoke it right now, and how do
I clean it out of git history? leakkill does that part too, from your terminal, for free.

```console
$ leakkill verify
#1   LIVE         GitHub token           ghp_************     config.py:3
      octocat  scopes: repo, workflow
#2   DEAD         AWS access key         AKIA************     deploy/old.sh:12
      key id is unknown or deactivated
#3   UNVERIFIABLE Credentials in URL     postgres://app:****@db.prod.internal  .env.backup:1

3 unique secret(s), 1 LIVE.

$ leakkill revoke --only 1 --yes
  #1 GitHub token: REVOKED (HTTP 202)
```

## Install

```sh
pip install leakkill
```

Python 3.9+, no dependencies. Latest development version:
`pip install git+https://github.com/ayushanand27/leakkill`

## Commands

| Command | What it does | Network? |
|---|---|---|
| `leakkill [scan] [PATH ...]` | Find secrets. Exit code 1 if any. | **Never** |
| `leakkill verify` | Also check each secret against the provider that issued it: live or dead, which account, which scopes | Read-only "who am I" calls |
| `leakkill revoke` | Show what can be revoked. With `--yes`, revoke the live ones (`--only 1,3` to pick) | Only with `--yes` |
| `leakkill report` | Write `leakkill-report.md`: every leak, its status and owner, and the cleanup steps in order | Same as `verify` (`--no-verify` to skip) |
| `leakkill install-hook` | Git pre-commit hook that blocks commits containing secrets | Never |
| `leakkill install-claude-hook` | Stop Claude Code reading `.env` and keys or writing secrets into code | Never |

Every scan command also accepts `--staged` (pre-commit), `--history` (every commit on every branch,
including secrets you already "deleted"), `--exclude-tests` and `--json`.

## What it can verify and revoke

| Provider | Verify (live? whose?) | Revoke from the CLI |
|---|---|---|
| GitHub (`ghp_`, `github_pat_`, `gho_`, `ghu_`, `ghr_`) | ✅ user and scopes | ✅ via GitHub's [credential revocation API](https://docs.github.com/en/rest/credentials/revoke) (the owner is notified) |
| GitLab (`glpat-`) | ✅ token name, scopes, expiry | ✅ self-revoke |
| Slack tokens (`xox…`) | ✅ user and workspace | ✅ `auth.revoke` |
| Discord webhooks | ✅ server and channel | ✅ deletes the webhook |
| AWS access key and secret | ✅ IAM ARN and account (STS, needs no permissions) | ⚠️ deactivates the key if it has `iam:UpdateAccessKey`, otherwise console steps |
| SendGrid (`SG.`) | ✅ scopes | ✅ the key deletes itself if it has API-key permissions |
| Stripe (live and test keys), OpenAI, Anthropic, OpenRouter, Groq, Hugging Face, Replicate, DigitalOcean, npm, Telegram, Slack webhooks | ✅ (account or username where the API returns it) | ❌ the provider has no API for it, so you get the exact page or command |
| Google API keys, Shopify, PyPI, Docker Hub, Twilio, Postman, Perplexity, Linear, Azure Storage, private keys, JWTs, credentials in URLs, generic high-entropy secrets | detected, not verified | step-by-step rotation guidance |

## How it compares

| | leakkill | Gitleaks | TruffleHog OSS | GitGuardian | GitHub Secret Protection |
|---|---|---|---|---|---|
| Price | **Free (MIT)** | Free (MIT) | Free (AGPL) | Free for individuals, roughly $15–30/dev/month for teams | Free on public repos, $19/committer/month on private |
| Runs fully local | ✅ | ✅ | ✅ | ❌ SaaS | ❌ GitHub only |
| Detectors | 245 (31 leakkill + 214 imported from Gitleaks, credited) | 150+ | 800+ | 550+ | [provider list](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns) |
| Checks if a key is live | ✅ 17 providers | ❌ | ✅ (its main strength) | ✅ | ✅ some |
| Revokes from the CLI | ✅ 6 providers | ❌ | ❌ (Enterprise) | partial | ❌ |
| Incident report and history-purge steps | ✅ Markdown file | ❌ | ❌ | ✅ dashboard and playbooks | ❌ |
| Guards AI coding agents | ✅ Claude Code hooks | ❌ | ❌ | ❌ | ❌ |
| SARIF / baselines | ✅ / ✅ hashes only | ✅ / ✅ (stores secrets) | ✅ / ❌ | ✅ / ✅ | built in |
| Dependencies | none | Go binary | Go binary | CLI + account | GitHub |

Detector and pricing figures come from public sources in October 2026. Use what fits your needs:
if breadth of detection matters most, run Gitleaks or TruffleHog alongside leakkill.

### Detection rules

leakkill's own 31 rules cover the providers it can verify and revoke. On top of those, it includes
**214 provider rules from [Gitleaks](https://github.com/gitleaks/gitleaks)** (MIT), translated to Python by
[`tools/import_gitleaks.py`](tools/import_gitleaks.py) from a pinned, checksum-verified release, together with
Gitleaks' entropy thresholds and allowlists. Thank you to the Gitleaks maintainers. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

### Speed

Measured on 4 cores (October 2026), wall-clock time for a full scan:

| Repository | leakkill | Gitleaks 8.28 |
|---|---|---|
| psf/requests (130 files) | 0.36 s | 0.63 s |
| pallets/flask (236 files) | 0.31 s | 0.64 s |
| expressjs/express (214 files) | 0.23 s | 0.48 s |
| pallets/flask full history (5,557 commits) | 2.0 s | 1.5 s |
| django/django (7,000 files, 43 MB) | 2.8 s | 1.4 s |

On typical repositories leakkill is faster; on very large ones Gitleaks (Go) is about 2x faster.

### Tested with real credentials

End to end on Windows with real, throwaway credentials:

| Credential | `verify` | `revoke --yes` | `verify` again |
|---|---|---|---|
| GitHub token | LIVE, correct user | REVOKED (HTTP 202) | DEAD |
| Discord webhook | LIVE, correct server and channel | REVOKED (HTTP 204) | DEAD |
| Slack bot token | LIVE, correct bot and workspace | REVOKED | DEAD (the app was uninstalled, as Slack documents) |
| Slack webhook | LIVE | (died with the app) | DEAD |
| Stripe test key | LIVE, correct account, "test mode" | manual roll in dashboard | |
| Hugging Face token | LIVE, correct user and token role | manual delete | |

Against the real AWS, GitLab, Anthropic and npm APIs, invalid keys are correctly reported DEAD.
Providers not yet tested with a live key (OpenAI, OpenRouter, Groq, Replicate, DigitalOcean,
SendGrid, Telegram) are covered by tests using simulated API responses.

### Accuracy (independent dataset)

On [Samsung CredData](https://github.com/Samsung/CredData), 67,896 lines labeled by people, scored by the
same script for every tool ([details and how to reproduce](benchmarks/README.md)):

| | precision | recall | precision / recall without OpenSSL test vectors |
|---|---|---|---|
| **leakkill** | 0.834 | 0.251 | 0.893 / 0.217 |
| Gitleaks 8.28 | 0.860 | 0.453 | 0.910 / 0.218 |
| TruffleHog 3.97 (detection only) | 0.579 | 0.024 | 0.486 / 0.026 |

On ordinary code leakkill matches Gitleaks; it finds 182/209 passwords in URLs (Gitleaks 0). Gitleaks' higher
recall on the full set comes mostly from OpenSSL crypto test vectors that leakkill deliberately doesn't flag.
False alarms on clean repositories (requests, flask, django, express): 1 / 2 / 3 / 0.

### How it's tested

- 108 tests on Linux, macOS and Windows with Python 3.9 and 3.13; CI fails below 88% branch coverage (currently 92%).
- Property-based fuzz tests: the scanner never crashes on random input, never prints a raw secret, finds a
  planted token in any surrounding text, and gives the same answer scanning a whole file or line by line.
  (Fuzzing found two real bugs before release: a guard crash and a slow-input case, both fixed.)
- Every one of the 245 rules is checked in CI against hostile input built from its own keywords, because
  Python's regex engine, unlike Go's, can be made to backtrack for minutes. The sweep found and fixed 4
  such rules among those imported from Gitleaks.
- Live tests against real APIs with real throwaway keys (above), and of the Claude Code guard in the real CLI.
- SonarCloud, OpenSSF Scorecard, pinned and hash-locked CI tooling, signed PyPI provenance.

## Safety model

- `scan` never touches the network.
- A secret is only ever sent to **the provider that issued it**. Hosts are hard-coded, and HTTP
  redirects are never followed, so a credential can't be bounced to another server (this is tested).
- Verification uses read-only identity calls: GitHub `GET /user`, Slack `auth.test`, AWS
  `GetCallerIdentity` and so on.
- `revoke` is a dry run unless you pass `--yes`, and only touches keys that verified as live.
- Raw secrets are never printed or written to the report. The only exception is the opt-in
  `report --replacements FILE` (needed by `git filter-repo`), which is created with permissions 600.

## Cleaning git history

```sh
leakkill revoke --history --yes                 # 1. kill live keys first: history rewrites don't help once copied
pip install git-filter-repo
leakkill report --history --replacements .leakkill-replacements.txt
git filter-repo --replace-text .leakkill-replacements.txt
rm .leakkill-replacements.txt
git push --force --all && git push --force --tags  # every collaborator must re-clone
```

## AI coding agent guard (Claude Code)

`leakkill install-claude-hook` adds hooks to `.claude/settings.json` that block:

- prompts that contain secrets (before they reach the model)
- reading `.env`, `*.pem`, `id_rsa`, `.npmrc` and similar, whether through the Read tool or any
  shell command that names such a file (`cat`, `grep`, `base64`, `python -c`, `cp` …).
  `.env.example` is allowed.
- writing hard-coded keys into code (writing them into `.env` is allowed)

This was tested live with the Claude Code CLI: prompts with keys, `Read .env`, `cat .env`,
`grep . .env` and writing an AWS key into `app.py` were all blocked. The check is pattern-based: a
command that builds the file name at runtime can get past it. Pair it with OS-level permissions for
hard guarantees.

## Use in CI (GitHub Action)

```yaml
- uses: actions/checkout@v4
- uses: ayushanand27/leakkill@v0
```

The build fails if a secret is found, and the incident report appears in the job summary. Options:

```yaml
- uses: ayushanand27/leakkill@v0
  with:
    path: .               # files or directories to scan
    exclude-tests: true   # skip test_* files and tests/ dirs
    history: true         # scan every commit (needs `fetch-depth: 0` on checkout)
    verify: true          # check secrets with their providers; fail only if one is LIVE
```

The action exposes `found` (the number of unique secrets) as an output. Outside GitHub Actions, use
`pip install leakkill && leakkill scan .`.

### Findings in the GitHub Security tab (SARIF)

```yaml
permissions:
  contents: read
  security-events: write   # needed to upload SARIF
steps:
  - uses: actions/checkout@v4
  - uses: ayushanand27/leakkill@v0
    id: leakkill
  - uses: github/codeql-action/upload-sarif@v3
    if: always()           # upload even when leakkill fails the build
    with:
      sarif_file: ${{ steps.leakkill.outputs.sarif-file }}
```

Outside the Action: `leakkill scan --sarif results.sarif .` (validated against the OASIS SARIF 2.1.0 schema).
The SARIF never contains secrets, only a masked prefix and a truncated hash.

## GitLab CI

```yaml
leakkill:
  image: python:3.12-slim
  script:
    - pip install leakkill
    - leakkill scan --exclude-tests --sarif gl-leakkill.sarif .
  artifacts:
    when: always
    paths: [gl-leakkill.sarif]
```

## Baselines: adopt it on a repo that already has old findings

```sh
leakkill scan --write-baseline .leakkill-baseline.json .   # accept what's there today
leakkill scan --baseline .leakkill-baseline.json .          # from now on, fail only on new secrets
```

The baseline file is safe to commit: it holds only salted scrypt hashes, never secrets, and scrypt is
deliberately slow so even weak passwords can't practically be brute-forced back out of it. (Gitleaks'
baseline is its previous report, which includes the secrets themselves.) Accepting a finding into the
baseline doesn't make it safe: revoke real keys first.

## Use with the pre-commit framework

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/ayushanand27/leakkill
    rev: v0.3.0
    hooks:
      - id: leakkill
```

Or without the framework: `leakkill install-hook`.

## Suppressing false positives

- Add `leakkill:ignore` on a line.
- List paths or globs in `.leakkillignore` (for example `fixtures/` or `*.snap`).
- High-entropy matches ignore placeholders (`your_key`, `example`, `${VAR}`), variables named
  test/example/fake/mock, password hashes and values without digits.

## Known limitations

- Detection breadth is close to Gitleaks (whose rules it includes) but below TruffleHog (800+ detectors).
- On very large repositories (tens of MB) scanning is about 2x slower than Gitleaks.
- Verification behind a proxy that injects its own credentials (some corporate and sandbox proxies
  do) can report the proxy's identity. Run `verify` from a normal network.
- AWS keys can only be verified when the secret key is found too (any file in the scan).
- Stripe, OpenAI, Anthropic, npm and Telegram offer no revoke API, so those need a manual click.

MIT licensed.
