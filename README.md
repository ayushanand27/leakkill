# leakkill

[![PyPI](https://img.shields.io/pypi/v/leakkill)](https://pypi.org/project/leakkill/) [![CI](https://github.com/ayushanand27/leakkill/actions/workflows/ci.yml/badge.svg)](https://github.com/ayushanand27/leakkill/actions/workflows/ci.yml) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ayushanand27/leakkill/badge)](https://scorecard.dev/viewer/?uri=github.com/ayushanand27/leakkill) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15151/badge)](https://www.bestpractices.dev/projects/15151)

**Leaked a key? Find it, see if it's live, and kill it in one command. Free, local, zero dependencies.**

Most secret scanners stop at *finding* secrets. leakkill also answers what comes next: is this key still
working, whose account is it, how do I revoke it right now, and how do I clean it out of git history? It installs
with a plain `pip install` (no dependencies), runs locally, and can stop AI coding agents from reading or writing
secrets in the first place.

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

Try it without installing: `uvx leakkill scan` or `pipx run leakkill scan` (scans the current folder).

Python 3.9+, no dependencies. Latest development version:
`pip install git+https://github.com/ayushanand27/leakkill`

Or with Docker, no Python needed:

```sh
docker run --rm -v "$PWD:/scan" ghcr.io/ayushanand27/leakkill            # scan this folder
docker run --rm -v "$PWD:/scan" ghcr.io/ayushanand27/leakkill --history  # every commit
```

## Commands

| Command | What it does | Network? |
|---|---|---|
| `leakkill init` | Set a project up in one step: the git hook, the guards for the AI agents you use, and a CI workflow. Adds only, never overwrites. | **Never** |
| `leakkill [scan] [PATH ...]` | Find secrets. Exit code 1 if any. | **Never** |
| `leakkill scan <github-url>` | Check a repository **before you trust it**: clones read-only to a temp folder, scans, deletes it (`--history` for every commit). Only scans; `verify`/`revoke` are refused, because they would test keys that belong to someone else. | Only the clone |
| `leakkill verify` | Also check each secret against the provider that issued it: live or dead, which account, which scopes | Read-only "who am I" calls |
| `leakkill revoke` | Show what can be revoked. With `--yes`, revoke the live ones (`--only 1,3` to pick) | Only with `--yes` |
| `leakkill report` | Write `leakkill-report.md`: every leak, its status and owner, and the cleanup steps in order | Same as `verify` (`--no-verify` to skip) |
| `leakkill install-hook` | Git pre-commit hook that blocks commits containing secrets | Never |
| `leakkill install-agent-hooks` | Stop AI coding agents (Claude Code, Cursor, GitHub Copilot, OpenAI Codex) reading `.env` and keys, sending secrets in prompts, or writing secrets into code | Never |

Every scan command also accepts `--include-ignored` (also scan `.gitignore`d files, which are left out by default), `--staged` (pre-commit), `--history` (every commit on every branch,
including secrets you already "deleted"), `--agents` (secrets your AI coding agents stored on this machine, see
below), `--exclude-tests` and `--json`.

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
| Postman, Linear, Notion, Sentry, Netlify, Doppler, Pulumi, Heroku, Brevo, Square, Airtable, Dropbox, LaunchDarkly, Cloudflare, Mailchimp | ✅ (account where the API returns it); live only on HTTP 200, dead only on 401 | ❌ you get the exact page to revoke it |
| Google API keys, Shopify, PyPI, Docker Hub, Twilio, Perplexity, Azure Storage, private keys, JWTs, credentials in URLs and Basic auth headers, generic high-entropy secrets | detected, not verified | step-by-step rotation guidance |

## How it compares

| | leakkill | Kingfisher | Betterleaks | Gitleaks | TruffleHog OSS | GitGuardian |
|---|---|---|---|---|---|---|
| License / price | MIT, free | Apache 2.0, free | MIT, free | MIT, free | AGPL, free | free for individuals, paid for teams |
| Runs fully local | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ SaaS |
| Install | `pip` (zero dependencies) or Docker | Rust binary | Go binary | Go binary | Go binary | CLI + account |
| Detection rules | 246 | ~485 | 463 | 150+ | 800+ | 550+ |
| Checks if a key is live | ✅ 32 services | ✅ hundreds | ✅ | ❌ | ✅ 700+ | ✅ |
| Revokes from the CLI | ✅ 6 providers | ✅ some providers | ❌ | ❌ | ❌ (Enterprise) | partial |
| Remediation report with ordered steps + history purge | ✅ | HTML report, blast-radius map | ❌ | ❌ | ❌ | ✅ |
| Guards AI coding agents | ✅ Claude Code, Cursor, Copilot, Codex | ❌ | ❌ | ❌ | ❌ | ✅ (hooks, paid platform) |
| Scans Slack / Jira / S3 / Docker | ❌ | ✅ | ❌ | ❌ | ✅ | ✅ |
| SARIF / baselines | ✅ / ✅ hashes only | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ (stores secrets) | ✅ / ❌ | ✅ / ✅ |

**Where each is strongest** (accuracy below): Betterleaks finds the most real credentials; Kingfisher has the
fewest false alarms and the broadest platform coverage with validation and revocation; TruffleHog verifies the
most providers. leakkill's niche is a dependency-free `pip install` that goes from finding to revoked key to
cleanup plan, guards AI coding agents, and is the best of these at passwords embedded in URLs and Basic auth headers.

Figures from each project's documentation, October 2026. Use what fits: running two scanners is common.

### Detection rules

leakkill's own 32 rules cover the providers it can verify and revoke. On top of those, it includes
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
| Postman API key | LIVE, correct username | manual delete (page linked) | DEAD |
| Netlify access token | LIVE, correct account email | manual delete (page linked) | DEAD |

Against the real AWS, GitLab, Anthropic and npm APIs, invalid keys are correctly reported DEAD.
Providers not yet tested with a live key (OpenAI, OpenRouter, Groq, Replicate, DigitalOcean,
SendGrid, Telegram, and the other 13 added in 0.7) are covered by tests using simulated API responses.

### Accuracy (independent dataset)

On [Samsung CredData](https://github.com/Samsung/CredData), 67,896 lines labeled by people, every tool scored
by the same script ([details and how to reproduce](benchmarks/README.md)):

| | precision | recall | F1 | without OpenSSL test vectors (P / R / F1) | passwords in URLs | HTTP Basic auth |
|---|---|---|---|---|---|---|
| **leakkill 0.6** | 0.825 | 0.510 | **0.630** | 0.922 / 0.300 / 0.453 | **182/209** | **601/601** |
| Betterleaks 1.9 | 0.712 | **0.562** | 0.628 | 0.585 / **0.379** / **0.460** | 96/209 | 10/601 |
| Gitleaks 8.28 | 0.860 | 0.453 | 0.594 | 0.910 / 0.218 / 0.351 | 0/209 | 0/601 |
| Kingfisher 2.9 (no validation) | **0.961** | 0.104 | 0.187 | **0.925** / 0.079 / 0.145 | 20/209 | 5/601 |
| TruffleHog 3.97 (no verification) | 0.579 | 0.024 | 0.045 | 0.486 / 0.026 / 0.049 | 59/209 | 0/601 |

Compare on the "without OpenSSL test vectors" column: those are public crypto test data, not leaks. There,
leakkill and Betterleaks are level on F1. Betterleaks finds more credentials (recall 0.379 vs 0.300); leakkill
raises far fewer false alarms (precision 0.922 vs 0.585). leakkill is far ahead on passwords in URLs and Basic
auth headers, because it decodes and checks them. The generic rules were tuned on this dataset, which flatters
leakkill somewhat; false alarms on four clean repositories (requests, flask, django, express) stayed at
1 / 2 / 3 / 0.

### How it's tested

- 191 tests on Linux, macOS and Windows with Python 3.9 and 3.13; CI fails below 88% branch coverage (currently 93%).
- Property-based fuzz tests: the scanner never crashes on random input, never prints a raw secret, finds a
  planted token in any surrounding text, and gives the same answer scanning a whole file or line by line.
  (Fuzzing found two real bugs before release: a guard crash and a slow-input case, both fixed.)
- Coverage-guided fuzzing with Atheris via ClusterFuzzLite on every pull request and weekly, of the scanner,
  the transcript reader and the AI agent guard. Its first run found a real bug in under a minute: the
  guard could quote a secret hidden in a file name back to the agent. Fixed, with a regression test.
- Every one of the 246 rules is checked in CI against hostile input built from its own keywords, because
  Python's regex engine, unlike Go's, can be made to backtrack for minutes. The sweep found and fixed 4
  such rules among those imported from Gitleaks.
- Live tests against real APIs with real throwaway keys (above), and of the Claude Code guard in the real CLI.
- OpenSSF Best Practices (passing), SonarCloud, OpenSSF Scorecard, pinned and hash-locked CI tooling, signed PyPI provenance, Sigstore-signed GitHub releases (see SECURITY.md).

## Safety model

- `scan` never touches the network.
- A secret is only ever sent to **the provider that issued it**. Hosts are hard-coded, and HTTP
  redirects are never followed, so a credential can't be bounced to another server (this is tested).
- Verification uses read-only identity calls: GitHub `GET /user`, Slack `auth.test`, AWS
  `GetCallerIdentity` and so on.
- `revoke` is a dry run unless you pass `--yes`, and only touches keys that verified as live.
- Raw secrets are never printed or written to the report. The only exception is the opt-in
  `report --replacements FILE` (needed by `git filter-repo`), which is created with permissions 600 and never overwrites an existing file.

## Cleaning git history

```sh
leakkill revoke --history --yes                 # 1. kill live keys first: history rewrites don't help once copied
pip install git-filter-repo
leakkill report --history --replacements .leakkill-replacements.txt
git filter-repo --replace-text .leakkill-replacements.txt
rm .leakkill-replacements.txt
git push --force --all && git push --force --tags  # every collaborator must re-clone
```

## AI coding agent guard

```sh
leakkill install-agent-hooks                 # all four, in this project
leakkill install-agent-hooks cursor codex    # just these
leakkill install-agent-hooks --global        # for your user account, every project
```

| Agent | Config written | Secret in a prompt | Reading `.env` / keys (file or shell) | Writing a key into code |
|---|---|---|---|---|
| Claude Code | `.claude/settings.json` | blocked | blocked | blocked |
| Cursor | `.cursor/hooks.json` | blocked | blocked, and any file whose content holds a key | blocked |
| GitHub Copilot CLI | `.github/hooks/leakkill.json` | warned only (Copilot ignores prompt-hook decisions) | blocked | blocked |
| OpenAI Codex | `.codex/hooks.json` | blocked | blocked | blocked, per file of each `apply_patch` |

Sensitive files are `.env` (but not `.env.example`), `*.pem`, `*.key`, `id_rsa`, `.npmrc`, `.pypirc` and
similar; a shell command that names one (`cat`, `grep`, `base64`, `python -c`, `cp` …) is blocked too.
Writing keys **into** `.env` is allowed, since that is where they belong. If the guard itself fails, it
blocks rather than lets a secret through. Codex only runs hooks you trust: after installing, type
`/hooks` in Codex and trust the leakkill hook.

Tested live with the Claude Code CLI: prompts with keys, `Read .env`, `cat .env`, `grep . .env` and
writing an AWS key into `app.py` were all blocked. Cursor, Copilot and Codex are tested against the hook
formats in their documentation, through the same command they run; if you see one misbehave, please open
an issue. The check is pattern-based: a command that builds the file name at runtime can get past it.
Pair it with OS-level permissions for hard guarantees.

## Secrets your AI agents already stored

```sh
leakkill scan --agents      # what's there
leakkill verify --agents    # ...and which of those keys still work
```

AI coding agents keep plain-text session transcripts and prompt histories, and MCP server configs often hold
API keys. A key you pasted into a chat, or a `.env` the agent read, stays on disk there, and was sent to the
model provider. `--agents` scans, on your machine only:

- Claude Code (`~/.claude.json`, `~/.claude/` including session transcripts), Codex (`~/.codex/`), GitHub
  Copilot CLI (`~/.copilot/`), Gemini CLI (`~/.gemini/`), Cursor and VS Code (Copilot Chat) chat histories, Cursor, Windsurf, Claude Desktop and VS Code MCP configs
- this project's `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.claude/settings*.json`, `.gemini/settings.json`

Transcripts are decoded, so a key behind JSON escapes is still found and reported at its line. The agents' own
login files (`~/.codex/auth.json`, `~/.claude/.credentials.json`, Gemini's OAuth file) are skipped, since that is
where their tokens belong. Cursor and VS Code keep chats in SQLite databases (`state.vscdb`); they are opened read-only, so a running editor is never disturbed.

## Use in CI (GitHub Action)

```yaml
- uses: actions/checkout@v7
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
  - uses: actions/checkout@v7
  - uses: ayushanand27/leakkill@v0
    id: leakkill
  - uses: github/codeql-action/upload-sarif@v4
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
    rev: v0.8.0
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

- Finds fewer real credentials than Betterleaks (recall 0.30 vs 0.38 on real code in CredData, with far fewer
  false alarms), and has fewer rules than Kingfisher or TruffleHog.
- Scans files, git history and local AI agent files: not Slack, Jira, Confluence, S3 or Docker images.
- The agent guard is pattern-based: a command that builds a file name at runtime can get past it. The Cursor,
  Copilot and Codex guards are tested against their documented hook formats; only Claude Code was tested in the
  real app. Copilot ignores prompt hooks, so a key typed into a Copilot prompt is warned about, not blocked.
- On very large repositories (tens of MB) scanning is about 2x slower than Gitleaks.
- Verification behind a proxy that injects its own credentials (some corporate and sandbox proxies
  do) can report the proxy's identity. Run `verify` from a normal network.
- AWS keys can only be verified when the secret key is found too (any file in the scan).
- Stripe, OpenAI, Anthropic, npm and Telegram offer no revoke API, so those need a manual click.

MIT licensed.
