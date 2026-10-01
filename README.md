# secretscan

**Leaked a key? Find it, see if it's live, and kill it in one command. Free, local, zero dependencies.**

Free tools are great at *finding* secrets. What happens *after* a leak is usually left to paid
platforms: is this key still working, whose account is it, how do I revoke it right now, and how do
I clean it out of git history? secretscan does that part too, from your terminal, for free.

```console
$ secretscan verify
#1   LIVE         GitHub token           ghp_************     config.py:3
      octocat  scopes: repo, workflow
#2   DEAD         AWS access key         AKIA************     deploy/old.sh:12
      key id is unknown or deactivated
#3   UNVERIFIABLE Credentials in URL     postgres://app:****@db.prod.internal  .env.backup:1

3 unique secret(s), 1 LIVE.

$ secretscan revoke --only 1 --yes
  #1 GitHub token: REVOKED (HTTP 202)
```

## Install

```sh
pip install "git+https://github.com/ayushanand27/real_work_with_me#subdirectory=secretscan"
```

Python 3.9+, no dependencies. The PyPI release (`pip install secretscan`) is coming soon.

## Commands

| Command | What it does | Network? |
|---|---|---|
| `secretscan [scan] [PATH ...]` | Find secrets. Exit code 1 if any. | **Never** |
| `secretscan verify` | Also check each secret against the provider that issued it: live or dead, which account, which scopes | Read-only "who am I" calls |
| `secretscan revoke` | Show what can be revoked. With `--yes`, revoke the live ones (`--only 1,3` to pick) | Only with `--yes` |
| `secretscan report` | Write `secretscan-report.md`: every leak, its status and owner, and the cleanup steps in order | Same as `verify` (`--no-verify` to skip) |
| `secretscan install-hook` | Git pre-commit hook that blocks commits containing secrets | Never |
| `secretscan install-claude-hook` | Stop Claude Code reading `.env` and keys or writing secrets into code | Never |

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
| Stripe, OpenAI, Anthropic, npm, Telegram, Slack webhooks | ✅ | ❌ the provider has no API for it, so you get the exact page or command |
| Google API keys, private keys, JWTs, credentials in URLs, generic high-entropy secrets | detected, not verifiable | step-by-step rotation guidance |

## How it compares

| | secretscan | Gitleaks | TruffleHog OSS | GitGuardian | GitHub Secret Protection |
|---|---|---|---|---|---|
| Price | **Free (MIT)** | Free (MIT) | Free (AGPL) | Free for individuals, roughly $15–30/dev/month for teams | Free on public repos, $19/committer/month on private |
| Runs fully local | ✅ | ✅ | ✅ | ❌ SaaS | ❌ GitHub only |
| Detectors | ~17 | 150+ | 800+ | 550+ | [provider list](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns) |
| Checks if a key is live | ✅ 11 providers | ❌ | ✅ (its main strength) | ✅ | ✅ some |
| Revokes from the CLI | ✅ 5 providers | ❌ | ❌ (Enterprise) | partial | ❌ |
| Incident report and history-purge steps | ✅ Markdown file | ❌ | ❌ | ✅ dashboard and playbooks | ❌ |
| Guards AI coding agents | ✅ Claude Code hooks | ❌ | ❌ | ❌ | ❌ |
| Dependencies | none | Go binary | Go binary | CLI + account | GitHub |

Detector and pricing figures come from public sources in October 2026. Use what fits your needs:
if breadth of detection matters most, run Gitleaks or TruffleHog alongside secretscan.

### Tested with real credentials

End to end on Windows with a real GitHub token and a real Discord webhook: `verify` reported both
LIVE with the right account and channel, `revoke --yes` returned GitHub `202` and Discord `204`, and
re-running `verify` reported both DEAD. Against the real AWS, GitLab, Anthropic and npm APIs, invalid
keys are correctly reported DEAD. Providers not yet tested with a live key (Slack, Stripe, OpenAI,
Telegram) are covered by tests using simulated API responses.

### Benchmark (reproducible, run October 2026)

Noise on clean, popular repos (unique secrets reported, default settings):

| Repo | secretscan | Gitleaks 8.28 |
|---|---|---|
| psf/requests | 1 (private-key test fixtures) | 4 (same fixtures, one per file) |
| pallets/flask | 2 (docs example `SECRET_KEY`s) | 2 (same) |
| django/django | 1 (a CSRF test fixture) | 8 |
| expressjs/express | 0 | 0 |

Recall on 17 planted realistic secrets: **secretscan 17/17, Gitleaks 14/17**. Gitleaks missed a
Postgres URL with a password, a Discord webhook and a Telegram bot token. The planted set was written
by us, so it is biased toward formats we support. Gitleaks detects many formats we don't.

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
secretscan revoke --history --yes                 # 1. kill live keys first: history rewrites don't help once copied
pip install git-filter-repo
secretscan report --history --replacements .secretscan-replacements.txt
git filter-repo --replace-text .secretscan-replacements.txt
rm .secretscan-replacements.txt
git push --force --all && git push --force --tags  # every collaborator must re-clone
```

## AI coding agent guard (Claude Code)

`secretscan install-claude-hook` adds hooks to `.claude/settings.json` that block:

- prompts that contain secrets (before they reach the model)
- reading `.env`, `*.pem`, `id_rsa`, `.npmrc` and similar, whether through the Read tool or any
  shell command that names such a file (`cat`, `grep`, `base64`, `python -c`, `cp` …).
  `.env.example` is allowed.
- writing hard-coded keys into code (writing them into `.env` is allowed)

This was tested live with the Claude Code CLI: prompts with keys, `Read .env`, `cat .env`,
`grep . .env` and writing an AWS key into `app.py` were all blocked. The check is pattern-based: a
command that builds the file name at runtime can get past it. Pair it with OS-level permissions for
hard guarantees.

## Use in CI (GitHub Actions)

```yaml
- run: pip install "git+https://github.com/ayushanand27/real_work_with_me#subdirectory=secretscan"
- run: secretscan scan --exclude-tests .
```

## Suppressing false positives

- Add `secretscan:ignore` on a line.
- List paths or globs in `.secretscanignore` (for example `fixtures/` or `*.snap`).
- High-entropy matches ignore placeholders (`your_key`, `example`, `${VAR}`), variables named
  test/example/fake/mock, password hashes and values without digits.

## Known limitations

- Fewer detectors than Gitleaks or TruffleHog.
- Verification behind a proxy that injects its own credentials (some corporate and sandbox proxies
  do) can report the proxy's identity. Run `verify` from a normal network.
- AWS keys can only be verified when the secret key is found too (any file in the scan).
- Stripe, OpenAI, Anthropic, npm and Telegram offer no revoke API, so those need a manual click.

MIT licensed.
