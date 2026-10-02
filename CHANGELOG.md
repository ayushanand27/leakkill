# Changelog

## 0.7.1 (2026-10-02)

- Friendlier output: after a scan, verify or `--agents` run, one line says what to do next (`leakkill verify`,
  then `leakkill revoke` / `leakkill report`), keeping flags like `--agents`. JSON output is unchanged.
- Postman and Netlify checks confirmed with real keys (LIVE, correct account, then DEAD after deletion).

## 0.7.0 (2026-10-02)

- `verify` checks 15 more services, 32 in total: Postman, Linear, Notion, Sentry, Netlify, Doppler, Pulumi,
  Heroku, Brevo, Square, Airtable, Dropbox, LaunchDarkly, Cloudflare and Mailchimp, each with a read-only
  "who am I" call to its own hard-coded host. A key is reported DEAD only on HTTP 401; any other answer is
  UNKNOWN, so an unexpected response never makes a live key look safe. Revoke guidance links each dashboard.
- `--agents` now reads Cursor and VS Code (Copilot Chat) chat histories from their `state.vscdb` SQLite
  databases, read-only (standard library `sqlite3`, still no dependencies); findings point at table and row.

## 0.6.1 (2026-10-02)

- Docker image: `docker run --rm -v "$PWD:/scan" ghcr.io/ayushanand27/leakkill`, published to GitHub
  Packages with every release (smoke-tested in CI, including `--history`).
- Credentials in URLs written as templates (`MASTER_USER:MASTER_PASSWORD@RDS_ENDPOINT`) are no longer reported
  (found when scanning a real machine with `--agents`). URL recall on CredData unchanged (182/209).
- Docs: `docs/` command reference; CONTRIBUTING.md; OpenSSF Best Practices badge (passing).

## 0.6.0 (2026-10-02)

- AI agent guard for **Cursor, GitHub Copilot CLI and OpenAI Codex**, in addition to Claude Code:
  `leakkill install-agent-hooks [claude|cursor|copilot|codex ...] [--global]`, and `leakkill guard --agent`.
  Cursor also blocks reads of files whose content holds a key (respecting `.leakkillignore`); Codex
  `apply_patch` edits are checked file by file, so writing keys into `.env` stays allowed.
  `install-claude-hook` still works.
- `--agents` (scan, verify, report, revoke): find secrets that AI coding agents stored on this machine:
  session transcripts and histories (Claude Code, Codex, Copilot CLI, Gemini CLI), and MCP configs (Cursor,
  Windsurf, Claude Desktop, VS Code, project `.mcp.json`). JSONL transcripts are decoded, streamed in chunks and
  reported by line; the agents' own login files are skipped.
- Fewer false alarms from code: template values (`AKIA{R(16)}`), URLs and `filename=...` are not secrets, and
  imported rules ignore placeholders and env var names (`YOUR_NEW_TOKEN`, `${PASSWORD}`).
- Security: the agent guard no longer repeats a secret from a file name back to the agent (found by the new
  ClusterFuzzLite fuzzer); the `--replacements` file is created owner-only (0600) from the start instead of
  being restricted after writing, and never overwrites an existing file (so `--replacements ~/.bashrc` is refused).
- Coverage-guided fuzzing (Atheris + ClusterFuzzLite) on pull requests and weekly; GitHub releases are
  Sigstore-signed; the CodeQL workflow has pinned actions and least-privilege permissions; Google's sample
  keys in the imported allowlist are written as `AIz[a]...` so GitHub secret scanning stops flagging them.
- Recall on real code up from 0.217 to 0.300 on Samsung CredData, with precision up from 0.893 to 0.921 (0.922 in 0.6.1)
  (OpenSSL test vectors excluded; full dataset: recall 0.251 to 0.510, F1 0.386 to 0.630):
  - HTTP Basic auth (`Authorization: Basic …`), reported only when it decodes to a real-looking
    `user:password` (601/601 in CredData, no new false positives).
  - Bare `key` names (`key = "…"`, `"Key": "…"`, `nkey`, `hexkey`) with token-shaped values, filtering
    dict/sort/cache/public keys, struct tags, ARNs and k8s labels.
  - Measured before porting: almost all of Betterleaks' extra recall comes from its generic rule, not its
    other 462 rules, so those were not imported. See benchmarks/README.md.

## 0.5.0 (2026-10-02)

- 245 detection rules: leakkill's own 31 plus 214 provider rules imported from Gitleaks v8.28.0 (MIT,
  credited; see THIRD_PARTY_NOTICES.md) with their entropy thresholds and allowlists.
- About 8x faster scanning (whole-file matching, keyword prefilter, all CPU cores). Faster than Gitleaks on
  typical repositories; about 2x slower on very large ones.
- `--sarif FILE`: SARIF 2.1.0 output for GitHub's Security tab (schema-validated); the Action exposes it as
  the `sarif-file` output.
- `--write-baseline` / `--baseline`: only fail on new secrets. Baselines hold salted scrypt hashes, never
  secrets.
- GitLab CI example.
- Generic `name = value` rule now also finds JSON/YAML/PHP-style keys (`"secret": "..."`, `'key' => '...'`),
  unquoted `.env`/YAML values, and `access_key` / `credential` / `client_key` names, while filtering code-like
  values (`self.attr`, `SNAKE_CASE`) and `author`/`authority`.
- Robustness: every rule is linear-time on hostile input (4 imported Gitleaks rules were catastrophically
  slow under Python's regex engine and are rewritten by the importer; a CI test sweeps all 245 rules).
- Property-based fuzz tests; branch coverage 92% with an 88% CI gate.
- Claude Code guard normalizes unexpected input and fails closed (blocks) on internal errors.
- Independent accuracy benchmark on Samsung CredData against Gitleaks and TruffleHog, with the evaluation
  script (benchmarks/).

## 0.4.2 (2026-10-02)

- Fix: the high-entropy assignment rule could take quadratic time on very long lines (e.g. minified
  bundles), stalling a scan or the Claude Code guard. Matching is now linear; regression-tested on
  multi-megabyte lines.
- The GitHub Action runs leakkill straight from its own source: nothing is downloaded from PyPI into
  your CI.
- CI and release tooling is installed from a hash-locked file (`requirements/ci.txt`), wheels only,
  and packages are built without fetching unpinned build dependencies.
- `install-hook` only adds the execute bit for the file owner.

## 0.4.1 (2026-10-02)

- Fix: a mistyped command (e.g. `leakkill verfiy`) or a missing path was scanned as an empty path and
  reported "Clean.". It is now an error (exit code 2) with a "did you mean" hint.

## 0.4.0 (2026-10-02)

- GitHub Action: `uses: ayushanand27/leakkill@v0` scans in CI, fails the build on leaks, and writes the
  incident report to the job summary (`verify: true` fails only on live keys).
- New providers with verification: Hugging Face, OpenRouter, Groq, Replicate, DigitalOcean, SendGrid
  (SendGrid keys can also revoke themselves).
- New detectors: Shopify, PyPI, Docker Hub, Twilio, Postman, Perplexity, Linear, Azure Storage, Stripe
  test-mode keys. 31 detectors in total, 17 verifiable, 6 revocable.
- `scan`/`verify --report FILE` writes the incident report from the same run.
- `revoke` warns about side effects before acting (e.g. revoking a Slack bot token uninstalls the app).
- Live-tested with real Slack (bot token and webhook), Stripe test key and Hugging Face token.
- OpenRouter keys are no longer misreported as OpenAI keys.

## 0.3.0 (2026-10-02)

First public release.

- `verify`: checks whether a leaked secret is live, and whose it is, against the provider that
  issued it (GitHub, GitLab, Slack, Slack and Discord webhooks, Stripe, AWS, OpenAI, Anthropic,
  npm, Telegram).
- `revoke`: revokes live keys through provider APIs (GitHub, GitLab, Slack, Discord, AWS). It is a
  dry run unless you pass `--yes`.
- `report`: Markdown incident report with cleanup steps and a `git filter-repo` replacements file.
- `scan --history` finds secrets in every commit, including ones already deleted.
- Claude Code guard: blocks prompts containing secrets, reads of `.env`/key files (Read tool or any
  shell command), and hard-coded secrets in generated code.
- pre-commit framework hook and `leakkill install-hook`.
- `.leakkillignore` and `leakkill:ignore` for false positives.
