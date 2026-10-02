# Changelog

## 0.5.0 (unreleased)

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
