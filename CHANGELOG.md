# Changelog

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
