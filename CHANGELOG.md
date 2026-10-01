# Changelog

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
- pre-commit framework hook and `secretscan install-hook`.
- `.secretscanignore` and `secretscan:ignore` for false positives.
