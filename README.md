# secretscan

Zero-dependency Python tool that stops secrets from leaking - from your code, your git history, **and your AI coding agent**.

## Why
Leaked API keys are still a top cause of breaches. Tools like gitleaks and TruffleHog scan repos well, but a new
leak path is wide open: AI coding agents read `.env` files into model context, and paste keys into prompts,
shell commands and generated code. `secretscan --guard` closes that path.

## Usage
```bash
python secretscan.py .                  # scan a folder
python secretscan.py --staged           # scan staged changes only
python secretscan.py --history          # scan every commit ever made (finds "deleted" secrets)
python secretscan.py --install-hook     # git pre-commit hook: block commits containing secrets
python secretscan.py --install-claude-hook   # guard Claude Code in this project (writes .claude/settings.json)
```

### AI agent guard (Claude Code hooks)
After `--install-claude-hook`, secretscan blocks, before they happen:
- prompts that contain a secret
- the agent **reading** `.env`, `*.pem`, `id_rsa`, `.npmrc`, ... (Read tool or `cat .env` in Bash)
- the agent **writing** a hard-coded key into code or shell commands (it is told to use an env var instead)

Writing to `.env` itself is allowed. Malformed hook input never breaks the agent (fails open).

## Details
Detects AWS/GitHub/Slack/Google/Stripe/OpenAI/Anthropic keys, JWTs, private keys, DB URLs with passwords, and
high-entropy values assigned to secret-looking names. Output is always masked. Suppress a line with
`# secretscan:ignore`; use `--exclude-tests` to skip `test_*` files. Exit code 1 when anything is found.

## Limits / roadmap
Pattern + entropy based (no live-key verification yet); false positives possible; no auto-rotation yet.
Planned: provider-verified keys, auto-revoke/rotate, more agent integrations, allowlist file.

Tests: `pip install pytest && pytest`.  License: MIT
