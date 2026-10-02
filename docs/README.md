# leakkill documentation

- [Getting started](#getting-started)
- [Command reference](#command-reference)
- [Options](#options)
- [Exit codes](#exit-codes)
- [Output formats](#output-formats)
- [Configuration files](#configuration-files)
- [AI agent guard](#ai-agent-guard)
- [More](#more)

## Getting started

```sh
pip install leakkill          # Python 3.9+, no dependencies
leakkill                      # scan the current directory (offline)
leakkill verify               # ...and check which secrets are live, and whose they are
leakkill revoke               # see what can be revoked; add --yes to do it
leakkill report               # write leakkill-report.md with cleanup steps in order
```

## Command reference

| Command | Does | Network |
|---|---|---|
| `leakkill [scan] [PATH ...]` | Find secrets in files (default `.`). | never |
| `leakkill verify [PATH ...]` | Scan, then ask each secret's issuer whether it is live and whose it is (read-only identity calls). | yes, only to the issuer |
| `leakkill revoke [PATH ...] [--only 1,3] [--yes]` | Verify, then list what can be revoked. Revokes only live keys, and only with `--yes`. | only with `--yes` |
| `leakkill report [PATH ...] [-o FILE] [--no-verify] [--replacements FILE]` | Write a Markdown incident report (default `leakkill-report.md`). `--replacements` writes a `git filter-repo --replace-text` file (owner-only, never overwrites). | like `verify` |
| `leakkill install-hook` | Git pre-commit hook that blocks commits containing secrets. | never |
| `leakkill install-agent-hooks [claude] [cursor] [copilot] [codex] [--global]` | Install the AI agent guard (all four by default; `--global` = your user account). | never |
| `leakkill install-claude-hook` | Same as `install-agent-hooks claude`. | never |
| `leakkill guard [--agent AGENT]` | Hook entry point the agents call; reads hook JSON on stdin. | never |
| `leakkill --version` / `--help` | Version / built-in help. | never |

## Options

Available on `scan`, `verify`, `revoke` and `report`:

| Option | Meaning |
|---|---|
| `--staged` | Scan staged git changes (what you are about to commit). |
| `--history` | Scan every commit on every branch, including secrets you already "deleted". |
| `--agents` | Scan AI agents' files on this machine: MCP configs, settings, session transcripts. |
| `--exclude-tests` | Skip `test_*` files and `tests/` directories. |
| `--json` | Machine-readable output (see below). |
| `--baseline FILE` | Ignore secrets recorded in a baseline file. |

Also on `scan` and `verify`: `--report FILE`, `--sarif FILE`, `--write-baseline FILE`.

## Exit codes

| Code | `scan` | `verify` | `revoke` | `report` |
|---|---|---|---|---|
| 0 | no secrets | no live secrets | nothing left to do | no secrets |
| 1 | secrets found | a live secret found | live secrets remain (dry run, failure, or manual steps) | secrets found |
| 2 | bad arguments or a path that doesn't exist | same | same | same, or `--replacements` file already exists |

The guard exits 0 to allow and 2 to block (the convention all supported agents use).

## Output formats

- **Text** (default): one line per unique secret: id, status (with `verify`), type, masked value, locations.
- **JSON** (`--json`): a list of `{"id", "type", "value" (masked), "status", "identity", "note", "locations"}`.
- **SARIF 2.1.0** (`--sarif FILE`): for GitHub code scanning; holds masked values and truncated hashes only.
- **Markdown report** (`report`, or `--report FILE`): every leak with status, owner and ordered cleanup steps.

Raw secrets are never printed. The only file that contains them is the opt-in `--replacements` file.

## Configuration files

- **`.leakkillignore`**: glob patterns (one per line) for paths to skip, e.g. `fixtures/` or `*.snap`.
- **`leakkill:ignore`**: put this comment on a line to ignore that line.
- **Baseline** (`--write-baseline` / `--baseline`): JSON with salted scrypt hashes, safe to commit.

## AI agent guard

`install-agent-hooks` writes `.claude/settings.json`, `.cursor/hooks.json`, `.github/hooks/leakkill.json`
and `.codex/hooks.json`. The guard blocks secrets in prompts (Copilot only warns), reads of `.env`/keys
(as files or via shell commands), and keys written into code (writing them into `.env` is allowed).
See the [main README](../README.md#ai-coding-agent-guard) for the per-agent table and limitations.

## More

- [README](../README.md): overview, comparison, accuracy benchmark, CI and pre-commit setup.
- [SECURITY.md](../SECURITY.md): reporting vulnerabilities, verifying releases.
- [CONTRIBUTING.md](../CONTRIBUTING.md): how to contribute.
- [benchmarks/](../benchmarks/README.md): how accuracy was measured.
