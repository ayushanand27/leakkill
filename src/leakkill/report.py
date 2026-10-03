"""Incident report: what leaked, is it live, whose is it, and the exact steps to clean up."""
import os, subprocess
from datetime import datetime, timezone

from .providers import LIVE, DEAD, provider
from .scanner import run_git


def tracked_files():
    try:
        out = run_git("ls-files", "-z", text=True, check=True).stdout
        return {os.path.normpath(p) for p in out.split("\0") if p}
    except (OSError, subprocess.CalledProcessError):
        return None  # not a git repo


def in_git(item, tracked):
    return any(f.commit or (tracked is not None and os.path.normpath(f.path) in tracked) for f in item.findings)


def _action(item):
    p = provider(item.kind)
    if item.result and item.result.status == DEAD:
        return "Already revoked/invalid. Still remove it from code and history."
    if p and p.revoke:
        return f"`leakkill revoke --only {item.n} --yes` (automatic), or manually: {p.manual}"
    return p.manual if p else "Rotate it with whoever issued it."


def render(items, target, verified=True):
    tracked = tracked_files()
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    count = lambda s: sum(1 for i in items if i.result and i.result.status == s)
    lines = [
        "# leakkill incident report", "",
        f"Generated {now} · target `{target}` · **{len(items)} unique secret(s)**"
        + (f" · **{count(LIVE)} live**, {count(DEAD)} dead, {len(items) - count(LIVE) - count(DEAD)} not confirmed"
           if verified else " · not verified (run without --no-verify to check which are live)"),
        "",
    ]
    if not items:
        return "\n".join(lines + ["No secrets found. 🎉", ""])
    lines += ["| # | Status | Type | Value | Account / identity | In git | Locations |",
              "|---|---|---|---|---|---|---|"]
    for it in items:
        st = it.result.status if it.result else "-"
        who = (it.result.identity if it.result else "") or ""
        where = "<br>".join(f"`{f.location}`" for f in it.findings[:5]) + (
            f"<br>+{len(it.findings) - 5} more" if len(it.findings) > 5 else "")
        lines.append(f"| {it.n} | **{st}** | {it.kind} | `{it.findings[0].masked}` | {who} | "
                     f"{'yes' if in_git(it, tracked) else 'no'} | {where} |")

    order = sorted(items, key=lambda i: (not (i.result and i.result.status == LIVE), i.n))
    lines += ["", "## What to do, in order", "",
              "Revoke first. Deleting a secret from code does **not** make it safe: bots scan new commits "
              "within minutes, and every clone/fork keeps the history.", ""]
    for it in order:
        r = it.result
        head = f"### #{it.n} {it.kind} `{it.findings[0].masked}`"
        if r:
            head += f" — {r.status}" + (f" ({r.identity})" if r.identity else "")
        lines += [head, "", f"1. **Revoke / rotate:** {_action(it)}"]
        if r and r.note:
            lines[-1] += f"  \n   _Check result: {r.note}_"
        logs = [f for f in it.findings if f.path.endswith(".jsonl") or ".vscdb#" in f.path]
        if logs:  # an AI agent's session transcript / history (`leakkill --agents`)
            lines += [f"2. **Delete the agent session file(s)** that hold it in plain text "
                      f"({', '.join('`' + f.path + '`' for f in logs[:3])}). It was also sent to the model "
                      "provider, which is why step 1 matters.", ""]
        else:
            lines += [f"2. **Remove from code:** load it from an environment variable or secret manager instead "
                      f"({', '.join('`' + f.location + '`' for f in it.findings[:3])}).", ""]

    if any(in_git(i, tracked) for i in items):
        lines += ["## Purge from git history (after revoking)", "",
                  "```sh",
                  "pip install git-filter-repo",
                  "leakkill report --history --no-verify --replacements .leakkill-replacements.txt",
                  "git filter-repo --replace-text .leakkill-replacements.txt",
                  "rm .leakkill-replacements.txt",
                  "git push --force --all && git push --force --tags",
                  "```", "",
                  "Rewriting history needs a force-push and every collaborator must re-clone. "
                  "If the repo was ever public, assume the secret was copied: revoking is what actually protects you.",
                  ""]
    return "\n".join(lines)


def write_replacements(items, path):
    """git filter-repo --replace-text file. Contains raw secrets: local use only, delete after.
    Created owner-only (0600) from the start, so the secrets are never readable by others, even briefly.
    Never overwrites: an existing file (or a symlink) raises FileExistsError, so a mistyped or malicious path
    such as ~/.bashrc can't be replaced with secrets."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        for it in items:
            f.write(f"{it.secret}==>***REMOVED-{it.kind.upper().replace(' ', '-')}***\n")
