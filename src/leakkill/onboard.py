"""`leakkill init`: set a project up in one command (git hook, AI agent guards, CI workflow), safely and repeatably.

It only adds things, never overwrites a file it didn't write, and says what it did and what it skipped.
"""
import os, shutil, sys

from . import guard

WORKFLOW = """name: leakkill
on: [push, pull_request]
permissions:
  contents: read
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }
      - uses: ayushanand27/leakkill@v0
        with: { history: true }   # also fails on secrets that were committed and later deleted
"""
# agent -> (config folder in the home directory, commands that mean it is installed)
AGENT_HINTS = {"claude": (".claude", ("claude",)), "cursor": (".cursor", ("cursor", "cursor-agent")),
               "copilot": (".copilot", ("copilot",)), "codex": (".codex", ("codex",))}


def agents_in_use(home=None, project="."):
    """Agents that appear to be installed or used here: a config folder, or the program on the PATH."""
    home = home or os.path.expanduser("~")
    found = []
    for agent, (folder, programs) in AGENT_HINTS.items():
        if os.path.isdir(os.path.join(home, folder)) or os.path.isdir(os.path.join(project, folder)) \
                or any(shutil.which(p) for p in programs):
            found.append(agent)
    return found


def _git_hook():
    if not os.path.isdir(".git"):
        return "skipped the git hook (run this from the top folder of a git repository)"
    hook = os.path.join(".git", "hooks", "pre-commit")
    if os.path.exists(hook) and "leakkill" not in open(hook, encoding="utf-8", errors="replace").read():
        return f"skipped the git hook ({hook} already exists and isn't leakkill's)"
    guard.install_git_hook()
    return None


def _workflow():
    path = os.path.join(".github", "workflows", "leakkill.yml")
    if os.path.exists(path):
        return f"kept your existing {path}"
    if not (os.path.isdir(".github") or os.path.isdir(".git")):
        return "skipped the CI workflow (not a git project)"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(WORKFLOW)
    print(f"Wrote {path}")
    return None


def run(home=None):
    notes = [_git_hook()]
    chosen = agents_in_use(home)
    if chosen:
        guard.install_agent_hooks(chosen)
    else:
        notes.append("no AI coding agent found (add one later with `leakkill install-agent-hooks`)")
    notes.append(_workflow())
    for n in filter(None, notes):
        print(f"  note: {n}")
    print("\nDone. Next: `leakkill` scans this folder now; `leakkill scan --agents` checks what your AI tools stored.")
    return 0
