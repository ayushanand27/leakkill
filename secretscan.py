#!/usr/bin/env python3
"""secretscan - find leaked credentials before they hit git.

Usage:
  python secretscan.py [PATH ...]      scan files/dirs (default: .)
  python secretscan.py --staged        scan only git-staged changes (pre-commit)
  python secretscan.py --history       scan every commit in git history
  python secretscan.py --install-hook  install as .git/hooks/pre-commit
  python secretscan.py --install-claude-hook   guard Claude Code (prompts + tool calls)
  python secretscan.py --guard         hook entry point: reads Claude Code hook JSON on stdin
Suppress a line with:  # secretscan:ignore
Add --exclude-tests to skip test_* files.
Exit code 1 if anything is found.
"""
import json, math, os, re, subprocess, sys

RULES = {
    "AWS access key":      re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token":        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "Slack token":         re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "Google API key":      re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "Stripe live key":     re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    "Anthropic/OpenAI key": re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_\-]{32,}\b"),
    "Private key block":   re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "JWT":                 re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "DB URL with password": re.compile(r"\b[a-z]+://[^\s:/@]+:[^\s:/@]{3,}@[^\s/]+"),
}
# key = "value" where key name looks sensitive
ASSIGN = re.compile(
    r"""(?i)\b[\w.-]*(?:secret|token|passwd|password|api[_-]?key|private[_-]?key|auth)[\w.-]*\b
        \s*[:=]\s*["']([^"'\s]{12,})["']""", re.X)
PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxx|<.*>|\$\{|\{\{|dummy|sample|test")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".idea"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".woff", ".woff2", ".ico", ".lock", ".pyc"}

def entropy(s):
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))

def mask(s):
    return s[:4] + "*" * min(len(s) - 4, 12) if len(s) > 8 else "****"

def scan_line(line):
    if "secretscan:ignore" in line:
        return []
    hits = [(name, m.group(0)) for name, rx in RULES.items() for m in rx.finditer(line)]
    for m in ASSIGN.finditer(line):
        v = m.group(1)
        if not PLACEHOLDER.search(v) and entropy(v) >= 3.5 and not any(v == h[1] for h in hits):
            hits.append(("High-entropy secret assignment", v))
    return hits

def scan_text(text, label):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        for name, val in scan_line(line):
            out.append((label, i, name, mask(val)))
    return out

def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                if os.path.splitext(f)[1].lower() not in SKIP_EXT:
                    yield os.path.join(root, f)

def scan_paths(paths):
    out = []
    for f in iter_files(paths):
        try:
            if os.path.getsize(f) > 2_000_000:
                continue
            with open(f, encoding="utf-8", errors="strict") as fh:
                out += scan_text(fh.read(), f)
        except (UnicodeDecodeError, OSError):
            continue  # binary / unreadable
    return out

def scan_staged():
    diff = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color"],
                          capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    out, cur = [], "?"
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            cur = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            out += scan_text(line[1:], cur)
    return out

SENSITIVE_FILE = re.compile(
    r"(?i)(^|[\\/])(\.env(\.[\w-]+)?|id_rsa|id_ed25519|credentials|\.npmrc|\.pypirc|[^\\/]*\.(pem|key|p12|pfx))$")
# Any shell command that names a secrets file is blocked (cat, grep, base64, python -c, cp ...),
# except harmless metadata commands and template files like .env.example.
SENSITIVE_MENTION = re.compile(
    r"(?i)(?<![\w.-])(\.env(\.(?!example|sample|template|dist)[\w-]+)?|id_rsa|id_ed25519|\.pypirc|\.npmrc"
    r"|[\w.-]*\.(pem|key|p12|pfx))(?![\w-]|\.\w)")
SAFE_CMD = re.compile(r"^\s*(git\s+(add|status|check-ignore|rm|diff\s+--stat)|ls|touch|rm|mkdir|stat|test|chmod)\b")
READ_TOOLS = {"Read", "NotebookRead"}

def scan_history():
    log = subprocess.run(["git", "log", "-p", "--all", "-U0", "--no-color", "--format=commit %h"],
                         capture_output=True, text=True, encoding="utf-8", errors="replace").stdout
    out, commit, cur = [], "?", "?"
    for line in log.splitlines():
        if line.startswith("commit "):
            commit = line[7:]
        elif line.startswith("+++ b/"):
            cur = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            out += scan_text(line[1:], f"{commit}:{cur}")
    return out

def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)

def guard_check(event):
    """Return a list of human-readable reasons to block this Claude Code hook event."""
    name, reasons = event.get("hook_event_name"), []
    if name == "UserPromptSubmit":
        for _, ln, kind, m in scan_text(event.get("prompt", ""), "prompt"):
            reasons.append(f"prompt line {ln} contains a {kind} ({m})")
    elif name == "PreToolUse":
        tool, ti = event.get("tool_name", ""), event.get("tool_input") or {}
        path = ti.get("file_path") or ti.get("path") or ti.get("notebook_path") or ""
        if tool in READ_TOOLS and SENSITIVE_FILE.search(path):
            reasons.append(f"reading {path} would put its secrets into the model context")
        cmd = ti.get("command", "") if tool == "Bash" else ""
        if cmd and SENSITIVE_MENTION.search(cmd) and not SAFE_CMD.match(cmd):
            reasons.append("shell command reads a secrets file into the model context")
        if not (path and SENSITIVE_FILE.search(path)):  # writing real secrets into .env is fine
            for text in _strings(ti):
                for _, ln, kind, m in scan_text(text, tool):
                    reasons.append(f"{tool} input contains a {kind} ({m}); use an environment variable instead")
    return reasons

def guard(raw):
    try:
        event = json.loads(raw)
    except ValueError:
        return 0  # never break the agent on malformed input
    reasons = guard_check(event)
    if reasons:
        print("secretscan blocked this action:\n- " + "\n- ".join(dict.fromkeys(reasons)), file=sys.stderr)
        return 2  # Claude Code: exit 2 = block, stderr is shown
    return 0

def install_claude_hook():
    path = os.path.join(".claude", "settings.json")
    os.makedirs(".claude", exist_ok=True)
    cfg = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
    cmd = f'python "{os.path.abspath(__file__)}" --guard'
    hooks = cfg.setdefault("hooks", {})
    for event, matcher in (("UserPromptSubmit", None), ("PreToolUse", "Read|Write|Edit|MultiEdit|Bash")):
        entry = {"hooks": [{"type": "command", "command": cmd}]}
        if matcher:
            entry["matcher"] = matcher
        groups = [g for g in hooks.get(event, []) if "--guard" not in json.dumps(g)]
        hooks[event] = groups + [entry]
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2)
    print("Installed Claude Code guard in", path)

def install_hook():
    hook = os.path.join(".git", "hooks", "pre-commit")
    if not os.path.isdir(".git"):
        sys.exit("Not a git repo root.")
    script = os.path.abspath(__file__).replace("\\", "/")
    with open(hook, "w", newline="\n") as f:
        f.write(f'#!/bin/sh\npython "{script}" --staged || {{ echo "Commit blocked: secrets found."; exit 1; }}\n')
    print("Installed", hook)

def main(argv):
    if "--install-hook" in argv:
        return install_hook()
    if "--install-claude-hook" in argv:
        return install_claude_hook()
    if "--guard" in argv:
        sys.exit(guard(sys.stdin.read()))
    findings = scan_history() if "--history" in argv else scan_staged() if "--staged" in argv else scan_paths([a for a in argv if not a.startswith("--")] or ["."])
    if "--exclude-tests" in argv:
        findings = [f for f in findings if not os.path.basename(f[0]).startswith("test_")]
    for label, ln, name, masked in findings:
        print(f"{label}:{ln}: {name}: {masked}")
    print(f"\n{len(findings)} potential secret(s) found." if findings else "Clean.")
    sys.exit(1 if findings else 0)

def main_cli():
    main(sys.argv[1:])

if __name__ == "__main__":
    main_cli()
