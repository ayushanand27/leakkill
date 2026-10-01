"""Claude Code hook: keep secrets out of AI coding agents (prompts, file reads, shell reads, generated code)."""
import json, os, re, sys

from .scanner import scan_text

SENSITIVE_FILE = re.compile(
    r"(?i)(^|[\\/])(\.env(\.(?!example$|sample$|template$|dist$)[\w-]+)?|id_rsa|id_ed25519|credentials|\.npmrc|\.pypirc"
    r"|[^\\/]*\.(pem|key|p12|pfx))$")
# Any shell command that names a secrets file is blocked (cat, grep, base64, python -c, cp ...),
# except harmless metadata commands and template files like .env.example.
SENSITIVE_MENTION = re.compile(
    r"(?i)(?<![\w.-])(\.env(\.(?!example|sample|template|dist)[\w-]+)?|id_rsa|id_ed25519|\.pypirc|\.npmrc"
    r"|[\w.-]*\.(pem|key|p12|pfx))(?![\w-]|\.\w)")
SAFE_CMD = re.compile(r"^\s*(git\s+(add|status|check-ignore|rm|diff\s+--stat)|ls|touch|rm|mkdir|stat|test|chmod)\b")
READ_TOOLS = {"Read", "NotebookRead"}


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
        for f in scan_text(event.get("prompt", ""), "prompt"):
            reasons.append(f"prompt line {f.line} contains a {f.kind} ({f.masked})")
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
                for f in scan_text(text, tool):
                    reasons.append(f"{tool} input contains a {f.kind} ({f.masked}); use an environment variable instead")
    return reasons


def guard(raw):
    try:
        event = json.loads(raw)
    except ValueError:
        return 0  # never break the agent on malformed input
    reasons = guard_check(event)
    if reasons:
        print("secretscan blocked this action:\n- " + "\n- ".join(dict.fromkeys(reasons)), file=sys.stderr)
        return 2  # Claude Code: exit 2 = block, stderr is shown to the model
    return 0


def _self_cmd(sub):
    return f'"{sys.executable}" -m secretscan {sub}'


def install_claude_hook():
    path = os.path.join(".claude", "settings.json")
    os.makedirs(".claude", exist_ok=True)
    cfg = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    cmd = _self_cmd("guard")
    hooks = cfg.setdefault("hooks", {})
    for event, matcher in (("UserPromptSubmit", None), ("PreToolUse", "Read|Write|Edit|MultiEdit|NotebookEdit|Bash")):
        entry = {"hooks": [{"type": "command", "command": cmd}]}
        if matcher:
            entry["matcher"] = matcher
        groups = [g for g in hooks.get(event, []) if "secretscan" not in json.dumps(g)]
        hooks[event] = groups + [entry]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print("Installed Claude Code guard in", path)
    return 0


def install_git_hook():
    if not os.path.isdir(".git"):
        print("Not a git repo root.", file=sys.stderr)
        return 1
    hook = os.path.join(".git", "hooks", "pre-commit")
    cmd = _self_cmd("scan --staged").replace("\\", "/")
    with open(hook, "w", newline="\n") as f:
        f.write(f'#!/bin/sh\n{cmd} || {{ echo "Commit blocked by secretscan."; exit 1; }}\n')
    os.chmod(hook, 0o755)
    print("Installed", hook)
    return 0
