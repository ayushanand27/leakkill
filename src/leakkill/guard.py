"""Guard AI coding agents: keep secrets out of prompts, file reads, shell reads and generated code.

One detection core, with small adapters for each agent's hook format:
  claude   Claude Code      .claude/settings.json   (also read by GitHub Copilot CLI)
  cursor   Cursor           .cursor/hooks.json
  copilot  GitHub Copilot   .github/hooks/leakkill.json (Claude-compatible PascalCase events)
  codex    OpenAI Codex     .codex/hooks.json
"""
import json, os, re, stat, sys

from .scanner import ignored, load_ignores, mask, scan_text

AGENTS = ("claude", "cursor", "copilot", "codex")
SENSITIVE_FILE = re.compile(
    r"(?i)(^|[\\/])(\.env(\.(?!example$|sample$|template$|dist$)[\w-]+)?|id_rsa|id_ed25519|credentials|\.npmrc|\.pypirc"
    r"|[^\\/]*\.(pem|key|p12|pfx))$")
# Any shell command that names a secrets file is blocked (cat, grep, base64, python -c, cp ...),
# except harmless metadata commands and template files like .env.example.
SENSITIVE_MENTION = re.compile(
    r"(?i)(?<![\w.-])(\.env(\.(?!example|sample|template|dist)[\w-]+)?|id_rsa|id_ed25519|\.pypirc|\.npmrc"
    r"|[\w.-]*\.(pem|key|p12|pfx))(?![\w-]|\.\w)")
SAFE_CMD = re.compile(r"^\s*(git\s+(add|status|check-ignore|rm|diff\s+--stat)|ls|touch|rm|mkdir|stat|test|chmod)\b")
READ_TOOLS = {"Read", "NotebookRead", "Grep"}
PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update) File: (.+)$")


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _str(x):
    return x if isinstance(x, str) else ""


# ---------------------------------------------------------------- per-agent input -> one common shape
def normalize(event, agent="claude"):
    """Return {"kind": "prompt", "prompt": ...} or {"kind": "tool", "tool", "input", "content", "cwd"} or None."""
    if not isinstance(event, dict):
        return None
    name = event.get("hook_event_name")
    cwd = _str(event.get("cwd")) or next(iter(event.get("workspace_roots") or []), "") or ""
    if agent == "cursor":
        if name == "beforeSubmitPrompt":
            return {"kind": "prompt", "prompt": _str(event.get("prompt"))}
        if name in ("beforeReadFile", "beforeTabFileRead"):
            return {"kind": "tool", "tool": "Read", "input": {"file_path": _str(event.get("file_path"))},
                    "content": _str(event.get("content")), "cwd": cwd}
        if name == "beforeShellExecution":
            return {"kind": "tool", "tool": "Bash", "input": {"command": _str(event.get("command"))}, "cwd": cwd}
        if name == "beforeMCPExecution":
            return {"kind": "tool", "tool": "MCP", "input": {"arguments": event.get("tool_input")}, "cwd": cwd}
        if name == "preToolUse":
            tool = {"Shell": "Bash"}.get(_str(event.get("tool_name")), _str(event.get("tool_name")))
            ti = event.get("tool_input")
            return {"kind": "tool", "tool": tool, "input": ti if isinstance(ti, dict) else {"value": ti}, "cwd": cwd}
        return None
    # Claude Code, Codex and Copilot (PascalCase events) share Claude's shape; also accept Copilot's camelCase.
    if name in ("UserPromptSubmit", "userPromptSubmitted") or (name is None and "prompt" in event and "toolName" not in event):
        return {"kind": "prompt", "prompt": _str(event.get("prompt"))}
    if name in ("PreToolUse", "preToolUse") or "toolName" in event:
        tool = _str(event.get("tool_name")) or _str(event.get("toolName"))
        ti = event.get("tool_input", event.get("toolArgs"))
        if isinstance(ti, str):
            try:
                ti = json.loads(ti)
            except ValueError:
                ti = {"value": ti}
        tool = {"bash": "Bash", "powershell": "Bash", "view": "Read", "create": "Write", "edit": "Edit"}.get(tool, tool)
        return {"kind": "tool", "tool": tool, "input": ti if isinstance(ti, dict) else {}, "cwd": cwd}
    return None


# ---------------------------------------------------------------- the detection core
def _patch_sections(patch):
    """Codex apply_patch text -> [(path, added_text)]."""
    sections, path, added = [], "", []
    for line in patch.split("\n"):
        m = PATCH_FILE.match(line)
        if m:
            if path:
                sections.append((path, "\n".join(added)))
            path, added = m.group(1).strip(), []
        elif path and line.startswith("+"):
            added.append(line[1:])
    if path:
        sections.append((path, "\n".join(added)))
    return sections


def _secrets(text, label):
    return [f"{label} contains {'an' if f.kind[:1] in 'AEIOaeio' else 'a'} {f.kind} ({f.masked})"
            for f in scan_text(text, label)]


def check(n):
    """Reasons to block a normalized event (empty list = allow)."""
    if not n:
        return []
    if n["kind"] == "prompt":
        return [r.replace("prompt contains", "the prompt contains") + "; it would be sent to the model"
                for r in _secrets(n["prompt"], "prompt")]
    tool, ti, reasons = n["tool"], n["input"], []
    path = _str(ti.get("file_path")) or _str(ti.get("path")) or _str(ti.get("notebook_path"))
    if tool in READ_TOOLS and SENSITIVE_FILE.search(path):
        reasons.append(f"reading {path} would put its secrets into the model context")
    elif tool == "Read" and n.get("content") and not ignored(os.path.relpath(path, n["cwd"]) if n["cwd"] and path else path,
                                                           load_ignores(n["cwd"] or ".")):
        reasons += [r + "; reading it sends it to the model (move it to .env, which leakkill keeps out)"
                    for r in _secrets(n["content"], os.path.basename(path) or "file")]
    if tool == "apply_patch":  # Codex file edits: check what each file gets, writing keys into .env is fine
        for target, added in _patch_sections(_str(ti.get("command"))):
            if not SENSITIVE_FILE.search(target):
                reasons += [r + "; use an environment variable instead" for r in _secrets(added, target)]
        return reasons
    cmd = _str(ti.get("command")) if tool == "Bash" else ""
    if cmd and SENSITIVE_MENTION.search(cmd) and not SAFE_CMD.match(cmd):
        reasons.append("shell command reads a secrets file into the model context")
    if not (path and SENSITIVE_FILE.search(path)) and tool not in READ_TOOLS:  # writing real secrets into .env is fine
        for text in _strings(ti):
            reasons += [r + "; use an environment variable instead" for r in _secrets(text, f"{tool or 'tool'} input")]
    return reasons


def guard_check(event, agent="claude"):
    return check(normalize(event, agent))


# ---------------------------------------------------------------- per-agent output
CURSOR_PERMISSION = {"beforeReadFile", "beforeTabFileRead", "beforeShellExecution", "beforeMCPExecution", "preToolUse"}


def _respond(agent, event_name, reasons):
    msg = "leakkill blocked this action:\n- " + "\n- ".join(dict.fromkeys(reasons)) if reasons else ""
    if agent == "cursor":  # Cursor expects a JSON answer on stdout, even when allowing
        if event_name == "beforeSubmitPrompt":
            print(json.dumps({"continue": not reasons, **({"user_message": msg} if reasons else {})}))
        else:
            out = {"permission": "deny", "user_message": msg, "agent_message": msg} if reasons else {"permission": "allow"}
            print(json.dumps(out))
    if reasons:
        print(msg, file=sys.stderr)
        return 2  # every supported agent treats exit code 2 as "block"
    return 0


def _redact(reasons, event, raw):
    """Mask every secret the event contains wherever a message would repeat it (e.g. a key in a file name):
    the guard's own answer goes back to the agent, so it must never carry a raw secret."""
    found = {f.secret for text in [raw, *_strings(event)] for f in scan_text(text, "event")}
    for secret in sorted(found, key=len, reverse=True):
        reasons = [r.replace(secret, mask(secret)) for r in reasons]
    return reasons


def guard(raw, agent="claude"):
    try:
        event = json.loads(raw)
    except ValueError:
        event = None
    name = event.get("hook_event_name") if isinstance(event, dict) else None
    try:
        reasons = guard_check(event, agent)
    except Exception as e:  # an unexpected bug must not let a secret through: fail closed, and say so
        reasons = [f"leakkill guard hit an internal error ({type(e).__name__}) and blocked this action to be safe. "
                   "Please report it: https://github.com/ayushanand27/leakkill/issues"]
    return _respond(agent, name, _redact(reasons, event, raw) if reasons else reasons)


# ---------------------------------------------------------------- installers
def _exe(powershell=False):
    exe = sys.executable
    if " " not in exe:
        return exe
    return f'& "{exe}"' if powershell else f'"{exe}"'


def _self_cmd(sub, powershell=False):
    return f"{_exe(powershell)} -m leakkill {sub}"


def _load(path):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def _save(path, cfg):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")


def _without_ours(entries):
    return [e for e in entries if "leakkill" not in json.dumps(e)]


def _install_claude(base):
    path = os.path.join(base, ".claude", "settings.json")
    cfg, cmd = _load(path), _self_cmd("guard --agent claude")
    hooks = cfg.setdefault("hooks", {})
    for event, matcher in (("UserPromptSubmit", None), ("PreToolUse", "Read|Grep|Write|Edit|MultiEdit|NotebookEdit|Bash")):
        entry = {"hooks": [{"type": "command", "command": cmd}]}
        if matcher:
            entry["matcher"] = matcher
        hooks[event] = _without_ours(hooks.get(event, [])) + [entry]
    _save(path, cfg)
    return path, None


def _install_cursor(base):
    path = os.path.join(base, ".cursor", "hooks.json")
    cfg, cmd = _load(path), _self_cmd("guard --agent cursor")
    cfg.setdefault("version", 1)
    hooks = cfg.setdefault("hooks", {})
    for event, matcher in (("beforeSubmitPrompt", None), ("beforeReadFile", None), ("beforeShellExecution", None),
                           ("beforeMCPExecution", None), ("preToolUse", "Write")):
        entry = {"command": cmd, "timeout": 30, "failClosed": True}
        if matcher:
            entry["matcher"] = matcher
        hooks[event] = _without_ours(hooks.get(event, [])) + [entry]
    _save(path, cfg)
    return path, None


def _install_copilot(base, user_level):
    path = os.path.join(base, ".copilot" if user_level else os.path.join(".github"), "hooks", "leakkill.json")
    entry = {"type": "command", "bash": _self_cmd("guard --agent copilot"),
             "powershell": _self_cmd("guard --agent copilot", powershell=True), "timeoutSec": 30}
    _save(path, {"version": 1, "hooks": {"PreToolUse": [entry], "UserPromptSubmit": [entry]}})
    return path, ("Copilot ignores prompt-hook decisions, so a secret in a Copilot prompt is warned about, "
                  "not blocked. Tool calls (reads, shell, writes) are blocked.")


def _install_codex(base):
    path = os.path.join(base, ".codex", "hooks.json")
    cfg = _load(path)
    hook = {"type": "command", "command": _self_cmd("guard --agent codex"), "timeout": 30,
            "statusMessage": "leakkill: checking for secrets"}
    hooks = cfg.setdefault("hooks", {})
    for event in ("PreToolUse", "UserPromptSubmit"):
        hooks[event] = _without_ours(hooks.get(event, [])) + [{"hooks": [hook]}]
    _save(path, cfg)
    return path, "Codex runs new hooks only after you trust them: open Codex, type /hooks, and trust the leakkill hook."


def install_agent_hooks(agents=AGENTS, user_level=False):
    """Install the guard for each agent, in this project (default) or for your user account."""
    base = os.path.expanduser("~") if user_level else "."
    for agent in agents:
        if agent == "copilot":
            path, note = _install_copilot(base, user_level)
        else:
            path, note = {"claude": _install_claude, "cursor": _install_cursor, "codex": _install_codex}[agent](base)
        print(f"Installed {agent} guard in {path}" + (f"\n  note: {note}" if note else ""))
    return 0


def install_claude_hook():
    return install_agent_hooks(["claude"])


def install_git_hook():
    if not os.path.isdir(".git"):
        print("Not a git repo root.", file=sys.stderr)
        return 1
    hook = os.path.join(".git", "hooks", "pre-commit")
    cmd = _self_cmd("scan --staged").replace("\\", "/")
    with open(hook, "w", newline="\n") as f:
        f.write(f'#!/bin/sh\n{cmd} || {{ echo "Commit blocked by leakkill."; exit 1; }}\n')
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR)  # git only needs the owner to be able to run it
    print("Installed", hook)
    return 0
