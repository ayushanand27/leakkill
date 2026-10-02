"""Each agent's documented hook payloads, run through the real entry point (stdin JSON -> stdout/exit code)."""
import io, json, os, sys

import pytest

from leakkill import guard
from leakkill.guard import guard_check, install_agent_hooks

KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def run(event, agent, capsys):
    rc = guard.guard(json.dumps(event), agent)
    out, err = capsys.readouterr()
    return rc, out, err


# ---------------------------------------------------------------- Cursor
def test_cursor_prompt_blocked_and_allowed(capsys):
    rc, out, err = run({"hook_event_name": "beforeSubmitPrompt", "prompt": f"use {KEY}"}, "cursor", capsys)
    assert rc == 2 and json.loads(out)["continue"] is False and "prompt" in err
    rc, out, _ = run({"hook_event_name": "beforeSubmitPrompt", "prompt": "fix the bug"}, "cursor", capsys)
    assert rc == 0 and json.loads(out) == {"continue": True}


def test_cursor_read_env_denied_code_allowed(capsys):
    rc, out, _ = run({"hook_event_name": "beforeReadFile", "file_path": "/w/.env", "content": "X=1"}, "cursor", capsys)
    assert rc == 2 and json.loads(out)["permission"] == "deny"
    rc, out, _ = run({"hook_event_name": "beforeReadFile", "file_path": "/w/app.py", "content": "print(1)"}, "cursor", capsys)
    assert rc == 0 and json.loads(out) == {"permission": "allow"}


def test_cursor_read_content_with_key(tmp_path, capsys):
    ev = {"hook_event_name": "beforeReadFile", "file_path": str(tmp_path / "cfg.py"),
          "content": f'KEY = "{KEY}"', "workspace_roots": [str(tmp_path)]}
    rc, out, _ = run(ev, "cursor", capsys)
    assert rc == 2 and "cfg.py" in json.loads(out)["user_message"]
    (tmp_path / ".leakkillignore").write_text("cfg.py\n")
    assert run(ev, "cursor", capsys)[0] == 0


def test_cursor_shell_and_mcp(capsys):
    assert run({"hook_event_name": "beforeShellExecution", "command": "cat .env", "cwd": "/w"}, "cursor", capsys)[0] == 2
    assert run({"hook_event_name": "beforeShellExecution", "command": "ls", "cwd": "/w"}, "cursor", capsys)[0] == 0
    ev = {"hook_event_name": "beforeMCPExecution", "tool_name": "post", "tool_input": json.dumps({"text": KEY})}
    assert run(ev, "cursor", capsys)[0] == 2


def test_cursor_pretooluse_write():
    assert guard_check({"hook_event_name": "preToolUse", "tool_name": "Write",
                        "tool_input": {"file_path": "a.py", "content": f'k="{KEY}"'}}, "cursor")
    assert not guard_check({"hook_event_name": "preToolUse", "tool_name": "Write",
                            "tool_input": {"file_path": ".env", "content": f"K={KEY}"}}, "cursor")
    assert guard_check({"hook_event_name": "preToolUse", "tool_name": "Shell",
                        "tool_input": {"command": "cat .env"}}, "cursor")


def test_cursor_unknown_event_allows(capsys):
    rc, out, _ = run({"hook_event_name": "afterFileEdit"}, "cursor", capsys)
    assert rc == 0 and json.loads(out) == {"permission": "allow"}


# ---------------------------------------------------------------- Codex
PATCH = "*** Begin Patch\n*** Add File: {f}\n+import os\n+KEY = \"{k}\"\n*** End Patch\n"


def test_codex_apply_patch():
    code = {"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
            "tool_input": {"command": PATCH.format(f="app.py", k=KEY)}}
    reasons = guard_check(code, "codex")
    assert reasons and "app.py" in reasons[0]
    env = {"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
           "tool_input": {"command": PATCH.format(f=".env", k=KEY)}}
    assert not guard_check(env, "codex")


def test_codex_patch_only_added_lines_count():
    patch = f"*** Begin Patch\n*** Update File: app.py\n@@\n-KEY = \"{KEY}\"\n+KEY = os.environ[\"KEY\"]\n*** End Patch"
    assert not guard_check({"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
                            "tool_input": {"command": patch}}, "codex")


def test_codex_prompt_bash_mcp(capsys):
    assert run({"hook_event_name": "UserPromptSubmit", "prompt": KEY}, "codex", capsys)[0] == 2
    assert guard_check({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                        "tool_input": {"command": "cat .env"}}, "codex")
    assert guard_check({"hook_event_name": "PreToolUse", "tool_name": "mcp__slack__post",
                        "tool_input": {"text": KEY}}, "codex")
    rc, out, _ = run({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}, "codex", capsys)
    assert rc == 0 and out == ""


# ---------------------------------------------------------------- Copilot
def test_copilot_pascal_case():
    assert guard_check({"hook_event_name": "PreToolUse", "tool_name": "Read",
                        "tool_input": {"file_path": ".env"}}, "copilot")


def test_copilot_camel_case_tool_args_string():
    assert guard_check({"toolName": "view", "toolArgs": json.dumps({"path": "/w/.env"})}, "copilot")
    assert guard_check({"toolName": "bash", "toolArgs": json.dumps({"command": "cat .env"})}, "copilot")
    assert guard_check({"toolName": "create", "toolArgs": json.dumps({"path": "a.py", "file_text": KEY})}, "copilot")
    assert not guard_check({"toolName": "bash", "toolArgs": "not json"}, "copilot")
    assert guard_check({"hook_event_name": "userPromptSubmitted", "prompt": KEY}, "copilot")


# ---------------------------------------------------------------- installers
def test_install_all_agents(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    claude = tmp_path / ".claude" / "settings.json"
    claude.parent.mkdir()
    claude.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
        {"type": "command", "command": "other-tool"}]}]}}))
    for _ in range(2):  # idempotent
        assert install_agent_hooks() == 0
    c = json.loads(claude.read_text())
    assert c["model"] == "x" and len(c["hooks"]["PreToolUse"]) == 2 and "other-tool" in json.dumps(c)
    cur = json.loads((tmp_path / ".cursor" / "hooks.json").read_text())
    assert cur["version"] == 1 and len(cur["hooks"]["beforeReadFile"]) == 1
    assert "guard --agent cursor" in cur["hooks"]["beforeReadFile"][0]["command"]
    cop = json.loads((tmp_path / ".github" / "hooks" / "leakkill.json").read_text())
    assert "guard --agent copilot" in cop["hooks"]["PreToolUse"][0]["bash"]
    cod = json.loads((tmp_path / ".codex" / "hooks.json").read_text())
    assert len(cod["hooks"]["PreToolUse"]) == 1 and "/hooks" in capsys.readouterr().out


def test_install_global(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    install_agent_hooks(["copilot", "codex"], user_level=True)
    assert (tmp_path / ".copilot" / "hooks" / "leakkill.json").exists()
    assert (tmp_path / ".codex" / "hooks.json").exists()


def test_exe_quoting(monkeypatch):
    monkeypatch.setattr(sys, "executable", "/opt/my python/python")
    assert guard._self_cmd("guard") == '"/opt/my python/python" -m leakkill guard'
    assert guard._self_cmd("guard", powershell=True).startswith('& "')


def test_cli_entry(monkeypatch, tmp_path, capsys):
    from leakkill.cli import main
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps({"hook_event_name": "beforeShellExecution",
                                                               "command": "cat .env"})))
    assert main(["guard", "--agent", "cursor"]) == 2
    assert json.loads(capsys.readouterr().out)["permission"] == "deny"
    monkeypatch.chdir(tmp_path)
    assert main(["install-agent-hooks", "nope"]) == 2
    assert main(["install-agent-hooks", "cursor"]) == 0 and os.path.exists(".cursor/hooks.json")
    assert not os.path.exists(".claude")
