"""Tests for paths the main suites didn't reach: guard install/block, more providers, parallel scanning."""
import json, os, stat, subprocess, sys

from leakkill import guard, providers as P, scanner

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


# ---- guard: blocking, failing closed, installers ----
def test_guard_blocks_with_exit_2_and_explains(capsys):
    ev = {"hook_event_name": "UserPromptSubmit", "prompt": f"use {GH}"}
    assert guard.guard(json.dumps(ev)) == 2
    err = capsys.readouterr().err
    assert "leakkill blocked this action" in err and GH not in err


def test_guard_allows_clean_and_ignores_non_events():
    assert guard.guard(json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": "fix the bug"})) == 0
    assert guard.guard("not json") == 0 and guard.guard("[]") == 0 and guard.guard("null") == 0


def test_guard_fails_closed_on_internal_error(monkeypatch, capsys):
    monkeypatch.setattr(guard, "guard_check", lambda ev, agent="claude": 1 / 0)
    assert guard.guard("{}") == 2
    assert "blocked this action to be safe" in capsys.readouterr().err


def test_install_claude_hook_merges_and_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".claude").mkdir()
    (tmp_path / ".claude" / "settings.json").write_text(json.dumps(
        {"model": "x", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "mine"}]}]}}))
    guard.install_claude_hook(); guard.install_claude_hook()
    cfg = json.loads((tmp_path / ".claude" / "settings.json").read_text())
    assert cfg["model"] == "x"  # unrelated settings kept
    pre = cfg["hooks"]["PreToolUse"]
    assert any("mine" in json.dumps(g) for g in pre)  # the user's own hook kept
    assert sum("leakkill guard" in json.dumps(g) for g in pre) == 1  # ours added once, not twice
    assert sum("leakkill guard" in json.dumps(g) for g in cfg["hooks"]["UserPromptSubmit"]) == 1


def test_install_git_hook(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert guard.install_git_hook() == 1  # not a repo
    subprocess.run(["git", "init", "-q"], check=True)
    assert guard.install_git_hook() == 0
    hook = tmp_path / ".git" / "hooks" / "pre-commit"
    assert "leakkill scan --staged" in hook.read_text()
    if os.name != "nt":
        assert os.stat(hook).st_mode & stat.S_IXUSR


def test_python_dash_m_entry_point():
    out = subprocess.run([sys.executable, "-m", "leakkill", "--version"], capture_output=True, text=True,
                         env=dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src")))
    assert out.returncode == 0 and out.stdout.startswith("leakkill ")


# ---- providers not covered elsewhere ----
class Fake:
    def __init__(self, resp): self.resp, self.calls = resp, []
    def __call__(self, method, url, headers=None, data=None, timeout=15):
        self.calls.append((method, url, headers or {}, data)); return self.resp


def test_slack_webhook_live_dead_and_posts_nothing(monkeypatch):
    f = Fake((400, {}, b"invalid_payload")); monkeypatch.setattr(P, "http", f)
    assert P.verify("Slack webhook", "https://hooks.slack.com/services/T/B/x").status == P.LIVE
    assert f.calls[0][3] == b"{}"  # an empty payload: rejected by Slack, so nothing is posted
    monkeypatch.setattr(P, "http", Fake((404, {}, b"no_service")))
    assert P.verify("Slack webhook", "https://hooks.slack.com/services/T/B/x").status == P.DEAD


def test_npm_telegram_anthropic(monkeypatch):
    monkeypatch.setattr(P, "http", Fake((200, {}, b'{"username":"ayush"}')))
    assert P.verify("npm token", "npm_x").identity == "ayush"
    monkeypatch.setattr(P, "http", Fake((200, {}, b'{"result":{"username":"mybot"}}')))
    assert P.verify("Telegram bot token", "1:AA").identity == "@mybot"
    monkeypatch.setattr(P, "http", Fake((401, {}, b"")))
    assert P.verify("Anthropic API key", "sk-ant-x").status == P.DEAD
    monkeypatch.setattr(P, "http", Fake((429, {}, b"")))
    assert P.verify("Anthropic API key", "sk-ant-x").status == P.LIVE


def test_unexpected_status_is_unknown_and_revoke_failure_reported(monkeypatch):
    monkeypatch.setattr(P, "http", Fake((500, {}, b"")))
    r = P.verify("GitHub token", GH)
    assert r.status == P.UNKNOWN and "500" in r.note
    monkeypatch.setattr(P, "http", Fake((422, {}, b"bad")))
    ok, msg = P.revoke("GitHub token", GH, P.Result(P.LIVE))
    assert not ok and "422" in msg


def test_aws_temporary_and_mismatched_keys(monkeypatch):
    assert P.verify("AWS access key", "ASIA" + "A" * 16, {"aws_secrets": ["s" * 40]}).status == P.UNKNOWN
    monkeypatch.setattr(P, "http", Fake((403, {}, b"<Code>SignatureDoesNotMatch</Code>")))
    r = P.verify("AWS access key", "AKIA" + "A" * 16, {"aws_secrets": ["s" * 40]})
    assert r.status == P.UNKNOWN and "no paired secret matched" in r.note
    monkeypatch.setattr(P, "http", Fake((403, {}, b"<Code>AccessDenied</Code>")))
    ok, msg = P.revoke("AWS access key", "AKIA" + "A" * 16, P.Result(P.LIVE, extra={"aws_secret": "s" * 40}))
    assert not ok and "AccessDenied" in msg


def test_imported_kinds_get_generic_guidance():
    assert P.verify("Doppler API token", "dp.pt.x").status == P.UNSUPPORTED
    ok, msg = P.revoke("Doppler API token", "dp.pt.x", P.Result(P.LIVE))
    assert not ok and "dashboard" in msg


# ---- parallel scanning gives exactly the single-core result ----
def test_parallel_scan_equals_single_core(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for i in range(240):  # above the 200-file threshold for using a process pool
        body = f'x = {i}\n' + (f'TOKEN = "{GH[:-4]}{i:04d}"\n' if i % 7 == 0 else "") + 'y = "plain"\n'
        (tmp_path / f"f{i:03d}.py").write_text(body)
    one = [(f.path, f.line, f.kind, f.secret) for f in scanner.scan_paths(["."], jobs=1)]
    many = [(f.path, f.line, f.kind, f.secret) for f in scanner.scan_paths(["."], jobs=4)]
    assert one == many and len(one) == len(range(0, 240, 7))
