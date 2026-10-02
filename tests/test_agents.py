import json, os

from leakkill import agents
from leakkill.cli import main
from leakkill.scanner import scan_line

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
SLACK = "xox" + "b-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"


def fake_home(tmp_path):
    home = tmp_path / "home"
    proj = home / ".claude" / "projects" / "-work-app"
    proj.mkdir(parents=True)
    lines = [json.dumps({"type": "user", "message": {"content": "hi"}}),
             # a pasted .env: the secret sits behind JSON escapes (\" and \n) in the raw file
             json.dumps({"type": "user", "message": {"content": f'api_key = "q8Zx3Lm9Vb2Nc7Rt5Yw1Hk4"\nGH={GH}'},
                         "toolUseResult": {"stdout": f"GH={GH}"}}),
             "not json at all " + SLACK]
    (proj / "s1.jsonl").write_text("\n".join(lines) + "\n")
    (home / ".codex").mkdir()
    (home / ".codex" / "auth.json").write_text(json.dumps({"OPENAI_API_KEY": "sk-proj-" + "B1" * 40}))
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"gh": {"env": {"GITHUB_TOKEN": GH}}}}))
    (home / ".claude" / "plugins").mkdir()
    (home / ".claude" / "plugins" / "x.json").write_text(json.dumps({"t": GH}))
    return home


def test_places_and_skips(tmp_path):
    home = fake_home(tmp_path)
    cwd = tmp_path / "proj"
    cwd.mkdir()
    (cwd / ".mcp.json").write_text("{}")
    found = agents.places(str(home), str(cwd), env={})
    assert {a for a, _ in found} == {"Claude Code", "Codex", "Cursor", "this project"}
    files = [f for _, p in found for f in agents._files(p)]
    assert not any(f.endswith("auth.json") or "plugins" in f for f in files)  # login store and plugin code skipped


def test_transcript_secrets_decoded_located_and_deduped(tmp_path):
    home = fake_home(tmp_path)
    fs = agents.scan_agents(str(home), str(tmp_path), env={}, quiet=True)
    by = {(f.path, f.line, f.kind) for f in fs}
    t = os.path.join("~", ".claude", "projects", "-work-app", "s1.jsonl")
    assert (t, 2, "GitHub token") in by and (t, 2, "High-entropy secret") in by and (t, 3, "Slack token") in by
    assert sum(1 for f in fs if f.path == t and f.line == 2 and f.kind == "GitHub token") == 1  # repeated on the line
    assert (os.path.join("~", ".cursor", "mcp.json"), 1, "GitHub token") in by
    assert not any("codex" in f.path for f in fs)


def test_large_transcript_chunks_keep_line_numbers(tmp_path, monkeypatch):
    monkeypatch.setattr(agents, "CHUNK", 200)
    p = tmp_path / "big.jsonl"
    rows = [json.dumps({"m": "x" * 50}) for _ in range(30)]
    rows[17] = json.dumps({"m": f"token {GH}"})
    p.write_text("\n".join(rows))
    fs = agents.scan_file(str(p), home=str(tmp_path))
    assert [(f.line, f.kind) for f in fs] == [(18, "GitHub token")]


def test_cli_agents(tmp_path, monkeypatch, capsys):
    home = fake_home(tmp_path)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.chdir(tmp_path)
    assert main(["scan", "--agents"]) == 1
    out, err = capsys.readouterr()
    assert "Scanning AI agent files: Claude Code" in err and "rotate them" in out and GH not in out
    assert main(["scan", "--agents", "--json"]) == 1
    assert any("s1.jsonl:2" in loc for item in json.loads(capsys.readouterr().out) for loc in item["locations"])


def test_code_values_are_not_secrets():
    for line in ['token = "AKIA{R(16,U)}x9"', 'token = "https://api.digitalocean.com/v2/account"',
                 'token = "filename=secretscan-0.3.0-0.editable-py3-none-any.whl"',
                 'curl -H "Authorization: Bearer YOUR_NEW_TOKEN" https://x', "curl -u user:${PASSWORD} https://x"]:
        assert not scan_line(line), line
    assert scan_line("SECRET_KEY = 'dyv8cxk7dv97*t=m&jeh;+1$9de=-#xje$xv^#@nrhqcb!^5rc@u*b'")  # Django keys: kept


def test_report_says_delete_session_file(tmp_path):
    from leakkill import report
    from leakkill.cli import Item
    fs = agents.scan_agents(str(fake_home(tmp_path)), str(tmp_path), env={}, quiet=True)
    items = [Item(1, f.kind, f.secret, [f]) for f in fs if f.kind == "Slack token"]
    assert "Delete the agent session file" in report.render(items, "AI agent files", verified=False)
