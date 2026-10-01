import json
from leakkill import cli, providers as P

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def project(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text(f'TOKEN = "{GH}"\nKEY = "AKIAIOSFODNN7EXAMPLE"\n')
    monkeypatch.chdir(tmp_path)


def fake_verify(monkeypatch, status=P.LIVE):
    monkeypatch.setattr(P, "verify", lambda kind, s, ctx=None: P.Result(status, "octocat") if kind == "GitHub token"
                        else P.Result(P.UNKNOWN, note="no paired secret"))


def test_scan_is_offline_and_never_prints_raw(tmp_path, monkeypatch, capsys):
    project(tmp_path, monkeypatch)
    monkeypatch.setattr(P, "http", lambda *a, **k: (_ for _ in ()).throw(AssertionError("network used")))
    assert cli.main(["scan"]) == 1
    out = capsys.readouterr().out
    assert "GitHub token" in out and GH not in out and "#1" in out


def test_verify_exit_code_and_json(tmp_path, monkeypatch, capsys):
    project(tmp_path, monkeypatch); fake_verify(monkeypatch)
    assert cli.main(["verify", "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data[0]["status"] == "LIVE" and data[0]["identity"] == "octocat" and GH not in json.dumps(data)


def test_revoke_is_dry_run_by_default(tmp_path, monkeypatch, capsys):
    project(tmp_path, monkeypatch); fake_verify(monkeypatch)
    called = []
    monkeypatch.setattr(P, "revoke", lambda *a: called.append(a) or (True, "ok"))
    cli.main(["revoke"])
    assert not called and "Dry run" in capsys.readouterr().out
    cli.main(["revoke", "--yes", "--only", "1"])
    assert len(called) == 1 and called[0][0] == "GitHub token"


def test_revoke_skips_dead_keys(tmp_path, monkeypatch, capsys):
    project(tmp_path, monkeypatch); fake_verify(monkeypatch, P.DEAD)
    called = []
    monkeypatch.setattr(P, "revoke", lambda *a: called.append(a) or (True, "ok"))
    assert cli.main(["revoke", "--yes"]) == 0 and not called


def test_report(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch); fake_verify(monkeypatch)
    cli.main(["report", "--replacements", "repl.txt"])
    md = (tmp_path / "leakkill-report.md").read_text(encoding="utf-8")
    assert "**1 live**" in md and "octocat" in md and "leakkill revoke --only 1 --yes" in md and GH not in md
    assert f"{GH}==>***REMOVED-GITHUB-TOKEN***" in (tmp_path / "repl.txt").read_text()


def test_leakkillignore(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch)
    (tmp_path / ".leakkillignore").write_text("app.py\n")
    assert cli.main(["scan"]) == 0


def test_legacy_flags_still_work(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch)
    assert cli.main([]) == 1 and cli.main(["--exclude-tests", "."]) == 1


def test_scan_report_option_writes_report_in_same_run(tmp_path, monkeypatch):
    project(tmp_path, monkeypatch); fake_verify(monkeypatch)
    assert cli.main(["verify", "--report", "r.md"]) == 1
    md = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert "**1 live**" in md and GH not in md


def test_revoke_dry_run_warns_about_side_effects(tmp_path, monkeypatch, capsys):
    project(tmp_path, monkeypatch); fake_verify(monkeypatch)
    cli.main(["revoke"])
    assert "GitHub emails the token's owner" in capsys.readouterr().out


def test_typo_command_is_an_error_not_clean(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["verfiy"]) == 2
    out = capsys.readouterr()
    assert "Clean" not in out.out and "did you mean `leakkill verify`" in out.err


def test_missing_path_is_an_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan", "does-not-exist"]) == 2
    assert "no such file or directory: does-not-exist" in capsys.readouterr().err
