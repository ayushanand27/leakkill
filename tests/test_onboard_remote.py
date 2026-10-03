import json, os, subprocess, sys, tempfile

import pytest

from leakkill import cli, onboard, remote, scanner

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


# ---------------------------------------------------------------- scan <url>
@pytest.mark.parametrize("arg,expected", [
    ("https://github.com/owner/repo", "https://github.com/owner/repo"),
    ("https://github.com/owner/repo.git", "https://github.com/owner/repo.git"),
    ("github.com/owner/repo", "https://github.com/owner/repo"),
    ("git@github.com:owner/repo.git", "git@github.com:owner/repo.git"),
    ("ssh://git@host/owner/repo", "ssh://git@host/owner/repo"),
])
def test_parse_accepts_clone_urls(arg, expected, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert remote.parse(arg) == expected


@pytest.mark.parametrize("arg", ["ext::sh -c 'touch /tmp/x'", "file:///etc", "--upload-pack=evil", "-h", "src", ".",
                                 "http://github.com/o/r", "ftp://x/y", "https://x/y z", "github.com/owner", ""])
def test_parse_rejects_everything_else(arg, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert remote.parse(arg) is None


def test_an_existing_local_path_is_never_a_url(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "github.com" / "o").mkdir(parents=True)
    (tmp_path / "github.com" / "o" / "r").mkdir()
    assert remote.parse("github.com/o/r") is None


def test_credentials_never_printed():
    assert remote.safe_url("https://user:pw@host/o/r") == "https://host/o/r"


@pytest.fixture
def fake_remote(tmp_path, monkeypatch):
    """A local repository standing in for the remote one: a secret that was committed and later deleted."""
    src = tmp_path / "src_repo"
    src.mkdir()
    git(src, "init", "-q")
    git(src, "config", "user.email", "t@example.com")
    git(src, "config", "user.name", "t")
    (src / "old.py").write_text(f'T = "{GH}"\n')
    (src / ".leakkillignore").write_text("*\n")  # the repo tries to hide everything
    git(src, "add", "-A"); git(src, "commit", "-qm", "leak")
    (src / "old.py").write_text("T = 1\n")
    (src / "new.py").write_text(f'T = "{GH}"  # leakkill:ignore\n')
    git(src, "add", "-A"); git(src, "commit", "-qm", "remove")
    def clone(url, dest, full_history):
        args = ["git", "clone", "--quiet", str(src), dest] if full_history else ["git", "clone", "--quiet", "--depth", "1", "file://" + str(src), dest]
        subprocess.run(args, check=True, capture_output=True)
    cleaned = []
    real = remote.checkout
    monkeypatch.setattr(remote, "checkout", lambda url, full_history=False: real(url, full_history, clone=clone))
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


def test_remote_scan_ignores_the_repos_own_hiding_and_cleans_up(fake_remote, capsys, monkeypatch, tmp_path):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    assert cli.main(["scan", "https://example.com/o/r"]) == 1  # new.py: its leakkill:ignore and .leakkillignore are not honored
    out = capsys.readouterr().out
    assert "new.py:1" in out and GH not in out
    assert scanner.INLINE_IGNORE is True and os.getcwd() == str(fake_remote)  # state restored
    assert os.listdir(scratch) == []  # the clone is gone


def test_remote_history_finds_the_deleted_secret(fake_remote, capsys):
    assert cli.main(["scan", "--history", "--json", "https://example.com/o/r"]) == 1
    assert any("old.py" in loc for i in json.loads(capsys.readouterr().out) for loc in i["locations"])


def test_remote_never_verifies_or_revokes_someone_elses_keys(fake_remote, capsys, monkeypatch):
    called = []
    monkeypatch.setattr(cli.providers, "verify", lambda *a, **k: called.append(a))
    for cmd in ("verify", "revoke"):
        assert cli.main([cmd, "https://example.com/o/r"]) == 2
    assert "belong to someone else" in capsys.readouterr().err and not called


def test_remote_report_writes_next_to_you_not_in_the_temp_clone(fake_remote):
    assert cli.main(["report", "-o", "r.md", "https://example.com/o/r"]) == 1
    text = (fake_remote / "r.md").read_text()
    assert "not verified" in text and GH not in text  # never contacted a provider about keys that aren't yours


def test_clone_failure_is_a_clean_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    def boom(url, dest, full_history):
        raise RuntimeError("repository not found")
    real = remote.checkout
    monkeypatch.setattr(remote, "checkout", lambda url, full_history=False: real(url, full_history, clone=boom))
    assert cli.main(["scan", "https://example.com/o/missing"]) == 2
    assert "could not clone https://example.com/o/missing: repository not found" in capsys.readouterr().err


# ---------------------------------------------------------------- init
def test_init_sets_up_what_exists_and_is_repeatable(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    work = tmp_path / "proj"
    work.mkdir()
    git(work, "init", "-q")
    monkeypatch.chdir(work)
    monkeypatch.setattr(onboard.shutil, "which", lambda p: None)
    monkeypatch.setenv("HOME", str(home)); monkeypatch.setenv("USERPROFILE", str(home))
    assert cli.main(["init"]) == 0
    assert (work / ".git" / "hooks" / "pre-commit").exists()
    assert (work / ".cursor" / "hooks.json").exists() and not (work / ".claude").exists()  # only the agent in use
    assert "uses: ayushanand27/leakkill@v0" in (work / ".github" / "workflows" / "leakkill.yml").read_text()
    first = (work / ".cursor" / "hooks.json").read_text()
    assert cli.main(["init"]) == 0  # again: nothing breaks, nothing duplicates
    assert (work / ".cursor" / "hooks.json").read_text() == first
    assert "kept your existing" in capsys.readouterr().out


def test_init_never_overwrites_foreign_files(tmp_path, monkeypatch, capsys):
    work = tmp_path / "proj"
    (work / ".git" / "hooks").mkdir(parents=True)
    (work / ".git" / "hooks" / "pre-commit").write_text("#!/bin/sh\necho mine\n")
    (work / ".github" / "workflows").mkdir(parents=True)
    (work / ".github" / "workflows" / "leakkill.yml").write_text("mine: true\n")
    monkeypatch.chdir(work)
    monkeypatch.setattr(onboard.shutil, "which", lambda p: None)
    monkeypatch.setenv("HOME", str(tmp_path / "nohome")); monkeypatch.setenv("USERPROFILE", str(tmp_path / "nohome"))
    assert cli.main(["init"]) == 0
    assert "echo mine" in (work / ".git" / "hooks" / "pre-commit").read_text()
    assert (work / ".github" / "workflows" / "leakkill.yml").read_text() == "mine: true\n"
    out = capsys.readouterr().out
    assert "isn't leakkill's" in out and "no AI coding agent found" in out
    assert cli.main(["install-hook"]) == 1  # the standalone command refuses too
