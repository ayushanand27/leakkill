"""Bugs found by using leakkill like a newcomer on Windows and in a normal git project."""
import os, subprocess, sys

import pytest

from leakkill import cli, scanner

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
LINE = f'TOKEN = "{GH}"\n'


def found(tmp_path, **kw):
    return {os.path.basename(f.path) for f in scanner.scan_paths([str(tmp_path)], **kw)}


def test_text_in_other_encodings_is_scanned(tmp_path):
    (tmp_path / "utf16_bom.py").write_bytes(LINE.replace("\n", "\r\n").encode("utf-16"))  # PowerShell 5 `echo >`
    (tmp_path / "utf16_le_nobom.txt").write_bytes(LINE.encode("utf-16-le"))
    (tmp_path / "utf16_be_nobom.txt").write_bytes(LINE.encode("utf-16-be"))
    (tmp_path / "latin1.py").write_bytes(("# caf\xe9\n" + LINE).encode("latin-1"))
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbf" + LINE.encode())
    (tmp_path / "plain.py").write_text(LINE)
    assert found(tmp_path) == {"utf16_bom.py", "utf16_le_nobom.txt", "utf16_be_nobom.txt", "latin1.py", "bom.py",
                               "plain.py"}


def test_decode_text_binary_and_edges():
    assert scanner.decode_text(b"\xff\xfe\x00\x00\xd8") is None or True  # never raises
    assert scanner.decode_text(b"\x00\x01\xff\xfe\x00\x80" * 50) is None  # binary with invalid UTF-8
    assert scanner.decode_text(b"") == ""
    assert scanner.decode_text("héllo".encode("utf-8")) == "héllo"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_named_pipe_does_not_hang_the_scan(tmp_path):
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "app.py").write_text(LINE)
    code = ("import sys; from leakkill import scanner; "
            f"print(len(scanner.scan_paths([{str(tmp_path)!r}], jobs=1)))")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30)
    assert r.stdout.strip() == "1"  # a blocked read would have hit the timeout


def test_skipped_files_are_reported_not_hidden(tmp_path, monkeypatch, capsys):
    (tmp_path / "huge.sql").write_text(LINE * 5)
    monkeypatch.setattr(scanner, "MAX_SCAN_BYTES", 10)
    assert scanner.scan_paths([str(tmp_path)]) == []
    assert [(os.path.basename(s.path), s.reason) for s in scanner.SKIPPED] == [("huge.sql", "too large")]
    cli.note_skipped()
    assert "skipped 1 file(s) it could not scan: 1 too large" in capsys.readouterr().err


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_gitignored_files_are_left_out_but_tracked_ones_never(tmp_path, capsys):
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.email", "t@example.com")
    git(tmp_path, "config", "user.name", "t")
    (tmp_path / ".gitignore").write_text(".env\nprivate/\n")
    (tmp_path / "private").mkdir()
    (tmp_path / "private" / "out.py").write_text(LINE)
    (tmp_path / ".env").write_text(LINE)
    (tmp_path / "app.py").write_text(LINE)
    (tmp_path / "old.env.py").write_text(LINE)
    git(tmp_path, "add", "-f", "old.env.py")  # tracked
    (tmp_path / ".gitignore").write_text(".env\nprivate/\nold.env.py\n")  # ignored later, but still tracked
    assert found(tmp_path) == {"app.py", "old.env.py"}
    assert sorted(os.path.basename(f) for f in scanner.IGNORED) == [".env", "out.py"]
    cli.note_skipped()
    assert "left out 2 git-ignored file(s)" in capsys.readouterr().err
    assert found(tmp_path, include_ignored=True) == {"app.py", "old.env.py", ".env", "out.py"}
    assert scanner.IGNORED == []


def test_no_git_means_everything_is_scanned(tmp_path):
    (tmp_path / ".gitignore").write_text(".env\n")  # not a repository: the file means nothing
    (tmp_path / ".env").write_text(LINE)
    assert found(tmp_path) == {".env"}


def test_cli_include_ignored_flag(tmp_path, monkeypatch):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text(".env\n")
    (tmp_path / ".env").write_text(LINE)
    monkeypatch.chdir(tmp_path)
    assert cli.main(["scan"]) == 0
    assert cli.main(["scan", "--include-ignored"]) == 1


def test_naming_an_ignored_folder_scans_it(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("data/\n")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "dump.txt").write_text(LINE)
    assert {os.path.basename(f.path) for f in scanner.scan_paths([str(tmp_path / "data")])} == {"dump.txt"}
    assert scanner.IGNORED == []
    assert found(tmp_path) == set() and len(scanner.IGNORED) == 1  # but scanning the repo root leaves it out
