import os, subprocess
from leakkill.scanner import scan_text, scan_history, scan_line, group, ignored, mask

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
def kinds(t): return [f.kind for f in scan_text(t, "x")]

def test_aws():         assert "AWS access key" in kinds('k = "AKIAIOSFODNN7EXAMPLE"')
def test_aws_secret():  assert "AWS secret key" in kinds('aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"')
def test_github():      assert "GitHub token" in kinds("t=" + GH)
def test_github_fine(): assert "GitHub token" in kinds("t=github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS")
def test_gitlab():      assert "GitLab token" in kinds("glpat-" + "x1Y2z3A4b5C6d7E8f9G0")
def test_slack_hook():  assert "Slack webhook" in kinds("https://hooks.slack.com/services/T0001/B0002/" + "abcdefghijklmnopqrstuvwx")
def test_discord():     assert "Discord webhook" in kinds("https://discord.com/api/webhooks/123456/" + "a" * 68)
def test_anthropic():   assert kinds("sk-ant-api03-" + "A" * 90) == ["Anthropic API key"]
def test_openai():      assert kinds("sk-proj-" + "B1" * 40) == ["OpenAI API key"]
def test_npm():         assert "npm token" in kinds("npm_" + "a1B2c3D4e5" * 3 + "a1B2c3")
def test_telegram():    assert "Telegram bot token" in kinds("123456789:AA" + "h" * 33)
def test_privkey():     assert "Private key block" in kinds("-----BEGIN RSA PRIVATE KEY-----")
def test_dburl():       assert "Credentials in URL" in kinds("postgres://admin:hunter2pw@db.internal/app")
def test_entropy():     assert kinds('api_key = "q8Zx3Lm9Vb2Nc7Rt5Yw1Hk4"')
def test_placeholder(): assert not kinds('api_key = "your_api_key_here_please"')
def test_low_entropy(): assert not kinds('password = "aaaaaaaaaaaaaaaa"')
def test_ignore():      assert not kinds('k = "AKIAIOSFODNN7EXAMPLE"  # leakkill:ignore')
def test_no_double():   assert kinds(f'token = "{GH}"') == ["GitHub token"]
def test_raw_kept_masked_shown():
    f = scan_text('k="AKIAIOSFODNN7EXAMPLE"', "x")[0]
    assert f.secret == "AKIAIOSFODNN7EXAMPLE" and "IOSFODNN7EXAMPLE" not in f.masked
def test_mask_webhook(): assert mask("https://hooks.slack.com/services/T/B/sec") == "https://hooks.slack.com/****"
def test_group_dedupes():
    g = group(scan_text(f"a={GH}\nb={GH}\n", "f"))
    assert len(g) == 1 and len(g[0][2]) == 2
def test_ignore_globs():
    assert ignored("./fixtures/a.txt", ["fixtures/"]) and ignored("x/y.snap", ["*.snap"]) and not ignored("src/a.py", ["fixtures/"])

def test_history_finds_deleted_secret(tmp_path):
    run = lambda *a: subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)
    run("init", "-q"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
    (tmp_path / "a.py").write_text('x = 1\nK = "AKIAIOSFODNN7EXAMPLE"\n'); run("add", "."); run("commit", "-qm", "oops")
    (tmp_path / "a.py").write_text("K = None\n"); run("commit", "-qam", "fix")
    cwd = os.getcwd(); os.chdir(tmp_path)
    try:
        hits = [f for f in scan_history() if f.kind == "AWS access key"]
        assert hits and hits[0].path == "a.py" and hits[0].line == 2 and hits[0].commit
    finally:
        os.chdir(cwd)
def test_identifier_values_are_not_secrets():
    assert not kinds('leakkill = "leakkill.cli:main_cli"')
    assert not kinds('auth_handler = "myapp.auth.handlers:login_view"')
def test_url_placeholders_ignored():
    for u in ["http://user:pass@example.com", "redis://username:password@127.0.0.1:6379",
              "http://{ENCODED_USER}:{ENCODED_PASSWORD}@x.com", "http://user:pass%20pass@x.com", "http://foo:bar@baz"]:
        assert not kinds(u), u
def test_url_real_password_found_and_masked():
    f = scan_text("DATABASE_URL=postgres://app:S3cr3tPw9@db.prod.internal/app", "x")[0]
    assert f.kind == "Credentials in URL" and f.masked == "postgres://app:****@db.prod.internal"
def test_test_named_vars_and_hashes_ignored():
    assert not kinds('MASKED_TEST_SECRET2 = "2JgchWvM1tpxT2lfz9aydoXW9yT1DN3NdLiejYxOOlzzV4nhBbYqmqZYbAV3V5Bf"')
    assert not kinds("ADMIN_PASSWORD = 'pbkdf2_sha256$30000$Vo0VlMnkR4Bk$qEvtdyZRWTcOsCnI/oQ7fVOu1XAURIZYoOZ3iq8Dr4M='")
