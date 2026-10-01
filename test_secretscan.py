from secretscan import scan_text
def kinds(t): return [h[2] for h in scan_text(t, "x")]

def test_aws():        assert "AWS access key" in kinds('k = "AKIAIOSFODNN7EXAMPLE"')
def test_github():     assert "GitHub token" in kinds("t=ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8")
def test_privkey():    assert "Private key block" in kinds("-----BEGIN RSA PRIVATE KEY-----")
def test_dburl():      assert "DB URL with password" in kinds("postgres://admin:hunter2pw@db.internal/app")
def test_entropy():    assert kinds('api_key = "q8Zx3Lm9Vb2Nc7Rt5Yw1Hk4"')
def test_placeholder():assert not kinds('api_key = "your_api_key_here_please"')
def test_low_entropy():assert not kinds('password = "aaaaaaaaaaaaaaaa"')
def test_ignore():     assert not kinds('k = "AKIAIOSFODNN7EXAMPLE"  # secretscan:ignore')
def test_masked():     assert "AKIAIOSFODNN7EXAMPLE" not in str(scan_text('k="AKIAIOSFODNN7EXAMPLE"', "x"))

# ---- agent guard ----
from secretscan import guard_check, scan_history
import os, subprocess

def ev(**kw): return kw
def test_guard_prompt():
    assert guard_check(ev(hook_event_name="UserPromptSubmit", prompt="use key AKIAIOSFODNN7EXAMPLE pls"))
def test_guard_clean_prompt():
    assert not guard_check(ev(hook_event_name="UserPromptSubmit", prompt="fix the login bug"))
def test_guard_blocks_read_env():
    assert guard_check(ev(hook_event_name="PreToolUse", tool_name="Read", tool_input={"file_path": r"C:\app\.env"}))
def test_guard_allows_read_code():
    assert not guard_check(ev(hook_event_name="PreToolUse", tool_name="Read", tool_input={"file_path": "app/main.py"}))
def test_guard_blocks_cat_env():
    assert guard_check(ev(hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": "cat .env | head"}))
def test_guard_blocks_hardcoded_write():
    assert guard_check(ev(hook_event_name="PreToolUse", tool_name="Write",
                          tool_input={"file_path": "a.py", "content": 'KEY = "AKIAIOSFODNN7EXAMPLE"'}))
def test_guard_allows_env_write():
    assert not guard_check(ev(hook_event_name="PreToolUse", tool_name="Write",
                              tool_input={"file_path": ".env", "content": "KEY=AKIAIOSFODNN7EXAMPLE"}))

def test_history_finds_deleted_secret(tmp_path):
    run = lambda *a: subprocess.run(["git", *a], cwd=tmp_path, check=True, capture_output=True)
    run("init", "-q"); run("config", "user.email", "t@t"); run("config", "user.name", "t")
    (tmp_path / "a.py").write_text('K = "AKIAIOSFODNN7EXAMPLE"\n'); run("add", "."); run("commit", "-qm", "oops")
    (tmp_path / "a.py").write_text("K = None\n"); run("commit", "-qam", "fix")
    cwd = os.getcwd(); os.chdir(tmp_path)
    try:
        assert any(f[2] == "AWS access key" for f in scan_history())
    finally:
        os.chdir(cwd)
