from leakkill.guard import guard_check

def ev(**kw): return kw
def _bash(cmd): return guard_check(ev(hook_event_name="PreToolUse", tool_name="Bash", tool_input={"command": cmd}))

def test_guard_prompt():
    assert guard_check(ev(hook_event_name="UserPromptSubmit", prompt="use key AKIAIOSFODNN7EXAMPLE pls"))
def test_guard_clean_prompt():
    assert not guard_check(ev(hook_event_name="UserPromptSubmit", prompt="fix the login bug"))
def test_guard_blocks_read_env():
    assert guard_check(ev(hook_event_name="PreToolUse", tool_name="Read", tool_input={"file_path": r"C:\app\.env"}))
    assert guard_check(ev(hook_event_name="PreToolUse", tool_name="Read", tool_input={"file_path": "/app/.env.production"}))
def test_guard_allows_read_code_and_templates():
    for p in ["app/main.py", "/app/.env.example"]:
        assert not guard_check(ev(hook_event_name="PreToolUse", tool_name="Read", tool_input={"file_path": p})), p
def test_guard_blocks_hardcoded_write():
    assert guard_check(ev(hook_event_name="PreToolUse", tool_name="Write",
                          tool_input={"file_path": "a.py", "content": 'KEY = "AKIAIOSFODNN7EXAMPLE"'}))
def test_guard_allows_env_write():
    assert not guard_check(ev(hook_event_name="PreToolUse", tool_name="Write",
                              tool_input={"file_path": ".env", "content": "KEY=AKIAIOSFODNN7EXAMPLE"}))
def test_guard_bash_readers():
    for c in ["cat .env | head", "grep . .env", "base64 .env", "sed -n p .env", "awk 1 .env", "cp .env /tmp/x",
              "python3 -c \"print(open('.env').read())\"", "cat ~/.ssh/id_rsa", "cat certs/server.pem"]:
        assert _bash(c), c
def test_guard_bash_allows():
    for c in ["ls -a .env", "git add .env.example", "cat .env.example", "echo hello", "cat environment.md"]:
        assert not _bash(c), c
