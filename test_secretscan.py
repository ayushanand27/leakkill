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
