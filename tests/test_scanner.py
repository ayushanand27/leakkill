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

NEW = {
    "OpenRouter key": "sk-or-v1-" + "a" * 64,
    "Hugging Face token": "hf_" + "A" * 34,
    "Groq key": "gsk_" + "A" * 52,
    "Replicate token": "r8_" + "A" * 37,
    "Perplexity key": "pplx-" + "A" * 48,
    "SendGrid key": "SG." + "A" * 22 + "." + "B" * 43,
    "DigitalOcean token": "dop_v1_" + "a" * 64,
    "Shopify token": "shpat_" + "a" * 32,
    "PyPI token": "pypi-AgEIcHlwaS5vcmc" + "A" * 60,
    "Docker Hub token": "dckr_pat_" + "A" * 27,
    "Twilio API key": "SK" + "a" * 32,
    "Postman key": "PMAK-" + "a" * 24 + "-" + "b" * 34,
    "Linear key": "lin_api_" + "A" * 40,
    "Azure storage key": "AccountKey=" + "A" * 86 + "==",
    "Stripe key": "sk_test_" + "A" * 24,
}
def test_new_providers_detected_exactly():
    for kind, token in NEW.items():
        assert kinds(f'x = "{token}"') == [kind], (kind, kinds(f'x = "{token}"'))
def test_openrouter_not_reported_as_openai():
    assert "OpenAI API key" not in kinds(NEW["OpenRouter key"])


def test_huge_lines_scan_in_linear_time():
    """Minified bundles can have megabyte-long lines; a backtracking regex must not stall the scan."""
    import time
    for line in ("secret" * 100_000, 'api_key="' * 60_000, "awssecret" * 60_000):
        t = time.perf_counter()
        scan_line(line)
        assert time.perf_counter() - t < 3, line[:20]


def test_every_rule_has_prefilter_keywords_that_its_matches_contain():
    """A rule without (correct) keywords would be silently skipped by the prefilter."""
    from leakkill.scanner import RULES, KEYWORDS, _has_keyword
    samples = dict(NEW, **{
        "AWS access key": "AKIAIOSFODNN7EXAMPLE", "GitHub token": GH, "GitLab token": "glpat-" + "x1Y2z3A4b5C6d7E8f9G0",
        "Slack token": "xoxb-1234567890-abcdefghij", "Slack webhook": "https://hooks.slack.com/services/T0001/B0002/" + "a" * 24,
        "Discord webhook": "https://discord.com/api/webhooks/1/" + "a" * 68, "Anthropic API key": "sk-ant-api03-" + "A" * 90,
        "OpenAI API key": "sk-proj-" + "B1" * 40, "npm token": "npm_" + "a1B2c3D4e5" * 3 + "a1B2c3",
        "Telegram bot token": "123456789:AA" + "h" * 33, "Google API key": "AIza" + "A" * 35,
        "Private key block": "-----BEGIN RSA PRIVATE KEY-----", "JWT": "eyJ" + "a" * 12 + ".eyJ" + "b" * 12 + "." + "c" * 12,
        "Credentials in URL": "postgres://app:S3cr3tPw9@db.prod.internal",
        "Basic auth credentials": "Authorization: Basic a3RnOmM4bmN6dS1uYm5qaHhwYQ==",
        "AWS secret key": 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"',
    })
    assert set(KEYWORDS) == set(RULES)
    for kind in RULES:
        assert _has_keyword(KEYWORDS[kind], samples[kind], samples[kind].lower()), kind
        assert kind in kinds(samples[kind]), kind


# ---- rules imported from Gitleaks ----
def test_gitleaks_prefixed_rules_detected():
    assert "Doppler API token" in kinds('DOPPLER = "dp.pt.' + "a1B2c3D4e5" * 4 + 'xyz"')
    assert "Adobe client secret" in kinds('x = "p8e-' + "a1B2c3D4" * 4 + '"')


def test_gitleaks_name_value_rules_use_two_phase_search():
    assert "Linear client secret" in kinds('LINEAR_CLIENT_SECRET = "' + "0a1b2c3d4e5f6789" * 2 + '"')
    assert "Linear client secret" not in kinds('LINEAR_CLIENT_SECRET = "' + "0" * 32 + '"')  # entropy too low


def test_gitleaks_global_allowlist_paths_and_stopwords():
    from leakkill.scanner import scan_text
    line = 'DOPPLER = "dp.pt.' + "a1B2c3D4e5" * 4 + 'xyz"'
    assert scan_text(line, "app/settings.py")
    assert not [f for f in scan_text(line, "static/logo.svg") if f.kind == "Doppler API token"]  # image path


def test_own_rules_win_over_imported_duplicates():
    assert kinds("t=" + GH) == ["GitHub token"]  # not also reported as Gitleaks' "GitHub PAT"


# ---- generic "name = value" rule (tuned on Samsung CredData, checked for noise on clean repos) ----
SECRETISH = "zMfX-tPfSeLy0oziyqF3ul28"
def test_assignment_forms_found():
    for line in [f'client_secret = "{SECRETISH}"', f'"client_secret": "{SECRETISH}"', f"'secret' => '{SECRETISH}'",
                 f"secret: {SECRETISH}", f"MINIO_ACCESS_KEY={SECRETISH}", f"  db_password: {SECRETISH}  # prod"]:
        assert kinds(line) == ["High-entropy secret"], line

def test_assignment_noise_filtered():
    for line in ["author=self.author_1,", 'cls.author_book_auto_m2m_intermediate_id = author_book_intermediate.pk',
                 '"password1": "FORBIDDEN_VALUE2",', "token = get_token_from_env()", "authority: some.module.path_v2"]:
        assert not kinds(line), line


def test_aligned_assignments_with_long_padding():
    assert kinds('  master_password                          = "Nwrdef9mlacvihhwf"') == ["High-entropy secret"]


def test_bare_key_name_found():
    for line in ['key = "n6i8J78+g9zskGPj4Ne3q4j/zSlOT2LPGdTIjqM2eq2="', '"Key": "a0a6ec5031294eb05c6c009b73561ad9"',
                 "signing_key: 'Qa8f9d7s6f5d4s3a2xZ'", "Key = Hx81Ld0Zq7Rt5Yw1Hk4"]:
        assert kinds(line) == ["High-entropy secret"], line


def test_bare_key_noise_filtered():
    for line in ['sort_key = "a8f9d7s6f5d4s3a2x9"', 'keyboard = "a8f9d7s6f5d4s3a2x9"', 'publicKey = "MIIBIjANBgkqhkiG9w0BA"',
                 'Value3 float64 `key:"value3,range=(1:5]"`', 'kms_key = "arn:aws:kms:us-east-1:123456789012:key/12"',
                 '- key: kubernetes.io/e2e-az-name', 'String key = "xkcoding:user:1"', 'encrypted_key: "0DJjBXri_kBcC46IkU5_Jk9B"',
                 '<c:Minus10Converter x:Key="Minus10Converter" />', 'monkey = "a8f9d7s6f5d4s3a2x9"', 'key_id = "a8f9d7s6f5d4s3a2x9"']:
        assert not kinds(line), line


def test_bare_key_value_check_is_linear():
    import time
    for value in ["1" * 4000 + "!", "Abc1" * 1000 + "!"]:
        t = time.perf_counter()
        kinds(f'key = "{value}"')
        assert time.perf_counter() - t < 1, value[:8]


def test_basic_auth_decoded_and_checked():
    assert kinds('headers = {"Authorization": "Basic a3RnOmM4bmN6dS1uYm5qaHhwYQ=="}') == ["Basic auth credentials"]
    for line in ["{'Authorization': 'Basic login_and_password_removed'}",  # not base64 of user:pass
                 "Authorization: Basic dXNlcjpwYXNzd29yZA==",  # user:password, a placeholder
                 "Authorization: Basic YWRtaW46JHtQQVNTV09SRH0=",  # admin:${PASSWORD}
                 "basic authentication is supported", "Authorization: Basic aGVsbG8gd29ybGQ="]:  # no colon
        assert not kinds(line), line


def test_basic_auth_password_with_url_characters():
    import base64
    b64 = base64.b64encode(b"svc:p@ss/w0rd Zq81").decode()
    assert kinds(f"Authorization: Basic {b64}") == ["Basic auth credentials"]


def test_url_with_all_caps_template_parts_ignored():
    for line in ["postgresql+asyncpg://MASTER_USER:MASTER_PASSWORD@RDS_ENDPOINT:5432/db",
                 "postgres://app:Sup3rS3cret9@DB_HOST:5432/app", "mysql://root:DB_PASSWORD@db.internal/app"]:
        assert not kinds(line), line
    assert kinds("postgres://app:SUP3RSECRET9@db.prod.internal/app") == ["Credentials in URL"]  # caps, but no _
