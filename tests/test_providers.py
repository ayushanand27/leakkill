import http.server, json, threading
from datetime import datetime, timezone
import pytest
from leakkill import aws, providers as P

GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


class FakeHTTP:
    """Replaces providers.http: routes (method, url-prefix) -> (status, headers, body); records calls."""
    def __init__(self, routes): self.routes, self.calls = routes, []
    def __call__(self, method, url, headers=None, data=None, timeout=15):
        self.calls.append((method, url, headers or {}, data))
        for (m, prefix), resp in self.routes.items():
            if m == method and url.startswith(prefix):
                return resp
        raise AssertionError(f"unexpected request {method} {url}")


@pytest.fixture
def fake(monkeypatch):
    def install(routes):
        f = FakeHTTP(routes); monkeypatch.setattr(P, "http", f); return f
    return install


def test_sigv4_matches_aws_official_test_vector():
    h = aws.sign("GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", "us-east-1", "iam", b"",
                 "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                 {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
                 datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc))
    assert h["Authorization"].endswith("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")


def test_github_live_with_identity_and_scopes(fake):
    f = fake({("GET", "https://api.github.com/user"): (200, {"X-OAuth-Scopes": "repo, gist"}, b'{"login":"octocat"}')})
    r = P.verify("GitHub token", GH)
    assert (r.status, r.identity, r.note) == (P.LIVE, "octocat", "scopes: repo, gist")
    assert f.calls[0][2]["Authorization"] == f"Bearer {GH}"

def test_github_dead(fake):
    fake({("GET", "https://api.github.com/user"): (401, {}, b"")})
    assert P.verify("GitHub token", GH).status == P.DEAD

def test_github_revoke_uses_public_endpoint_without_auth(fake):
    f = fake({("POST", "https://api.github.com/credentials/revoke"): (202, {}, b"")})
    ok, _ = P.revoke("GitHub token", GH, P.Result(P.LIVE))
    method, url, headers, data = f.calls[0]
    assert ok and json.loads(data) == {"credentials": [GH]} and "Authorization" not in headers

def test_slack_live_dead_revoke(fake):
    fake({("POST", "https://slack.com/api/auth.test"): (200, {}, b'{"ok":true,"user":"bob","team":"Acme","url":"https://acme.slack.com/"}')})
    assert P.verify("Slack token", "xoxb-1").identity == "bob @ Acme (https://acme.slack.com/)"
    fake({("POST", "https://slack.com/api/auth.test"): (200, {}, b'{"ok":false,"error":"token_revoked"}')})
    assert P.verify("Slack token", "xoxb-1").status == P.DEAD
    fake({("POST", "https://slack.com/api/auth.revoke"): (200, {}, b'{"ok":true,"revoked":true}')})
    assert P.revoke("Slack token", "xoxb-1", P.Result(P.LIVE))[0]

def test_gitlab_live_and_self_revoke(fake):
    f = fake({("GET", "https://gitlab.com/api/v4/personal_access_tokens/self"):
              (200, {}, b'{"name":"ci","user_id":7,"scopes":["api"],"expires_at":null}'),
              ("DELETE", "https://gitlab.com/api/v4/personal_access_tokens/self"): (204, {}, b"")})
    r = P.verify("GitLab token", "glpat-x")
    assert r.status == P.LIVE and "user id 7" in r.identity and "api" in r.note
    assert P.revoke("GitLab token", "glpat-x", r)[0] and f.calls[-1][2]["PRIVATE-TOKEN"] == "glpat-x"

def test_stripe_restricted_key_403_is_live(fake):
    fake({("GET", "https://api.stripe.com/v1/account"): (403, {}, b"")})
    assert P.verify("Stripe key", "rk_live_x").status == P.LIVE

def test_stripe_has_no_auto_revoke():
    ok, msg = P.revoke("Stripe key", "sk_live_x", P.Result(P.LIVE))
    assert not ok and "dashboard.stripe.com" in msg

def test_openai_quota_exceeded_counts_as_live(fake):
    fake({("GET", "https://api.openai.com/v1/models"): (429, {}, b"")})
    assert P.verify("OpenAI API key", "sk-proj-x").status == P.LIVE

def test_discord_webhook_verify_and_delete(fake):
    url = "https://discord.com/api/webhooks/1/abc"
    fake({("GET", url): (200, {}, b'{"name":"deploy","guild_id":"9","channel_id":"8"}'), ("DELETE", url): (204, {}, b"")})
    assert P.verify("Discord webhook", url).status == P.LIVE
    assert P.revoke("Discord webhook", url, P.Result(P.LIVE))[0]

def test_aws_pairs_secret_and_verifies(fake):
    f = fake({("POST", "https://sts.amazonaws.com/"): (200, {}, b"<Arn>arn:aws:iam::123:user/ci</Arn><Account>123</Account>")})
    r = P.verify("AWS access key", "AKIAIOSFODNN7EXAMPLE", {"aws_secrets": ["s" * 40]})
    assert r.status == P.LIVE and r.identity == "arn:aws:iam::123:user/ci" and r.extra["aws_secret"] == "s" * 40
    assert f.calls[0][2]["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")

def test_aws_without_secret_is_unknown_and_makes_no_call(fake):
    f = fake({})
    assert P.verify("AWS access key", "AKIAIOSFODNN7EXAMPLE", {}).status == P.UNKNOWN and not f.calls

def test_aws_invalid_key_is_dead(fake):
    fake({("POST", "https://sts.amazonaws.com/"): (403, {}, b"<Code>InvalidClientTokenId</Code>")})
    assert P.verify("AWS access key", "AKIAIOSFODNN7EXAMPLE", {"aws_secrets": ["s" * 40]}).status == P.DEAD

def test_aws_revoke_deactivates(fake):
    f = fake({("POST", "https://iam.amazonaws.com/"): (200, {}, b"<UpdateAccessKeyResponse/>")})
    ok, _ = P.revoke("AWS access key", "AKIAIOSFODNN7EXAMPLE", P.Result(P.LIVE, extra={"aws_secret": "s" * 40}))
    assert ok and b"Status=Inactive" in f.calls[0][3]

def test_network_error_is_unknown_not_crash(monkeypatch):
    def boom(*a, **k): raise OSError("proxy refused")
    monkeypatch.setattr(P, "http", boom)
    assert P.verify("GitHub token", GH).status == P.UNKNOWN

def test_unverifiable_kinds_make_no_network_call(fake):
    f = fake({})
    assert P.verify("Private key block", "-----BEGIN").status == P.UNSUPPORTED and not f.calls


def test_redirects_are_never_followed():
    """A provider redirect must not forward the credential to another host."""
    hits = []
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append((self.path, self.headers.get("Authorization")))
            if self.path == "/start":
                self.send_response(302); self.send_header("Location", "/stolen"); self.end_headers()
            else:
                self.send_response(200); self.end_headers()
        def log_message(self, *a): pass
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    code, _, _ = P.http("GET", f"http://127.0.0.1:{srv.server_port}/start", {"Authorization": "Bearer secret"})
    srv.server_close()
    assert code == 302 and [p for p, _ in hits] == ["/start"]


def test_huggingface_live_with_name_and_role(fake):
    fake({("GET", "https://huggingface.co/api/whoami-v2"):
          (200, {}, b'{"name":"ayush","auth":{"accessToken":{"role":"read"}}}')})
    r = P.verify("Hugging Face token", "hf_x")
    assert (r.status, r.identity, r.note) == (P.LIVE, "ayush", "token role: read")

def test_simple_bearer_providers_live_and_dead(fake):
    cases = {"OpenRouter key": "https://openrouter.ai/api/v1/key",
             "DigitalOcean token": "https://api.digitalocean.com/v2/account",
             "Replicate token": "https://api.replicate.com/v1/account",
             "Groq key": "https://api.groq.com/openai/v1/models",
             "SendGrid key": "https://api.sendgrid.com/v3/scopes"}
    for kind, url in cases.items():
        f = fake({("GET", url): (200, {}, b'{}')})
        assert P.verify(kind, "tok").status == P.LIVE, kind
        assert f.calls[0][2]["Authorization"] == "Bearer tok"
        fake({("GET", url): (401, {}, b'')})
        assert P.verify(kind, "tok").status == P.DEAD, kind

def test_digitalocean_identity(fake):
    fake({("GET", "https://api.digitalocean.com/v2/account"): (200, {}, b'{"account":{"email":"a@b.c"}}')})
    assert P.verify("DigitalOcean token", "dop_v1_x").identity == "a@b.c"

def test_sendgrid_revoke_deletes_itself_by_key_id(fake):
    key = "SG.KEYID123.secretpart"
    f = fake({("DELETE", "https://api.sendgrid.com/v3/api_keys/KEYID123"): (204, {}, b"")})
    assert P.revoke("SendGrid key", key, P.Result(P.LIVE))[0]
    assert f.calls[0][2]["Authorization"] == f"Bearer {key}"

def test_sendgrid_revoke_without_permission_falls_back(fake):
    fake({("DELETE", "https://api.sendgrid.com/v3/api_keys/K"): (403, {}, b"")})
    ok, msg = P.revoke("SendGrid key", "SG.K.s", P.Result(P.LIVE))
    assert not ok and "dashboard" in msg

def test_stripe_test_mode_labelled(fake):
    fake({("GET", "https://api.stripe.com/v1/account"): (200, {}, b'{"id":"acct_1","email":"a@b.c"}')})
    r = P.verify("Stripe key", "sk_test_x")
    assert r.status == P.LIVE and r.note == "test mode"

def test_every_detector_has_remediation():
    from leakkill.scanner import RULES
    for kind in list(RULES) + ["High-entropy secret"]:
        assert P.PROVIDERS[kind].manual, kind
