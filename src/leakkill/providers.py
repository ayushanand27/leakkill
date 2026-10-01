"""Check whether a leaked secret is live, and revoke it where the provider allows.

Safety rules:
- A secret is only ever sent to the provider that issued it (hosts are hard-coded below).
- Redirects are never followed, so a credential can't be forwarded to another host.
- Verification uses read-only "who am I" calls. Revocation only runs on explicit request.
"""
import base64, json, os, re, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass, field

from . import __version__, aws

LIVE, DEAD, UNKNOWN, UNSUPPORTED = "LIVE", "DEAD", "UNKNOWN", "UNVERIFIABLE"
UA = f"leakkill/{__version__} (+https://github.com/ayushanand27/leakkill)"


@dataclass
class Result:
    status: str
    identity: str = ""
    note: str = ""
    extra: dict = field(default_factory=dict)  # provider data needed later (e.g. paired AWS secret)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http(method, url, headers=None, data=None, timeout=15):
    """Return (status, headers, body_bytes). HTTP errors are returned, network errors raise OSError."""
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": UA, **(headers or {})})
    try:
        with _opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read()


def _json(body):
    try:
        return json.loads(body or b"{}")
    except ValueError:
        return {}


def _by_status(code, live=(200,), dead=(401,), identity=""):
    if code in live:
        return Result(LIVE, identity)
    if code in dead:
        return Result(DEAD)
    return Result(UNKNOWN, note=f"unexpected HTTP {code}")


# ---------------------------------------------------------------- GitHub
def github_verify(s, ctx):
    code, h, body = http("GET", "https://api.github.com/user",
                         {"Authorization": f"Bearer {s}", "Accept": "application/vnd.github+json"})
    if code == 200:
        scopes = {k.lower(): v for k, v in h.items()}.get("x-oauth-scopes", "")
        return Result(LIVE, _json(body).get("login", "?"), f"scopes: {scopes}" if scopes else "")
    return _by_status(code)


def github_revoke(s, res):
    # Public endpoint built for exactly this: anyone can revoke a token they found exposed.
    # GitHub notifies the token owner. https://docs.github.com/en/rest/credentials/revoke
    code, _, body = http("POST", "https://api.github.com/credentials/revoke",
                         {"Accept": "application/vnd.github+json", "Content-Type": "application/json"},
                         json.dumps({"credentials": [s]}).encode())
    return code == 202, f"HTTP {code}" + ("" if code == 202 else f": {body[:200]!r}")


# ---------------------------------------------------------------- GitLab
def _gitlab():
    return os.environ.get("LEAKKILL_GITLAB_URL", "https://gitlab.com").rstrip("/")


def gitlab_verify(s, ctx):
    code, _, body = http("GET", f"{_gitlab()}/api/v4/personal_access_tokens/self", {"PRIVATE-TOKEN": s})
    if code == 200:
        j = _json(body)
        return Result(LIVE, f"token '{j.get('name')}' (user id {j.get('user_id')})",
                      f"scopes: {','.join(j.get('scopes', []))}; expires: {j.get('expires_at')}")
    return _by_status(code)


def gitlab_revoke(s, res):
    code, _, body = http("DELETE", f"{_gitlab()}/api/v4/personal_access_tokens/self", {"PRIVATE-TOKEN": s})
    return code == 204, f"HTTP {code}"


# ---------------------------------------------------------------- Slack
SLACK_DEAD = {"invalid_auth", "token_revoked", "account_inactive", "not_authed", "token_expired"}


def slack_verify(s, ctx):
    code, _, body = http("POST", "https://slack.com/api/auth.test", {"Authorization": f"Bearer {s}"})
    j = _json(body)
    if j.get("ok"):
        return Result(LIVE, f"{j.get('user')} @ {j.get('team')} ({j.get('url')})")
    if j.get("error") in SLACK_DEAD:
        return Result(DEAD, note=j["error"])
    return Result(UNKNOWN, note=j.get("error") or f"HTTP {code}")


def slack_revoke(s, res):
    code, _, body = http("POST", "https://slack.com/api/auth.revoke", {"Authorization": f"Bearer {s}"})
    j = _json(body)
    return bool(j.get("revoked")), j.get("error") or f"HTTP {code}"


def slack_webhook_verify(s, ctx):
    # An empty JSON body is rejected as invalid, so nothing gets posted to the channel.
    code, _, body = http("POST", s, {"Content-Type": "application/json"}, b"{}")
    if code == 400:
        return Result(LIVE, note=body.decode(errors="replace")[:60])
    if code in (403, 404, 410):
        return Result(DEAD, note=body.decode(errors="replace")[:60])
    return Result(UNKNOWN, note=f"HTTP {code}")


# ---------------------------------------------------------------- Discord
def discord_webhook_verify(s, ctx):
    code, _, body = http("GET", s)
    if code == 200:
        j = _json(body)
        return Result(LIVE, f"webhook '{j.get('name')}' (guild {j.get('guild_id')}, channel {j.get('channel_id')})")
    return _by_status(code, dead=(401, 404))


def discord_webhook_revoke(s, res):
    code, _, _ = http("DELETE", s)  # "Delete Webhook with Token" needs no other auth
    return code == 204, f"HTTP {code}"


# ---------------------------------------------------------------- Stripe
def stripe_verify(s, ctx):
    auth = "Basic " + base64.b64encode(f"{s}:".encode()).decode()
    code, _, body = http("GET", "https://api.stripe.com/v1/account", {"Authorization": auth})
    if code == 200:
        j = _json(body)
        return Result(LIVE, f"{j.get('id')} {j.get('email') or j.get('business_profile', {}).get('name') or ''}".strip())
    if code == 403:  # restricted key without account read permission: valid but limited
        return Result(LIVE, note="restricted key")
    return _by_status(code)


# ---------------------------------------------------------------- AWS
def _aws_call(key_id, secret, host, service, params):
    body = urllib.parse.urlencode(params).encode()
    hdr = aws.sign("POST", f"https://{host}/", "us-east-1", service, body, key_id, secret,
                   {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"})
    return http("POST", f"https://{host}/", hdr, body)


def _xml(body, tag):
    m = re.search(rf"<{tag}>([^<]*)</{tag}>", body.decode(errors="replace"))
    return m.group(1) if m else ""


def aws_verify(key_id, ctx):
    if key_id.startswith("ASIA"):
        return Result(UNKNOWN, note="temporary (STS) key: needs a session token; it expires on its own")
    secrets = ctx.get("aws_secrets") or []
    if not secrets:
        return Result(UNKNOWN, note="no matching AWS secret key found nearby; the key id alone can't be verified")
    mismatch = False
    for secret in secrets[:5]:
        code, _, body = _aws_call(key_id, secret, "sts.amazonaws.com", "sts",
                                  {"Action": "GetCallerIdentity", "Version": "2011-06-15"})
        if code == 200:
            return Result(LIVE, _xml(body, "Arn"), f"account {_xml(body, 'Account')}", {"aws_secret": secret})
        err = _xml(body, "Code")
        if err == "InvalidClientTokenId":
            return Result(DEAD, note="key id is unknown or deactivated")
        mismatch = mismatch or err == "SignatureDoesNotMatch"
    return Result(UNKNOWN, note="key id exists but no paired secret matched" if mismatch else f"HTTP {code}")


def aws_revoke(key_id, res):
    secret = res.extra.get("aws_secret")
    if not secret:
        return False, "no verified secret for this key"
    # Deactivate (reversible) rather than delete, as AWS recommends. Works only if the key has iam:UpdateAccessKey.
    code, _, body = _aws_call(key_id, secret, "iam.amazonaws.com", "iam",
                              {"Action": "UpdateAccessKey", "AccessKeyId": key_id, "Status": "Inactive",
                               "Version": "2010-05-08"})
    if code == 200:
        return True, "access key set to Inactive"
    return False, f"{_xml(body, 'Code') or 'HTTP ' + str(code)}: this key can't deactivate itself, use the console"


# ---------------------------------------------------------------- AI providers, npm, Telegram
def openai_verify(s, ctx):
    code, _, _ = http("GET", "https://api.openai.com/v1/models", {"Authorization": f"Bearer {s}"})
    if code in (403, 429):  # authenticated but restricted / out of quota: still a working key
        return Result(LIVE, note=f"HTTP {code}")
    return _by_status(code)


def anthropic_verify(s, ctx):
    code, _, _ = http("GET", "https://api.anthropic.com/v1/models",
                      {"x-api-key": s, "anthropic-version": "2023-06-01"})
    if code in (403, 429):
        return Result(LIVE, note=f"HTTP {code}")
    return _by_status(code)


def npm_verify(s, ctx):
    code, _, body = http("GET", "https://registry.npmjs.org/-/whoami", {"Authorization": f"Bearer {s}"})
    return _by_status(code, dead=(401, 403), identity=_json(body).get("username", "") if code == 200 else "")


def telegram_verify(s, ctx):
    code, _, body = http("GET", f"https://api.telegram.org/bot{s}/getMe")
    if code == 200:
        return Result(LIVE, "@" + str(_json(body).get("result", {}).get("username")))
    return _by_status(code, dead=(401, 404))


@dataclass
class Provider:
    verify: object = None
    revoke: object = None
    manual: str = ""


PROVIDERS = {
    "GitHub token": Provider(github_verify, github_revoke,
                             "Delete it at https://github.com/settings/tokens (or the app's settings for gho_/ghu_ tokens)."),
    "GitLab token": Provider(gitlab_verify, gitlab_revoke,
                             "Revoke it at https://gitlab.com/-/user_settings/personal_access_tokens."),
    "Slack token": Provider(slack_verify, slack_revoke,
                            "Regenerate it in your app's 'OAuth & Permissions' page at https://api.slack.com/apps."),
    "Slack webhook": Provider(slack_webhook_verify, None,
                              "Remove the webhook in your app's 'Incoming Webhooks' page at https://api.slack.com/apps."),
    "Discord webhook": Provider(discord_webhook_verify, discord_webhook_revoke,
                                "Server Settings > Integrations > Webhooks > delete the webhook."),
    "Stripe key": Provider(stripe_verify, None,
                           "Roll the key at https://dashboard.stripe.com/apikeys (Stripe has no API to revoke keys)."),
    "AWS access key": Provider(aws_verify, aws_revoke,
                               "Deactivate then delete it in IAM > Users > Security credentials "
                               "(https://console.aws.amazon.com/iam/home#/security_credentials), then check CloudTrail "
                               "for activity from this key."),
    "OpenAI API key": Provider(openai_verify, None, "Revoke it at https://platform.openai.com/api-keys."),
    "Anthropic API key": Provider(anthropic_verify, None, "Delete it at https://console.anthropic.com/settings/keys."),
    "npm token": Provider(npm_verify, None, "Run `npm token list` then `npm token revoke <id>`, "
                                            "or use https://www.npmjs.com/settings/<user>/tokens."),
    "Telegram bot token": Provider(telegram_verify, None, "Send /revoke to @BotFather and pick the bot."),
    "Google API key": Provider(None, None, "Delete or restrict it at https://console.cloud.google.com/apis/credentials."),
    "AWS secret key": Provider(None, None, "Rotate it together with its access key id (see the AWS access key entry)."),
    "Private key block": Provider(None, None, "Generate a new key pair and remove the old public key everywhere it is "
                                              "trusted (servers' authorized_keys, GitHub deploy keys, TLS certs)."),
    "JWT": Provider(None, None, "If it is long-lived, rotate the signing secret that issued it."),
    "Credentials in URL": Provider(None, None, "Change that password (database user: ALTER USER ... PASSWORD; proxy or "
                                               "service account: its admin console) and restrict network access to it."),
    "High-entropy secret": Provider(None, None, "Treat as compromised: rotate it with whoever issued it."),
}


def verify(kind, secret, ctx=None):
    p = PROVIDERS.get(kind)
    if not p or not p.verify:
        return Result(UNSUPPORTED)
    try:
        return p.verify(secret, ctx or {})
    except Exception as e:  # DNS, timeout, proxy refusal, truncated response... never crash the scan
        return Result(UNKNOWN, note=f"network error: {getattr(e, 'reason', e)}")


def revoke(kind, secret, result):
    p = PROVIDERS.get(kind)
    if not p or not p.revoke:
        return False, "no revocation API: " + (p.manual if p else "rotate it manually")
    try:
        return p.revoke(secret, result)
    except Exception as e:
        return False, f"network error: {getattr(e, 'reason', e)}"
