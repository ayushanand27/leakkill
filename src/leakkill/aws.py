"""Minimal AWS Signature Version 4 signer (stdlib only)."""
import hashlib, hmac, urllib.parse
from datetime import datetime, timezone


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sign(method, url, region, service, body, key_id, secret, headers=None, now=None):
    """Return the headers (incl. Authorization) for a SigV4-signed request."""
    t = now or datetime.now(timezone.utc)
    amzdate, datestamp = t.strftime("%Y%m%dT%H%M%SZ"), t.strftime("%Y%m%d")
    u = urllib.parse.urlsplit(url)
    q = sorted(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    canonical_qs = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}" for k, v in q)
    hdrs = {"host": u.netloc, "x-amz-date": amzdate, **{k.lower(): v for k, v in (headers or {}).items()}}
    signed = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k].strip()}\n" for k in sorted(hdrs))
    creq = "\n".join([method, u.path or "/", canonical_qs, canonical_headers, signed,
                      hashlib.sha256(body).hexdigest()])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amzdate, scope, hashlib.sha256(creq.encode()).hexdigest()])
    k = _hmac(("AWS4" + secret).encode(), datestamp)
    for part in (region, service, "aws4_request"):
        k = _hmac(k, part)
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    out = {k: v for k, v in hdrs.items() if k != "host"}
    out["Authorization"] = f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed}, Signature={sig}"
    return out
