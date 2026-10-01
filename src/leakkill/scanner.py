"""Find secrets in files, staged changes and git history. Never touches the network."""
import fnmatch, math, os, re, subprocess
from dataclasses import dataclass

# kind -> regex. Group 1 (if present) is the secret, otherwise the whole match.
RULES = {
    "AWS access key":      re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    "AWS secret key":      re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?[\s:=\"']+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
    "GitHub token":        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    "GitLab token":        re.compile(r"\b(glpat-[A-Za-z0-9_\-.]{20,})"),
    "Slack token":         re.compile(r"\b(xox[abposre]-[A-Za-z0-9-]{10,})"),
    "Slack webhook":       re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,})"),
    "Discord webhook":     re.compile(r"(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{60,})"),
    "Stripe key":          re.compile(r"\b([sr]k_(?:live|test)_[0-9A-Za-z]{20,})\b"),
    "Anthropic API key":   re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{32,})"),
    "OpenRouter key":      re.compile(r"\b(sk-or-v1-[a-f0-9]{64})\b"),
    "OpenAI API key":      re.compile(r"\b(sk-(?!ant-|or-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,})"),
    "Hugging Face token":  re.compile(r"\b(hf_[A-Za-z0-9]{34,40})\b"),
    "Groq key":            re.compile(r"\b(gsk_[A-Za-z0-9]{48,56})\b"),
    "Replicate token":     re.compile(r"\b(r8_[A-Za-z0-9]{37})\b"),
    "Perplexity key":      re.compile(r"\b(pplx-[A-Za-z0-9]{48})\b"),
    "SendGrid key":        re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})(?![A-Za-z0-9_\-])"),
    "DigitalOcean token":  re.compile(r"\b(do[po]_v1_[a-f0-9]{64})\b"),
    "Shopify token":       re.compile(r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"),
    "PyPI token":          re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"),
    "Docker Hub token":    re.compile(r"\b(dckr_pat_[A-Za-z0-9_\-]{27})(?![A-Za-z0-9_\-])"),
    "Twilio API key":      re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
    "Postman key":         re.compile(r"\b(PMAK-[a-f0-9]{24}-[a-f0-9]{34})\b"),
    "Linear key":          re.compile(r"\b(lin_api_[A-Za-z0-9]{40})\b"),
    "Azure storage key":   re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)"),
    "npm token":           re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
    "Telegram bot token":  re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})(?![A-Za-z0-9_\-])"),
    "Google API key":      re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})"),
    "Private key block":   re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----)"),
    "JWT":                 re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
    "Credentials in URL":  re.compile(r"\b([a-z][a-z0-9+]*://[^\s:/@]+:[^\s:/@]{3,}@[^\s/\"']+)"),
}
# key = "value" where the key name looks sensitive and the value looks random.
# Name parts are length-bounded so matching stays linear on huge (e.g. minified) lines.
ASSIGN = re.compile(
    r"""(?i)(?<![\w.-])[\w.-]{0,40}?(?:secret|token|passwd|password|api[_-]?key|private[_-]?key|auth)[\w.-]{0,40}
        \s*[:=]\s*["']([^"'\s]{12,})["']""", re.X)
PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxx|<.*>|\$\{|\{\{|dummy|sample|test")
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", ".idea", ".tox", ".mypy_cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".exe", ".dll", ".so", ".woff", ".woff2",
            ".ico", ".lock", ".pyc", ".mp4", ".mp3", ".jar", ".class"}
IGNORE_FILE = ".leakkillignore"


@dataclass
class Finding:
    path: str
    line: int
    kind: str
    secret: str          # raw value: kept in memory only, never printed
    commit: str = ""     # set for --history findings

    @property
    def masked(self):
        return mask(self.secret)

    @property
    def location(self):
        return f"{self.commit}:{self.path}:{self.line}" if self.commit else f"{self.path}:{self.line}"


def entropy(s):
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s)) if s else 0.0


def mask(s):
    if CRED_URL.match(s):  # keep scheme://user@host for context, hide the password
        return CRED_URL.sub(r"\1****\3", s)
    if s.startswith("https://"):  # webhooks: keep host, hide the path secret
        return re.sub(r"(https://[^/]+/).*", r"\1****", s)
    return s[:4] + "*" * min(len(s) - 4, 12) if len(s) > 8 else "****"


CRED_URL = re.compile(r"^([a-z][a-z0-9+]*://[^\s:/@]+:)([^\s:/@]+)(@.*)$")
FAKE_PASSWORDS = {"pass", "password", "passwd", "pwd", "pw", "secret", "foo", "bar", "baz", "test", "user", "username",
                  "admin", "root", "changeme", "xxx", "x", "p", "s"}
HASH_PREFIX = re.compile(r"^(pbkdf2_|argon2|bcrypt|\$2[aby]?\$|\$argon2|\$6\$|sha256\$|md5\$)")
TEST_NAME = re.compile(r"(?i)test|example|dummy|fake|mock|sample")


def real_url_password(url):
    pw = CRED_URL.match(url).group(2)
    words = [w for w in re.split(r"%[0-9a-fA-F]{2}|[^A-Za-z0-9]", pw) if w]
    return bool(words) and not PLACEHOLDER.search(url) and not re.search(r"[{}$<>*]", pw) \
        and not all(w.lower() in FAKE_PASSWORDS for w in words)


def scan_line(line):
    """Return [(kind, secret)] for one line."""
    if "leakkill:ignore" in line:
        return []
    hits = []
    for kind, rx in RULES.items():
        for m in rx.finditer(line):
            val = m.group(1) if rx.groups else m.group(0)
            if kind == "Credentials in URL" and not real_url_password(val):
                continue
            if not any(val in h[1] or h[1] in val for h in hits):
                hits.append((kind, val))
    for m in ASSIGN.finditer(line):
        v, name = m.group(1), m.group(0)[:m.start(1) - m.start(0)]
        if (PLACEHOLDER.search(v) or TEST_NAME.search(name) or HASH_PREFIX.match(v) or entropy(v) < 3.5
                or not re.search(r"\d", v) or not re.search(r"[A-Za-z]", v)):  # real random secrets mix letters+digits
            continue
        if not any(v in h[1] or h[1] in v for h in hits):
            hits.append(("High-entropy secret", v))
    return hits


def scan_text(text, path, commit=""):
    return [Finding(path, i, kind, val, commit)
            for i, line in enumerate(text.splitlines(), 1) for kind, val in scan_line(line)]


def load_ignores(root="."):
    try:
        with open(os.path.join(root, IGNORE_FILE), encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def ignored(path, patterns):
    p = path.replace("\\", "/").lstrip("./")
    return any(fnmatch.fnmatch(p, pat) or fnmatch.fnmatch(os.path.basename(p), pat) or p.startswith(pat.rstrip("/") + "/")
               for pat in patterns)


def iter_files(paths):
    for p in paths:
        if os.path.isfile(p):
            yield p
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for f in sorted(files):
                if os.path.splitext(f)[1].lower() not in SKIP_EXT:
                    yield os.path.join(root, f)


def scan_paths(paths):
    out = []
    for f in iter_files(paths):
        try:
            if os.path.getsize(f) > 2_000_000:
                continue
            with open(f, encoding="utf-8", errors="strict") as fh:
                out += scan_text(fh.read(), os.path.relpath(f))
        except (UnicodeDecodeError, OSError):
            continue  # binary / unreadable
    return out


def _git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


def _scan_diff(diff, commit_of_header=None):
    out, cur, commit, ln = [], "?", "", 0
    for line in diff.splitlines():
        if commit_of_header and line.startswith("commit "):
            commit = line.split()[1]
        elif line.startswith("+++ "):
            cur = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            ln = int(m.group(1)) if m else 0
        elif line.startswith("+"):
            out += [Finding(cur, ln, k, v, commit) for k, v in scan_line(line[1:])]
            ln += 1
    return out


def scan_staged():
    return _scan_diff(_git("diff", "--cached", "-U0", "--no-color"))


def scan_history():
    """Every line ever added in any commit on any branch (catches secrets that were 'deleted')."""
    return _scan_diff(_git("log", "-p", "--all", "-U0", "--no-color", "--format=commit %h"), commit_of_header=True)


def is_test_path(path):
    p = path.replace("\\", "/")
    return os.path.basename(p).startswith("test_") or "/tests/" in "/" + p or p.startswith("tests/")


def group(findings):
    """Group findings by unique secret, preserving first-seen order. Returns [(kind, secret, [Finding])]."""
    groups = {}
    for f in findings:
        groups.setdefault((f.kind, f.secret), []).append(f)
    return [(k, s, fs) for (k, s), fs in groups.items()]
