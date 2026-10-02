"""Find secrets in files, staged changes and git history. Never touches the network."""
import bisect, fnmatch, math, os, re, subprocess
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass

from . import gitleaks_rules

# kind -> regex. Group 1 (if present) is the secret, otherwise the whole match.
RULES = {
    "AWS access key":      re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    "AWS secret key":      re.compile(r"(?i)aws.{0,20}?(?:secret|sk).{0,20}?(?:[^\S\n]|[:=\"'])+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
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
# A rule's pattern only runs on text containing one of its keywords: a plain substring search, far cheaper
# than a regex. Keywords with uppercase letters are matched case-sensitively, others against lowercased text.
KEYWORDS = {
    "AWS access key": ["AKIA", "ASIA"], "AWS secret key": ["aws"],
    "GitHub token": ["ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"], "GitLab token": ["glpat-"],
    "Slack token": ["xox"], "Slack webhook": ["hooks.slack.com"], "Discord webhook": ["discord"],
    "Stripe key": ["k_live_", "k_test_"], "Anthropic API key": ["sk-ant-"], "OpenRouter key": ["sk-or-v1-"],
    "OpenAI API key": ["sk-"], "Hugging Face token": ["hf_"], "Groq key": ["gsk_"], "Replicate token": ["r8_"],
    "Perplexity key": ["pplx-"], "SendGrid key": ["SG."], "DigitalOcean token": ["dop_v1_", "doo_v1_"],
    "Shopify token": ["shpat_", "shpca_", "shppa_", "shpss_"], "PyPI token": ["pypi-AgEIcHlwaS5vcmc"],
    "Docker Hub token": ["dckr_pat_"], "Twilio API key": ["SK"], "Postman key": ["PMAK-"], "Linear key": ["lin_api_"],
    "Azure storage key": ["accountkey="], "npm token": ["npm_"], "Telegram bot token": [":AA"],
    "Google API key": ["AIza"], "Private key block": ["private key-----"], "JWT": ["eyJ"],
    "Credentials in URL": ["://"],
}
ASSIGN_KEYWORDS = ["secret", "token", "passw", "api_key", "api-key", "apikey", "private_key", "private-key",
                   "privatekey", "auth", "access_key", "access-key", "accesskey", "credential", "client_key",
                   "client-key"]


def _has_keyword(keywords, text, lower):
    return any((k in text) if k != k.lower() else (k in lower) for k in keywords)


# key = "value" where the key name looks sensitive and the value looks random. Found in two steps: a plain
# substring search for each keyword, then this short pattern anchored right after it. Every part is bounded or
# anchored, so matching stays linear even on huge (e.g. minified) lines.
# Covers `key = "v"`, `"key": "v"` (JSON), `'key' => 'v'` (PHP/Ruby) and unquoted `key: v` / `KEY=v` (YAML, .env).
# Every part has an upper bound (values up to 4096 chars), so each keyword hit costs a bounded amount of work and
# a hostile line like `secret=secret=secret=...` stays linear instead of quadratic.
ASSIGN_TAIL = re.compile(r"""[\w.-]{0,40}["']?[^\S\n]{0,100}(?:=>|[:=])[^\S\n]{0,100}"""
                         r"""(?:["'](?=([^"'\s]{12,4096}))\1["']|(?=([A-Za-z0-9+/=_\-.~]{12,4096}))\2(?=[\s,;]|$))""")
# `(?=(X))\1` is an atomic group: the value is taken greedily and never shortened again. Shortening could never
# succeed anyway (a value's characters and its terminators are disjoint), but trying it made hostile input slow.
ASSIGN_NAMES = ["secret", "token", "passwd", "password", "api_key", "api-key", "apikey", "private_key", "private-key",
                "privatekey", "auth", "access_key", "access-key", "accesskey", "credential", "client_key", "client-key"]
# Values shaped like code rather than secrets: `self.author_1`, `obj.pk`, `MY_CONSTANT_NAME`, `some_identifier`.
CODE_LIKE = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+|[a-z0-9]+(?:_[a-z0-9]+)+|[A-Z0-9]+(?:_[A-Z0-9]+)+")
IDENT = re.compile(r"[\w.-]{1,40}$")
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


def _assignments(text, lower):
    """Yield (start, value, name) for `name = "value"` where name contains a sensitive word."""
    found = {}
    for kw in ASSIGN_NAMES:
        i = lower.find(kw)
        skip_until = -1
        while i != -1:
            if i < skip_until:  # this keyword sits inside a value already matched: nothing new to find here
                i = lower.find(kw, skip_until)
                continue
            m = None if kw == "auth" and lower.startswith("or", i + 4) else ASSIGN_TAIL.match(text, i + len(kw))
            if m:  # (`auth` inside `author` / `authority` is not a credential name)
                g = 1 if m.group(1) is not None else 2
                value = m.group(g)
                skip_until = m.end(g)
                if m.start(g) not in found and not CODE_LIKE.fullmatch(value):
                    before = IDENT.search(text, max(0, i - 40), i)
                    found[m.start(g)] = (i, value, (before.group(0) if before else "") + text[i:m.start(g)])
            i = lower.find(kw, i + 1)
    return [found[k] for k in sorted(found)]


def _is_random_assignment(v, name):
    return not (PLACEHOLDER.search(v) or TEST_NAME.search(name) or HASH_PREFIX.match(v) or entropy(v) < 3.5
                or not re.search(r"\d", v) or not re.search(r"[A-Za-z]", v))  # real random secrets mix letters+digits


_GL = None


def _gitleaks():
    """Compile the imported Gitleaks rules on first use (keeps startup fast for the Claude Code guard)."""
    global _GL
    if _GL is None:
        rules = []
        for r in gitleaks_rules.RULES:
            rules.append(dict(r, rx=re.compile(r["regex"]), tail_rx=re.compile(r["tail"]) if "tail" in r else None,
                              path_rx=re.compile(r["path"]) if r["path"] else None,
                              allow_c=[(a.get("regexTarget", "secret"), [re.compile(x) for x in a["regexes"]],
                                        [re.compile(x) for x in a["paths"]], [w.lower() for w in a.get("stopwords", [])])
                                       for a in r["allow"]]))
        g = gitleaks_rules.ALLOW_GLOBAL
        _GL = (rules, [re.compile(x) for x in g["paths"]], [re.compile(x) for x in g["regexes"]], g["stopwords"])
    return _GL


def _first_group(m):
    return next((g for g in m.groups() if g), m.group(0))


def _gitleaks_matches(rule, text, lower):
    """Yield (start, secret, full_match) for one imported rule."""
    if rule["tail_rx"] is None:
        for m in rule["rx"].finditer(text):
            yield m.start(), _first_group(m), m.group(0)
        return
    seen = set()
    for name in rule["names"]:  # "<identifier containing name> = value": find the name, then anchor the rest
        i = lower.find(name)
        while i != -1:
            m = rule["tail_rx"].match(text, i + len(name))
            if m and m.start() not in seen:
                seen.add(m.start())
                yield i, _first_group(m), text[i:m.end()]
            i = lower.find(name, i + 1)


def _gitleaks_allowed(rule, secret, match, path, g_regexes, g_stopwords):
    low = secret.lower()
    if rule["entropy"] and entropy(secret) < rule["entropy"]:
        return True
    if any(rx.search(secret) for rx in g_regexes) or any(w in low for w in g_stopwords):
        return True
    for target, regexes, paths, stopwords in rule["allow_c"]:
        t = match if target == "match" else secret
        if any(rx.search(t) for rx in regexes) or (path and any(p.search(path) for p in paths)) \
                or any(w in low for w in stopwords):
            return True
    return False


def _scan(text, path=None):
    """Return {line_number: [(kind, secret)]}.

    Each pattern runs once over the whole text (fast, in C) instead of once per line; matches are then
    mapped back to line numbers. Patterns never cross a newline, so results equal a per-line scan.
    """
    lower = text.lower()
    rules = [(k, rx) for k, rx in RULES.items() if _has_keyword(KEYWORDS[k], text, lower)]
    assign = _has_keyword(ASSIGN_KEYWORDS, text, lower)
    gl_rules, g_paths, g_regexes, g_stopwords = _gitleaks()
    if path and any(p.search(path.replace("\\", "/")) for p in g_paths):
        gl_rules = []  # e.g. lockfiles and vendored assets, per Gitleaks' global allowlist
    present = {}

    def has(kw):
        if kw not in present:
            present[kw] = kw in lower
        return present[kw]

    gl_rules = [r for r in gl_rules if (not r["path_rx"] or (path and r["path_rx"].search(path)))
                and any(has(k) for k in r["keywords"])]
    if not rules and not assign and not gl_rules:
        return {}
    starts = [0] + [m.end() for m in re.finditer("\n", text)]
    raw = {}
    for kind, rx in rules:
        for m in rx.finditer(text):
            val = m.group(1) if rx.groups else m.group(0)
            if kind == "Credentials in URL" and not real_url_password(val):
                continue
            raw.setdefault(bisect.bisect_right(starts, m.start()), []).append((kind, val))
    for rule in gl_rules:  # after leakkill's own rules, so verifiable kinds win when both match
        for pos, secret, match in _gitleaks_matches(rule, text, lower):
            if not _gitleaks_allowed(rule, secret, match, path, g_regexes, g_stopwords):
                raw.setdefault(bisect.bisect_right(starts, pos), []).append((rule["kind"], secret))
    for pos, value, name in (_assignments(text, lower) if assign else ()):
        if _is_random_assignment(value, name):
            raw.setdefault(bisect.bisect_right(starts, pos), []).append(("High-entropy secret", value))
    out = {}
    for ln in sorted(raw):
        end = starts[ln] if ln < len(starts) else len(text)
        if "leakkill:ignore" in text[starts[ln - 1]:end]:
            continue
        hits = []
        for kind, val in raw[ln]:  # rule order first, then position: a specific rule beats a generic one
            if not any(val in h[1] or h[1] in val for h in hits):
                hits.append((kind, val))
        out[ln] = hits
    return out


def scan_line(line):
    """Return [(kind, secret)] for one line."""
    return _scan(line).get(1, [])


def scan_text(text, path, commit=""):
    return [Finding(path, ln, kind, val, commit) for ln, hits in _scan(text, path).items() for kind, val in hits]


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


def _scan_file(f):
    try:
        if os.path.getsize(f) > 2_000_000:
            return []
        with open(f, encoding="utf-8", errors="strict") as fh:
            return scan_text(fh.read(), os.path.relpath(f))
    except (UnicodeDecodeError, OSError):
        return []  # binary / unreadable


def _parallel(fn, items, jobs=None):
    """map fn over items, across CPU cores when there are many items; results keep their order."""
    jobs = jobs or int(os.environ.get("LEAKKILL_JOBS", 0)) or os.cpu_count() or 1
    if jobs > 1 and len(items) >= 200:
        try:
            with ProcessPoolExecutor(jobs) as ex:
                return [f for found in ex.map(fn, items, chunksize=32) for f in found]
        except (OSError, RuntimeError, ImportError):
            pass  # no multiprocessing here (some sandboxes): fall back to one process
    return [f for item in items for f in fn(item)]


def scan_paths(paths, jobs=None):
    """Scan files, in parallel across CPU cores when there are many of them."""
    return _parallel(_scan_file, list(iter_files(paths)), jobs)


def _git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace").stdout


def _scan_batch(batch):
    path, commit, text, numbers = batch
    return [Finding(path, numbers[i - 1], k, v, commit) for i, hits in _scan(text, path).items() for k, v in hits]


def _scan_diff(diff, commit_of_header=None, jobs=None):
    """Scan the added lines of a diff. Lines are batched per file and commit, so each pattern runs once per
    batch, and batches are spread across CPU cores when there are many (e.g. a long --history)."""
    batches, cur, commit, ln = [], "?", "", 0
    added, numbers = [], []

    def flush():
        if added:
            batches.append((cur, commit, "\n".join(added), list(numbers)))
            added.clear()
            numbers.clear()

    for line in diff.split("\n"):
        if commit_of_header and line.startswith("commit "):
            flush()
            commit = line.split()[1]
        elif line.startswith("+++ "):
            flush()
            cur = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            ln = int(m.group(1)) if m else 0
        elif line.startswith("+"):
            added.append(line[1:])
            numbers.append(ln)
            ln += 1
    flush()
    return _parallel(_scan_batch, batches, jobs)


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
