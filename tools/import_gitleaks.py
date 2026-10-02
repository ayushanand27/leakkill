"""Generate src/leakkill/gitleaks_rules.py from Gitleaks' rule file (MIT licensed, credited in the output).

    python tools/import_gitleaks.py

The source is pinned to a release and checked against a SHA-256, so the generated rules are reproducible.
Go (RE2) regex syntax is translated to Python; rules that can't be translated are listed, never silently dropped.
"""
import hashlib, pprint, re, sys, urllib.request

VERSION = "v8.28.0"
URL = f"https://raw.githubusercontent.com/gitleaks/gitleaks/{VERSION}/config/gitleaks.toml"
SHA256 = "c3bee40d87bb4689e3f5ffa5cc0315f7e6e4d43f4e9388397fca59f29407b432"
OUT = "src/leakkill/gitleaks_rules.py"
# generic-api-key: leakkill has its own, quieter generic rule. pkcs12-file: file-name only, no content pattern.
# kubernetes-secret-yaml: its allowlist relies on multi-document YAML matching that doesn't translate cleanly.
SKIP = {"generic-api-key", "pkcs12-file", "kubernetes-secret-yaml"}
TEMPLATE = re.compile(r"^\(\?i\)\[\\w\.-\]\{0,50\}\?\(\?:([A-Za-z0-9_|-]+)\)")


def scope_inline_flags(rx):
    """RE2 allows `(?i)` mid-pattern: it applies to the rest of the enclosing group, including later
    `|` alternatives. Python needs scoped groups, so `a(?i)b|c` becomes `a(?i:b)|(?i:c)`."""
    out, i, in_class = [], 0, False
    stack = [[]]  # per open group: flags whose scoped groups are currently open
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            out.append(rx[i:i + 2]); i += 2; continue
        if in_class:
            in_class = c != "]"; out.append(c); i += 1; continue
        if c == "[":
            in_class = True; out.append(c); i += 1
            if i < len(rx) and rx[i] == "]":  # a literal ] right after [
                out.append("]"); i += 1
            continue
        m = re.match(r"\(\?([a-zA-Z]+)\)", rx[i:])
        if m and i > 0:
            out.append(f"(?{m.group(1)}:"); stack[-1].append(m.group(1)); i += m.end(); continue
        if c == "(":
            stack.append([]); out.append(c); i += 1; continue
        if c == ")":
            out.append(")" * len(stack.pop()) + ")"); i += 1; continue
        if c == "|":
            flags = stack[-1]
            out.append(")" * len(flags) + "|" + "".join(f"(?{f}:" for f in flags)); i += 1; continue
        out.append(c); i += 1
    return "".join(out) + ")" * len(stack[0])


def translate(rx):
    return scope_inline_flags(rx.replace(r"\z", r"\Z"))


# Go's RE2 engine runs any pattern in linear time; Python's backtracking engine does not. These rewrites keep
# what a rule detects but remove the shapes that make Python backtrack catastrophically on hostile input.
NAME_PREFIX = r"[\w.-]{0,50}?"
CURL_SPANS = [r"(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})", r"(?:.*|.*(?:[\r\n]{1,2}.*){1,5})"]
CURL_SPAN_LINEAR = r"[^\r\n]{0,300}?(?:[\r\n]{1,2}[^\r\n]{0,300}?){0,5}"  # same idea: up to 5 more lines


def harden(rx):
    """Drop leading optional name prefixes (they can always match nothing, so which secret is found doesn't change;
    stacked ones like `[\w.-]{0,50}?(?i:[\w.-]{0,50}?...` are quadratic in Python), and bound curl's multi-line
    spans so each line split is forced instead of searched."""
    changed = True
    while changed:
        changed = False
        for lead in ("", "(?i:", "(?i)"):
            if rx.startswith(lead + NAME_PREFIX):
                rx = lead + rx[len(lead + NAME_PREFIX):]
                changed = True
    for span in CURL_SPANS:
        rx = rx.replace(span, CURL_SPAN_LINEAR)
    return rx


def humanize(rule_id):
    fixes = {"api": "API", "aws": "AWS", "pat": "PAT", "jwt": "JWT", "id": "ID", "oauth": "OAuth", "url": "URL",
             "github": "GitHub", "gitlab": "GitLab", "gcp": "GCP", "sso": "SSO", "ssh": "SSH", "sdk": "SDK"}
    words = [fixes.get(w, w) for w in rule_id.split("-")]
    return " ".join([words[0][:1].upper() + words[0][1:]] + words[1:])


def compiles(rx):
    try:
        re.compile(rx)
        return True
    except re.error:
        return False


def main():
    import tomllib  # Python 3.11+, only needed to regenerate the rules (translation helpers work on 3.9)

    raw = urllib.request.urlopen(URL, timeout=60).read()
    got = hashlib.sha256(raw).hexdigest()
    if got != SHA256:
        sys.exit(f"checksum mismatch: {got}")
    cfg = tomllib.loads(raw.decode())
    rules, failed = [], []
    for r in cfg["rules"]:
        if r["id"] in SKIP or "regex" not in r:
            continue
        rx = translate(r["regex"])
        allow = [dict(a) for a in r.get("allowlists", [])]
        for a in allow:
            a.pop("description", None)
            a["regexes"] = [translate(x) for x in a.get("regexes", [])]
            a["paths"] = [translate(x) for x in a.get("paths", [])]
        if not compiles(rx) or not all(compiles(x) for a in allow for x in a["regexes"] + a["paths"]):
            failed.append(r["id"])
            continue
        rule = {"id": r["id"], "kind": humanize(r["id"]), "regex": rx, "keywords": [k.lower() for k in r["keywords"]],
                "entropy": r.get("entropy", 0), "path": translate(r["path"]) if "path" in r else None, "allow": allow}
        m = TEMPLATE.match(rx)
        if m:  # "<name containing keyword> = value": searched via the keyword, then the tail is anchored after it
            rule["names"] = [n.lower() for n in m.group(1).split("|")]
            rule["tail"] = "(?i)" + rx[m.end():]
            assert compiles(rule["tail"]), r["id"]
        else:
            rule["regex"] = harden(rx)
            assert compiles(rule["regex"]), r["id"]
        rules.append(rule)
    g = cfg["allowlist"]
    allow_global = {"paths": [translate(x) for x in g.get("paths", [])],
                    "regexes": [translate(x) for x in g.get("regexes", [])],
                    "stopwords": [s.lower() for s in g.get("stopwords", [])]}
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(f'''"""GENERATED by tools/import_gitleaks.py from Gitleaks {VERSION} config/gitleaks.toml (sha256 {SHA256[:16]}...).

Do not edit by hand. Rules are translated from Go (RE2) to Python regex syntax.

Gitleaks is MIT licensed:
{open_license()}"""
# flake8: noqa
# {len(rules)} rules imported; {len(SKIP)} skipped on purpose ({", ".join(sorted(SKIP))}); {len(failed)} not translatable: {failed}

RULES = {pprint.pformat(rules, width=120, sort_dicts=False)}

ALLOW_GLOBAL = {pprint.pformat(allow_global, width=120)}
''')
    print(f"{len(rules)} rules written to {OUT}; skipped {sorted(SKIP)}; untranslatable: {failed}")


def open_license():
    lic = urllib.request.urlopen(f"https://raw.githubusercontent.com/gitleaks/gitleaks/{VERSION}/LICENSE", timeout=60)
    return lic.read().decode().strip()


if __name__ == "__main__":
    main()
