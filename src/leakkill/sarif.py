"""SARIF 2.1.0 output, the format GitHub code scanning (the Security tab) and other tools read."""
import hashlib, json, re

from . import __version__
from .providers import LIVE, provider

INFO_URI = "https://github.com/ayushanand27/leakkill"


def rule_id(kind):
    return "leakkill/" + re.sub(r"[^a-z0-9]+", "-", kind.lower()).strip("-")


def fingerprint(item):
    # A stable id for the same secret across runs. A plain hash is fine here (unlike baselines, SARIF files are
    # usually uploaded, not committed), and it is truncated so it can't be used to confirm a guessed secret.
    return hashlib.sha256(f"{item.kind}\0{item.secret}".encode()).hexdigest()[:16]


def render(items):
    kinds = list(dict.fromkeys(it.kind for it in items))
    rules = [{
        "id": rule_id(k), "name": re.sub(r"[^A-Za-z0-9]", "", k.title()),
        "shortDescription": {"text": f"{k} committed to the repository"},
        "fullDescription": {"text": f"A {k} was found in the code. Anyone with read access to the repository "
                                    "(or a leaked clone) can use it."},
        "help": {"text": provider(k).manual, "markdown": provider(k).manual},
        "helpUri": INFO_URI,
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", "secret", "credential"], "security-severity": "9.0",
                       "precision": "high"},
    } for k in kinds]
    results = []
    for it in items:
        status = it.result.status if it.result else None
        msg = f"{it.kind} ({it.findings[0].masked})" + (f": {status}" if status else "")
        if status == LIVE:
            msg += f" - the key works right now{' (' + it.result.identity + ')' if it.result.identity else ''}; revoke it first."
        for f in it.findings:
            loc = {"physicalLocation": {"artifactLocation": {"uri": f.path.replace("\\", "/").lstrip("./") or f.path},
                                        "region": {"startLine": max(f.line, 1)}}}
            result = {"ruleId": rule_id(it.kind), "ruleIndex": kinds.index(it.kind), "level": "error",
                      "message": {"text": msg + (f" (added in commit {f.commit})" if f.commit else "")},
                      "locations": [loc], "partialFingerprints": {"secretHash/v1": fingerprint(it)}}
            if status:
                result["properties"] = {"status": status}
            results.append(result)
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "leakkill", "version": __version__, "semanticVersion": __version__,
                                      "informationUri": INFO_URI, "rules": rules}},
                  "results": results}],
    }, indent=2)
