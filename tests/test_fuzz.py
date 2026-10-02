"""Property-based fuzz tests: random and adversarial inputs, checked against rules that must always hold.

Seeded, so failures reproduce. Run longer locally with LEAKKILL_FUZZ_ITERS=20000.
"""
import json, os, random, string

from leakkill import guard, scanner
from leakkill.scanner import RULES, scan_line, scan_text

ITERS = int(os.environ.get("LEAKKILL_FUZZ_ITERS", "600"))
ALPHABET = string.printable + "äöü€漢字​ \x00\x0b\x0c\x1c\x85"
TOKENS = {  # one realistic-shaped value per own provider rule
    "GitHub token": "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
    "GitLab token": "glpat-" + "x1Y2z3A4b5C6d7E8f9G0",
    "Slack token": "xox" + "b-1234567890-abcdefghijKLMN",  # split so the literal never trips push protection
    "Stripe key": "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
    "Anthropic API key": "sk-ant-api03-" + "A1b2" * 22,
    "npm token": "npm_" + "a1B2c3D4e5" * 3 + "a1B2c3",
    "Google API key": "AIza" + "B1c2D3e4F5" * 3 + "g6H7i",
    "Hugging Face token": "hf_" + "Ab1Cd2Ef3Gh4" * 3,
    "DigitalOcean token": "dop_v1_" + "a1b2c3d4" * 8,
}
OWN = set(RULES) | {"High-entropy secret"}


def rand_text(rng, n):
    return "".join(rng.choice(ALPHABET) for _ in range(n))


def test_never_crashes_on_random_text():
    rng = random.Random(1)
    for _ in range(ITERS):
        scan_text(rand_text(rng, rng.randint(0, 400)), "f.txt")


def test_masked_output_never_reveals_the_secret():
    rng = random.Random(2)
    for _ in range(ITERS):
        kind, tok = rng.choice(list(TOKENS.items()))
        text = rand_text(rng, rng.randint(0, 60)) + " " + tok + " " + rand_text(rng, rng.randint(0, 60))
        for f in scan_text(text, "f.txt"):
            assert f.secret not in f.masked or len(f.secret) <= 8, (f.kind, f.masked)


def test_planted_token_found_in_any_context():
    rng = random.Random(3)
    sep = [" ", "\t", '"', "'", "=", ":", "(", ",", "\n", "`"]
    for _ in range(ITERS):
        kind, tok = rng.choice(list(TOKENS.items()))
        text = rand_text(rng, rng.randint(0, 80)) + rng.choice(sep) + tok + rng.choice(sep) + rand_text(rng, rng.randint(0, 80))
        if "leakkill:ignore" in text:
            continue
        assert any(f.secret == tok for f in scan_text(text, "f.txt")), (kind, repr(text))


def test_whole_file_scan_equals_line_by_line_scan():
    """The fast whole-file matcher must report exactly what scanning each line on its own reports."""
    rng = random.Random(4)
    pieces = list(TOKENS.values()) + ['api_key = "q8Zx3Lm9Vb2Nc7Rt5Yw1Hk4"', "postgres://app:S3cr3tPw9@db.x", "leakkill:ignore"]
    for _ in range(ITERS // 3):
        lines = []
        for _ in range(rng.randint(1, 12)):
            parts = [rand_text(rng, rng.randint(0, 20)).replace("\n", " ").replace("\r", " ") for _ in range(2)]
            lines.append(parts[0] + (rng.choice(pieces) if rng.random() < 0.6 else "") + parts[1])
        text = "\n".join(lines)
        whole = {(f.line, f.kind, f.secret) for f in scan_text(text, "f.txt") if f.kind in OWN}
        per_line = {(i, k, v) for i, line in enumerate(lines, 1) for k, v in scan_line(line) if k in OWN}
        assert whole == per_line, repr(text)


def test_huge_and_pathological_inputs_finish():
    rng = random.Random(5)
    for unit in ["secret=", '"token": "', "auth", "eyJ" * 5, "://a:b@", "=" * 7, "AKIA", "sk-", "ghp_"]:
        scan_text(unit * 40_000 + rand_text(rng, 100), "f.txt")


def test_guard_never_crashes_on_random_events():
    rng = random.Random(6)
    tools = ["Read", "Write", "Edit", "Bash", "NotebookEdit", "Unknown", None, 5]
    for _ in range(ITERS):
        ev = {"hook_event_name": rng.choice(["PreToolUse", "UserPromptSubmit", "Other", None]),
              "tool_name": rng.choice(tools),
              "tool_input": rng.choice([None, {}, {"file_path": rand_text(rng, 30)}, {"command": rand_text(rng, 50)},
                                        {"content": rand_text(rng, 80), "nested": [{"x": rand_text(rng, 20)}]}]),
              "prompt": rand_text(rng, 100)}
        guard.guard_check(ev)
        assert guard.guard(json.dumps(ev)) in (0, 2)
    for junk in ["", "{", "null", "[]", "\x00", "{" * 1000]:
        assert guard.guard(junk) == 0 or guard.guard(junk) == 2
