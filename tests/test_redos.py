"""Every rule must stay fast on hostile input built from its own keywords.

Gitleaks' patterns were written for Go's linear-time RE2 engine; Python's engine backtracks, so a translated
pattern can be catastrophically slow on the same input. tools/import_gitleaks.py hardens such patterns; this
test makes sure no rule (imported or own) regresses.
"""
import time

from leakkill import scanner

SHAPES = ["", "=", " = '", "_", "a1", ":", ".", " ", "-"]


def _worst(fn, keywords):
    worst = 0.0
    for kw in keywords[:3]:
        for tail in SHAPES:
            unit = kw + tail
            text = unit * max(1, 8_000 // len(unit))
            t = time.perf_counter()
            fn(text)
            worst = max(worst, time.perf_counter() - t)
    return worst


def test_imported_rules_are_linear_on_hostile_input():
    slow = []
    for r in scanner._gitleaks()[0]:
        t = _worst(lambda text: list(scanner._gitleaks_matches(r, text, text.lower())), r["keywords"])
        if t > 0.5:  # healthy rules take ~1 ms here; catastrophic ones took > 3 s
            slow.append((r["id"], round(t, 2)))
    assert not slow, slow


def test_own_rules_are_linear_on_hostile_input():
    for kind, kws in list(scanner.KEYWORDS.items()) + [("assignment", scanner.ASSIGN_NAMES)]:
        assert _worst(lambda text: scanner.scan_text(text, "f.txt"), kws) < 1.5, kind
