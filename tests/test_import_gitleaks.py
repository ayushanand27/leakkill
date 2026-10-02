import importlib.util, pathlib, re

spec = importlib.util.spec_from_file_location("imp", pathlib.Path(__file__).parent.parent / "tools" / "import_gitleaks.py")
imp = importlib.util.module_from_spec(spec); spec.loader.exec_module(imp)


def same(go_rx, py_rx, yes, no):
    rx = re.compile(py_rx)
    assert all(rx.fullmatch(s) for s in yes), [s for s in yes if not rx.fullmatch(s)]
    assert not any(rx.fullmatch(s) for s in no), [s for s in no if rx.fullmatch(s)]


def test_mid_pattern_flag_scoped_to_rest_of_group():
    py = imp.translate(r"\b(p8e-(?i)[a-z0-9]{4})")
    assert py == r"\b(p8e-(?i:[a-z0-9]{4}))"
    same(None, py, ["p8e-AbC1", "p8e-abcd"], ["P8E-abcd"])  # flag applies after it, not before


def test_mid_pattern_flag_carries_into_later_alternatives():
    py = imp.translate(r"x(?:a(?i)b|c)")
    same(None, py, ["xab", "xaB", "xc", "xC"], ["xAb"])


def test_backslash_z_and_char_classes():
    assert imp.translate(r"foo\z") == r"foo\Z"
    assert imp.translate(r"[(?i)]x(?i)y") == r"[(?i)]x(?i:y)"  # inside a class it's literal


def test_humanize():
    assert imp.humanize("alibaba-access-key-id") == "Alibaba access key ID"
    assert imp.humanize("github-pat") == "GitHub PAT"
