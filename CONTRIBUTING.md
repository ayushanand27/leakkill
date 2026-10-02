# Contributing to leakkill

Thanks for helping! Bug reports, false positives/negatives, new provider rules and docs fixes are all welcome.

## Reporting

- Bugs, false positives and missed secrets: open a [GitHub issue](https://github.com/ayushanand27/leakkill/issues).
  Include the leakkill version (`leakkill --version`), your OS and a **fake** example of the text involved.
  Never paste a real key, even a revoked one.
- Security vulnerabilities: report privately as described in [SECURITY.md](SECURITY.md), not in an issue.

## Making a change

1. Fork, then create a branch from `main`.
2. `pip install -e . pytest hypothesis` and make your change.
3. **Every new feature or bug fix comes with a test** in `tests/` that fails without it. Detection changes
   also need a "should not match" test for the false positives you thought about.
4. Run `pytest -q` (all tests must pass on Python 3.9+) and `leakkill scan --exclude-tests .` (must be clean).
5. Open a pull request. CI runs the tests on Linux, macOS and Windows, a coverage gate, CodeQL, SonarCloud,
   workflow linting and a fuzzer; all must pass before merging.

Rules imported from Gitleaks are generated: change `tools/import_gitleaks.py`, never `gitleaks_rules.py` by hand.
Accuracy claims in the README must come from `benchmarks/creddata_eval.py`, re-run on your change.

## Style

Match the surrounding code: standard library only (leakkill has no runtime dependencies), short functions,
comments that explain why. By contributing you agree your work is released under the MIT license.
