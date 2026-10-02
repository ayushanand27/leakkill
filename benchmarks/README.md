# Benchmarks

## Accuracy: Samsung CredData

[CredData](https://github.com/Samsung/CredData) (commit `0b1940e`) is a public dataset of code from 337 open-source
repositories in which 67,896 suspicious lines were labeled by people: 15,753 real credentials (`T`) and
52,143 lines that look like credentials but aren't (`F`/`X`).

Every tool is scored by the same script, [`creddata_eval.py`](creddata_eval.py), at line level:
a reported line is a true positive if it holds a labeled real credential and a false positive if it is labeled
not-a-credential. Lines without any label are excluded from precision (and counted as false positives in the
"worst case" column). Recall is the share of labeled real credentials found. All tools run with default
settings; TruffleHog with `--no-verification`, so all three are measured on detection alone.

| October 2026 | precision | recall | F1 | precision, worst case |
|---|---|---|---|---|
| **leakkill 0.6.1** | 0.825 | 0.510 | **0.630** | 0.805 |
| leakkill 0.5.0 | 0.834 | 0.251 | 0.386 | 0.785 |
| Betterleaks 1.9.0 | 0.712 | **0.562** | 0.628 | 0.688 |
| Kingfisher 2.9.0 (`--no-validate --no-dedup`) | 0.961 | 0.104 | 0.187 | 0.948 |
| Gitleaks 8.28.0 | 0.860 | 0.453 | 0.594 | 0.835 |
| TruffleHog 3.97.9 | 0.579 | 0.024 | 0.045 | 0.421 |

**Without the OpenSSL test vectors.** 28% of CredData's "real credential" labels (4,416 lines) sit in five
OpenSSL test-vector files (`data/2ba83c6a/test/*.txt`: lines like `Key = 19fdafd8…` used to test
cryptography). These are public test data, not leaked secrets. Since 0.6 leakkill flags most of them too (a
pattern scanner can't tell a test vector from a real `key = ...`), which inflates its full-dataset recall, so
**this is the table to compare on**. Excluding those files:

| | precision | recall | F1 |
|---|---|---|---|
| **leakkill 0.6.1** | 0.922 | 0.300 | 0.453 |
| leakkill 0.5.0 | 0.893 | 0.217 | 0.349 |
| Betterleaks 1.9.0 | 0.585 | **0.379** | **0.460** |
| Kingfisher 2.9.0 | 0.925 | 0.079 | 0.145 |
| Gitleaks 8.28.0 | 0.910 | 0.218 | 0.351 |
| TruffleHog 3.97.9 | 0.486 | 0.026 | 0.049 |

Selected categories (recall, full dataset):

| | leakkill | Betterleaks | Kingfisher | Gitleaks | TruffleHog |
|---|---|---|---|---|---|
| Credentials in URLs | **182/209** | 96/209 | 20/209 | 0/209 | 59/209 |
| HTTP Basic auth (`Authorization: Basic …`) | **601/601** | 10/601 | 5/601 | 0/601 | 0/601 |

**Reading this honestly:** on real code (the second table) leakkill 0.6 has the best precision of the
tools that find a meaningful share of credentials, and Betterleaks still finds the most (recall 0.379 vs
0.300), at the cost of many more false alarms; on F1 the two are level. Kingfisher has the fewest false alarms but
finds far fewer. leakkill is far ahead on passwords in URLs and HTTP Basic auth headers, because it decodes and
checks them instead of matching shapes. TruffleHog is built around live verification of specific services, so
its detection-only recall here is low by design. Recall is modest for all tools: CredData also labels plain
passwords, UUIDs and nonces as credentials, which pattern-based scanners mostly don't target (leakkill finds
186 of 2,530 plain passwords; Betterleaks' generic password rule finds more but has more false alarms than hits).

**Where 0.6's gain came from.** We measured where Betterleaks' extra recall comes from before copying anything:
one rule, `generic-api-key`, accounts for almost all of it, and 90% of that is OpenSSL test vectors. Its other
462 rules together add under 100 lines here, so we did not import them. Instead leakkill 0.6 adds two rules:
a bare `key` name (`key = "..."`, `"Key": "..."`, `nkey`, `hexkey`) restricted to token-shaped values, and
HTTP Basic auth, which is only reported when the base64 decodes to a real-looking `user:password`.

**Tuning caveat.** The generic rules were tuned using this dataset's false positives (struct tags, ARNs,
k8s labels, XAML keys...), so leakkill's numbers here are somewhat flattering compared to tools that weren't
tuned on it. As an independent check, every change was also run on four clean repositories (requests,
flask, django, express), where false alarms stayed at 1 / 2 / 3 / 0.

### Reproduce

```sh
git clone https://github.com/Samsung/CredData && cd CredData && git checkout 0b1940e
pip install -r requirements.txt && python download_data.py --data_dir data   # ~12 GB download, 1 GB kept
leakkill scan --json data > leakkill.json
gitleaks dir data -f json -r gitleaks.json
betterleaks dir data -f json -r betterleaks.json
kingfisher scan data --no-validate --no-dedup -f json -o kingfisher.json
trufflehog filesystem data --json --no-verification > trufflehog.json
python /path/to/leakkill/benchmarks/creddata_eval.py . leakkill leakkill.json   # likewise for the others
```
