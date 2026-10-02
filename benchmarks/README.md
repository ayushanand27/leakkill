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
| **leakkill 0.5.0** | 0.834 | 0.251 | 0.386 | 0.785 |
| Gitleaks 8.28.0 | 0.860 | 0.453 | 0.594 | 0.835 |
| TruffleHog 3.97.9 | 0.579 | 0.024 | 0.045 | 0.421 |

**Without the OpenSSL test vectors.** 28% of CredData's "real credential" labels (4,416 lines) sit in five
OpenSSL test-vector files (`data/2ba83c6a/test/*.txt`: lines like `Key = 19fdafd8…` used to test
cryptography). These are public test data, not leaked secrets, and leakkill deliberately doesn't flag them.
Excluding those files:

| | precision | recall | F1 |
|---|---|---|---|
| **leakkill 0.5.0** | 0.893 | 0.217 | 0.349 |
| Gitleaks 8.28.0 | 0.910 | 0.218 | 0.351 |
| TruffleHog 3.97.9 | 0.486 | 0.026 | 0.049 |

Selected categories (recall, full dataset):

| | leakkill | Gitleaks | TruffleHog |
|---|---|---|---|
| Credentials in URLs | **182/209** | 0/209 | 59/209 |
| PEM private keys | 1160/1161 | 1161/1161 | 109/1161 |

**Reading this honestly:** on ordinary code leakkill detects about as well as Gitleaks, and it is far better at
passwords embedded in URLs. On the full dataset Gitleaks finds more, mostly because it reports crypto test
vectors. TruffleHog is built around live verification of specific services, so its detection-only recall here
is low by design. Recall is modest for all tools: CredData also labels plain passwords, UUIDs and nonces as
credentials, which pattern-based scanners mostly don't target.

The generic `name = value` rule was tuned using this dataset. To guard against tuning to the benchmark, every
change was also checked for new false positives on four clean repositories (requests, flask, django,
express), which stayed at 1 / 2 / 3 / 0.

### Reproduce

```sh
git clone https://github.com/Samsung/CredData && cd CredData && git checkout 0b1940e
pip install -r requirements.txt && python download_data.py --data_dir data   # ~12 GB download, 1 GB kept
leakkill scan --json data > leakkill.json
gitleaks dir data -f json -r gitleaks.json
trufflehog filesystem data --json --no-verification > trufflehog.json
python /path/to/leakkill/benchmarks/creddata_eval.py . leakkill leakkill.json   # likewise for the others
```
