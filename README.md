# secretscan

Zero-dependency Python tool that catches leaked credentials (AWS/GitHub/Slack/Stripe/OpenAI keys, JWTs,
private keys, DB URLs, high-entropy secrets) before they reach git.

```bash
python secretscan.py .             # scan a folder
python secretscan.py --staged      # scan staged changes only
python secretscan.py --install-hook  # block commits containing secrets
```
Suppress a line with `# secretscan:ignore`. Exits 1 when anything is found (CI-friendly). Output is masked.

Limits: scans current files/staged diffs, not git history; entropy rule can false-positive.
Run tests: `pip install pytest && pytest`.  License: MIT
