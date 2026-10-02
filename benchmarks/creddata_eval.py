"""Score secret scanners against Samsung CredData's human labels, the same way for every tool.

    python benchmarks/creddata_eval.py CREDDATA_DIR TOOL FINDINGS_FILE

FINDINGS_FILE is a tool's native JSON output (leakkill --json, gitleaks/betterleaks -f json,
trufflehog --json, kingfisher -f json --no-dedup).
A finding is matched by file and line:
  - TP: the line holds a credential labeled real (T)
  - FP: the line is labeled not-a-credential (F or X, as CredData defines)
  - unlabeled: the line has no label at all; reported separately, and as a worst case also counted as FP
Recall = labeled-real credentials hit / all labeled-real credentials. Each line counts once per tool, so a
tool that reports the same line several times is neither rewarded nor penalized for it.
"""
import collections, csv, glob, json, os, sys


def load_labels(cred_dir):
    rows = collections.defaultdict(list)  # path -> [(start, end, label, category)]
    for f in glob.glob(os.path.join(cred_dir, "meta", "*.csv")):
        with open(f, encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                rows[r["FilePath"]].append((int(r["LineStart"]), int(r["LineEnd"]), r["GroundTruth"], r["Category"]))
    return rows


def norm(path):
    path = path.replace("\\", "/")
    return path[path.index("data/"):] if "data/" in path else path


def findings(tool, file):
    if tool == "leakkill":
        for item in json.load(open(file)):
            for loc in item["locations"]:
                path, line = loc.rsplit(":", 1)
                yield norm(path), int(line)
    elif tool == "kingfisher":
        for f in json.load(open(file))["findings"]:
            yield norm(f["finding"]["path"]), int(f["finding"]["line"])
    elif tool in ("gitleaks", "betterleaks"):  # Betterleaks keeps the Gitleaks report format
        for f in json.load(open(file)):
            yield norm(f["File"]), int(f["StartLine"])
    elif tool == "trufflehog":
        for raw in open(file):
            if raw.strip().startswith("{"):
                d = json.loads(raw)
                fs = d.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                if fs:
                    yield norm(fs["file"]), int(fs.get("line", 0))
    else:
        raise SystemExit(f"unknown tool {tool}")


def score(labels, hits):
    tp = fp = unlabeled = 0
    found_true = set()
    for path, line in set(hits):
        covering = [(s, e, gt, cat) for s, e, gt, cat in labels.get(path, []) if s <= line <= e]
        trues = [(path, s, e, cat) for s, e, gt, cat in covering if gt == "T"]
        if trues:
            tp += 1
            found_true.update(trues)
        elif covering:
            fp += 1
        else:
            unlabeled += 1
    all_true = {(p, s, e, cat) for p, rs in labels.items() for s, e, gt, cat in rs if gt == "T"}
    by_cat = collections.Counter(cat for _, _, _, cat in all_true)
    hit_cat = collections.Counter(cat for _, _, _, cat in found_true)
    precision = tp / (tp + fp) if tp + fp else 0.0
    worst = tp / (tp + fp + unlabeled) if tp + fp + unlabeled else 0.0
    recall = len(found_true) / len(all_true)
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"reported_lines": tp + fp + unlabeled, "tp": tp, "fp": fp, "unlabeled": unlabeled,
            "true_found": len(found_true), "true_total": len(all_true), "precision": round(precision, 3),
            "precision_worst_case": round(worst, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "recall_by_category": {c: f"{hit_cat[c]}/{n}" for c, n in by_cat.most_common(14)}}


if __name__ == "__main__":
    cred_dir, tool, file = sys.argv[1:4]
    print(json.dumps({"tool": tool, **score(load_labels(cred_dir), list(findings(tool, file)))}, indent=2))
