"""Baselines: accept the secrets you already know about and only fail on new ones.

The file never contains secrets, only salted scrypt hashes. scrypt is deliberately slow, so even a weak password
in a committed baseline can't practically be brute-forced back out of it.
"""
import hashlib, json, os

VERSION = 1
N, R, P = 2 ** 13, 8, 1  # scrypt cost: tens of ms per hash, fine for the handful of entries a baseline holds


def _hash(kind, secret, salt):
    return hashlib.scrypt(f"{kind}\0{secret}".encode(), salt=bytes.fromhex(salt), n=N, r=R, p=P, dklen=32).hex()


def write(items, path):
    salt = os.urandom(16).hex()
    entries = sorted({_hash(it.kind, it.secret, salt) for it in items})
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"leakkill_baseline": VERSION, "salt": salt, "entries": entries}, f, indent=2)
        f.write("\n")
    return len(entries)


def load(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if data.get("leakkill_baseline") != VERSION:
        raise ValueError(f"{path} is not a leakkill baseline (version {VERSION})")
    return data["salt"], set(data["entries"])


def filter_new(items, path):
    """Drop items whose secret is in the baseline; returns (new_items, number_suppressed)."""
    salt, known = load(path)
    new = [it for it in items if _hash(it.kind, it.secret, salt) not in known]
    return new, len(items) - len(new)
