"""`leakkill scan https://github.com/owner/repo`: clone read-only into a temp folder, scan it, delete it.

For checking a repository before you trust it. Cloning untrusted code is the risky part, so:
- only https:// and ssh-style URLs are accepted (git's `ext::` and `file:` transports can run commands or read
  local files), and the URL goes after `--` so it can never be taken for an option;
- git never asks for a password (GIT_TERMINAL_PROMPT=0), never fetches submodules, and runs with the same
  hardening as every other leakkill git call (no repository-configured programs);
- the clone is deleted afterwards, even when the scan fails.
"""
import contextlib, os, re, shutil, stat, subprocess, tempfile

URL = re.compile(r"^(?:https://[^\s/]+/\S+|ssh://\S+|[\w.-]+@[\w.-]+:\S+)$")
SHORT = re.compile(r"^(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org)/[\w.-]+/[\w.-]+$")


def parse(arg):
    """A clone URL for `arg` if it is one (or looks like github.com/owner/repo), else None (a local path)."""
    if not isinstance(arg, str) or arg.startswith("-") or any(c.isspace() for c in arg) or os.path.exists(arg):
        return None
    if SHORT.match(arg):
        return "https://" + arg
    return arg if URL.match(arg) and not arg.lower().startswith(("ext::", "file:")) else None


def safe_url(url):
    """The URL with any `user:password@` removed, for messages."""
    return re.sub(r"//[^/@\s]*@", "//", url)


def _clone(url, dest, full_history):
    from .scanner import run_git
    depth = [] if full_history else ["--depth", "1"]
    r = run_git("-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
                "clone", "--quiet", "--no-tags", "--no-recurse-submodules", *depth, "--", url, dest,
                text=True, timeout=600, env_extra={"GIT_TERMINAL_PROMPT": "0"})
    if r.returncode:
        raise RuntimeError((r.stderr or "git clone failed").strip().splitlines()[-1][:300])


def _writable(func, path, _exc):  # Windows keeps .git objects read-only
    os.chmod(path, stat.S_IWRITE)
    func(path)


@contextlib.contextmanager
def checkout(url, full_history=False, clone=_clone):
    work = tempfile.mkdtemp(prefix="leakkill-")
    try:
        clone(url, os.path.join(work, "repo"), full_history)
        yield os.path.join(work, "repo")
    finally:
        shutil.rmtree(work, onerror=_writable)
