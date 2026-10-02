"""Find secrets that AI coding agents have stored on this machine: MCP server configs, agent settings, and the
session transcripts and prompt histories they keep (a key you pasted, or a .env the agent read, stays there in
plain text, and was sent to the model provider).

Credential stores the agents are meant to use (e.g. ~/.codex/auth.json) are skipped: that is where tokens belong.
"""
import functools, glob, json, os, pathlib, sqlite3, sys

from .scanner import _parallel, scan_text

# (agent, path relative to home, is_dir). Dirs are scanned recursively, minus SKIP_NAMES.
HOME_PLACES = [
    ("Claude Code", ".claude.json", False), ("Claude Code", ".claude", True),
    ("Codex", ".codex", True),
    ("GitHub Copilot CLI", ".copilot", True),
    ("Cursor", ".cursor/mcp.json", False), ("Cursor", ".cursor/cli-config.json", False),
    ("Gemini CLI", ".gemini", True),
    ("Windsurf", ".codeium/windsurf/mcp_config.json", False),
    ("Claude Desktop", ".config/Claude/claude_desktop_config.json", False),
    ("Claude Desktop", "Library/Application Support/Claude/claude_desktop_config.json", False),
    ("VS Code", ".config/Code/User/mcp.json", False),
    ("VS Code", "Library/Application Support/Code/User/mcp.json", False),
]
APPDATA_PLACES = [("Claude Desktop", "Claude/claude_desktop_config.json"), ("VS Code", "Code/User/mcp.json")]
PROJECT_PLACES = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".claude/settings.json",
                  ".claude/settings.local.json", ".gemini/settings.json", ".codex/config.toml"]
ENV_HOMES = {"CLAUDE_CONFIG_DIR": "Claude Code", "CODEX_HOME": "Codex", "COPILOT_HOME": "GitHub Copilot CLI"}
# The agent's own login (expected to hold a token), and bulky caches/third-party code that isn't the user's.
SKIP_NAMES = {".credentials.json", "auth.json", "oauth_creds.json", "google_accounts.json", "plugins", "extensions",
              "node_modules", "pkg", "statsig", "ide", ".git", "cache", "Cache"}
TEXT_EXT = {".json", ".jsonl", ".toml", ".yaml", ".yml", ".md", ".txt", ".log", ".env", ".sh", ".ini", ".cfg", ""}
# Cursor and VS Code (Copilot Chat) keep chats in SQLite databases (state.vscdb) under the editor's user folder.
EDITOR_DIRS = {"Cursor": ["Library/Application Support/Cursor/User", ".config/Cursor/User"],
               "VS Code": ["Library/Application Support/Code/User", ".config/Code/User"]}
EDITOR_APPDATA = {"Cursor": "Cursor/User", "VS Code": "Code/User"}
DB_TABLES = ("ItemTable", "cursorDiskKV")  # key/value tables; chats are JSON values
MAX_FILE = 500_000_000
CHUNK = 1_000_000


def places(home=None, cwd=None, env=None):
    """[(agent, path)] that exist on this machine."""
    home = home or os.path.expanduser("~")
    cwd = cwd or os.getcwd()
    env = os.environ if env is None else env
    out = [(a, os.path.join(home, p)) for a, p, _ in HOME_PLACES]
    if env.get("APPDATA"):
        out += [(a, os.path.join(env["APPDATA"], p)) for a, p in APPDATA_PLACES]
    out += [(a, env[k]) for k, a in ENV_HOMES.items() if env.get(k)]
    out += [("this project", os.path.join(cwd, p)) for p in PROJECT_PLACES]
    seen, found = set(), []
    for agent, p in out:
        real = os.path.realpath(p)
        if os.path.exists(p) and real not in seen:
            seen.add(real)
            found.append((agent, p))
    return found


def _files(path):
    if os.path.isfile(path):
        yield path
        return
    for root, dirs, files in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_NAMES)
        for f in sorted(files):
            if f not in SKIP_NAMES and os.path.splitext(f)[1].lower() in TEXT_EXT:
                yield os.path.join(root, f)


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                yield f"{k}: {v}"  # keep the name next to the value: `"OPENAI_API_KEY": "..."` stays recognizable
            else:
                yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def _decoded_lines(fh):
    """Yield (line_no, text) for a JSONL file, with each JSON line decoded to its string contents, so that
    escaped quotes and newlines (`\\"`, `\\n`) don't hide a secret. Lines that aren't JSON are kept as they are."""
    for n, raw in enumerate(fh, 1):
        try:
            text = "\n".join(_strings(json.loads(raw)))
        except ValueError:
            text = raw
        yield n, text


def _scan_stream(lines, display):
    """Scan (line_no, text) pairs in ~1 MB chunks; report each finding once at its original line."""
    found, seen, buf, line_of, size = [], set(), [], [], 0

    def flush():
        for f in scan_text("\n".join(buf), display):
            f.line = line_of[f.line - 1]
            if (f.line, f.kind, f.secret) not in seen:  # transcripts often repeat a tool's output on one line
                seen.add((f.line, f.kind, f.secret))
                found.append(f)

    for n, text in lines:
        parts = text.split("\n")
        buf += parts
        line_of += [n] * len(parts)
        size += len(text)
        if size >= CHUNK:
            flush()
            buf, line_of, size = [], [], 0
    if buf:
        flush()
    return found


def _display(path, home):
    return "~" + path[len(home):] if home and path.startswith(home + os.sep) else os.path.relpath(path)


def scan_file(path, home=None):
    home = home or os.path.expanduser("~")
    display = _display(path, home)
    try:
        if os.path.getsize(path) > MAX_FILE:
            return []
        with open(path, encoding="utf-8", errors="strict") as fh:
            if path.endswith(".jsonl"):
                return _scan_stream(_decoded_lines(fh), display)
            return _scan_stream(enumerate(fh.read().split("\n"), 1), display)
    except (UnicodeDecodeError, OSError):
        return []


def editor_dbs(home=None, env=None):
    """[(agent, state.vscdb path)] for Cursor and VS Code on this machine."""
    home = home or os.path.expanduser("~")
    env = os.environ if env is None else env
    roots = [(a, os.path.join(home, d)) for a, ds in EDITOR_DIRS.items() for d in ds]
    if env.get("APPDATA"):
        roots += [(a, os.path.join(env["APPDATA"], d)) for a, d in EDITOR_APPDATA.items()]
    found = []
    for agent, root in roots:
        for db in [os.path.join(root, "globalStorage", "state.vscdb")] + sorted(
                glob.glob(os.path.join(glob.escape(root), "workspaceStorage", "*", "state.vscdb"))):
            if os.path.isfile(db):
                found.append((agent, db))
    return found


def _db_rows(con, table):
    for rowid, value in con.execute(f"SELECT rowid, value FROM {table}"):  # table names are our constants
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        if not isinstance(value, str) or len(value) > 20_000_000:
            continue
        try:
            value = "\n".join(_strings(json.loads(value)))
        except ValueError:
            pass
        yield rowid, value


def scan_db(path, home=None):
    """Read an editor's state.vscdb read-only and scan its chat/key-value rows; findings point at table:rowid."""
    home = home or os.path.expanduser("~")
    display = _display(path, home)
    found = []
    try:  # read-only; immutable=1 skips locking so a running editor isn't disturbed
        con = sqlite3.connect(pathlib.Path(path).resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
        try:
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            for table in DB_TABLES:
                if table in tables:
                    found += _scan_stream(_db_rows(con, table), f"{display}#{table}")
        finally:
            con.close()
    except sqlite3.Error:
        return []
    return found


def scan_agents(home=None, cwd=None, env=None, quiet=False):
    """Scan every agent location found; return Findings with ~-relative paths."""
    home = home or os.path.expanduser("~")
    where = places(home, cwd, env)
    dbs = editor_dbs(home, env)
    if not quiet:
        names = ", ".join(dict.fromkeys(a for a, _ in where + dbs)) or "none found"
        print(f"Scanning AI agent files: {names}", file=sys.stderr)
    files = list(dict.fromkeys(f for _, p in where for f in _files(p)))
    return _parallel(functools.partial(scan_file, home=home), files) + [f for _, db in dbs for f in scan_db(db, home)]


ADVICE = ("Secrets in agent transcripts and histories were sent to the model provider and sit on disk in plain "
          "text: rotate them (`leakkill verify --agents` shows which still work), then delete those session "
          "files. In MCP configs, replace the value with an environment variable reference.")
