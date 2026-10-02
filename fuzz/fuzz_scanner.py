#!/usr/bin/python3
"""Coverage-guided fuzzing (Atheris, run by ClusterFuzzLite in CI) of everything that reads untrusted input:
the scanner (any file in a repo) and the AI agent guard (hook JSON from the agent).

A crash, an uncaught exception, a raw secret in the output, or a slow input (a regex backtracking on hostile
text: libFuzzer's timeout) is a bug.
"""
import contextlib, io, json, sys

import atheris

with atheris.instrument_imports():
    from leakkill import agents, guard, scanner


def check_scan(text):
    for f in scanner.scan_text(text, "fuzz.py"):
        assert f.masked != f.secret, "a finding must never be shown unmasked"


def check_guard(raw, agent):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = guard.guard(raw, agent)
    assert rc in (0, 2), rc
    for f in scanner.scan_text(raw, "event"):
        if len(f.secret) > 12:
            assert f.secret not in out.getvalue() + err.getvalue(), "the guard echoed a raw secret"


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 3)
    text = fdp.ConsumeUnicodeNoSurrogates(len(data))
    if choice == 0:
        check_scan(text)
    elif choice == 1:  # transcript-style JSONL, as `scan --agents` reads it
        list(agents._scan_stream(agents._decoded_lines(io.StringIO(text)), "fuzz.jsonl"))
    elif choice == 2:
        check_guard(text, guard.AGENTS[len(text) % len(guard.AGENTS)])
    else:  # well-formed hook events with fuzzed fields
        event = {"hook_event_name": ["PreToolUse", "UserPromptSubmit", "beforeReadFile", "beforeShellExecution",
                                     "preToolUse"][len(text) % 5],
                 "tool_name": ["Bash", "Read", "Write", "apply_patch", "Shell"][len(text) % 5],
                 "prompt": text, "command": text, "file_path": text, "content": text,
                 "tool_input": {"command": text, "file_path": text, "content": text}}
        check_guard(json.dumps(event), guard.AGENTS[len(text) % len(guard.AGENTS)])


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
