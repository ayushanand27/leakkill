"""leakkill: find leaked secrets, check if they're live, revoke them, and guard AI coding agents.

  leakkill [scan] [PATH ...]         find secrets (offline; exit 1 if any)
  leakkill verify [PATH ...]         ...and check which are live and whose they are (exit 1 if any live)
  leakkill revoke [PATH ...]         plan revocation of live secrets; add --yes to do it
  leakkill report [PATH ...]         write an incident report with step-by-step cleanup
  leakkill install-hook              block commits that contain secrets (git pre-commit)
  leakkill install-agent-hooks [AGENT ...] [--global]
                                     stop AI agents (claude, cursor, copilot, codex) reading .env/keys,
                                     sending secrets in prompts, or writing secrets into code
  leakkill install-claude-hook       same as `install-agent-hooks claude`
  leakkill guard [--agent AGENT]     hook entry point (reads the agent's hook JSON on stdin)

Common options: --staged (pre-commit), --history (all commits), --agents (AI agents' MCP configs, settings and
session transcripts on this machine), --exclude-tests, --json, --baseline FILE.
scan/verify also take --report FILE, --sarif FILE and --write-baseline FILE.
Ignore a line with `leakkill:ignore`; ignore paths with globs in .leakkillignore.
"""
import argparse, difflib, json, os, sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from . import __version__, agents, baseline, guard as guard_mod, providers, report, sarif, scanner

LEGACY = {"--guard": "guard", "--install-hook": "install-hook", "--install-claude-hook": "install-claude-hook"}
COMMANDS = {"scan", "verify", "revoke", "report", "guard", "install-hook", "install-claude-hook", "install-agent-hooks"}


@dataclass
class Item:
    n: int
    kind: str
    secret: str
    findings: list
    result: providers.Result = None


def collect(args):
    if args.agents:
        found = agents.scan_agents()
    elif args.history:
        found = scanner.scan_history()
    elif args.staged:
        found = scanner.scan_staged()
    else:
        found = scanner.scan_paths(args.paths or ["."])
    ignores = scanner.load_ignores()
    found = [f for f in found if not scanner.ignored(f.path, ignores)]
    if args.exclude_tests:
        found = [f for f in found if not scanner.is_test_path(f.path)]
    items = [Item(0, k, s, fs) for k, s, fs in scanner.group(found)]
    if args.baseline:
        items, suppressed = baseline.filter_new(items, args.baseline)
        if suppressed:
            print(f"({suppressed} known secret(s) suppressed by baseline {args.baseline})", file=sys.stderr)
    for n, it in enumerate(items, 1):
        it.n = n
    return items


def verify_all(items):
    aws_secrets = {}
    for it in items:
        if it.kind == "AWS secret key":
            for f in it.findings:
                aws_secrets.setdefault(f.path, []).append(it.secret)
    all_aws = [it.secret for it in items if it.kind == "AWS secret key"]

    def one(it):
        ctx = {}
        if it.kind == "AWS access key":
            near = [s for f in it.findings for s in aws_secrets.get(f.path, [])]
            ctx["aws_secrets"] = list(dict.fromkeys(near + all_aws))
        it.result = providers.verify(it.kind, it.secret, ctx)

    with ThreadPoolExecutor(8) as ex:
        list(ex.map(one, items))


def as_json(items):
    return json.dumps([{
        "id": it.n, "type": it.kind, "value": it.findings[0].masked,
        "status": it.result.status if it.result else None,
        "identity": it.result.identity if it.result else None,
        "note": it.result.note if it.result else None,
        "locations": [f.location for f in it.findings],
    } for it in items], indent=2)


def print_items(items):
    for it in items:
        r = it.result
        status = f"{r.status:<13}" if r else ""
        extra = "  ".join(x for x in ((r.identity, r.note) if r else ()) if x)
        locs = ", ".join(f.location for f in it.findings[:3]) + (f" (+{len(it.findings) - 3})" if len(it.findings) > 3 else "")
        print(f"#{it.n:<3} {status}{it.kind:<22} {it.findings[0].masked:<20} {locs}" + (f"\n      {extra}" if extra else ""))


def summary(items):
    if not items:
        return "Clean."
    s = f"\n{len(items)} unique secret(s)"
    if items[0].result:
        live = sum(1 for i in items if i.result.status == providers.LIVE)
        s += f", {live} LIVE"
    return s + "."


def _target(args):
    return "AI agent files" if args.agents else "git history" if args.history else "staged changes" if args.staged else " ".join(args.paths or ["."])


def cmd_scan(args, verify=False):
    items = collect(args)
    if args.write_baseline:
        n = baseline.write(items, args.write_baseline)
        print(f"Baseline with {n} known secret(s) written to {args.write_baseline} (hashes only, no secrets). "
              f"Use --baseline {args.write_baseline} to only report new ones.")
        return 0
    if verify and items:
        verify_all(items)
    if args.json:
        print(as_json(items))
    else:
        print_items(items)
        print(summary(items))
        if args.agents and items:
            print("\n" + agents.ADVICE)
    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            f.write(report.render(items, _target(args), verified=verify))
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            f.write(sarif.render(items))
    if verify:
        return 1 if any(i.result.status == providers.LIVE for i in items) else 0
    return 1 if items else 0


def cmd_revoke(args):
    items = collect(args)
    only = {int(x) for x in args.only.split(",")} if args.only else None
    if only:
        items = [i for i in items if i.n in only]
    if not items:
        print("Nothing to revoke.")
        return 0
    verify_all(items)
    live = [i for i in items if i.result.status == providers.LIVE]
    print_items(items)
    if not live:
        print("\nNo live secrets: nothing to revoke.")
        return 0
    auto = [i for i in live if providers.provider(i.kind).revoke]
    manual = [i for i in live if i not in auto]
    print(f"\n{len(live)} live secret(s): {len(auto)} can be revoked automatically, {len(manual)} need manual steps.")
    for i in manual:
        print(f"  #{i.n} {i.kind}: {providers.provider(i.kind).manual}")
    for i in auto:
        if providers.provider(i.kind).side_effect:
            print(f"  note for #{i.n} {i.kind}: {providers.provider(i.kind).side_effect}")
    if not args.yes:
        if auto:
            print(f"\nDry run. Re-run with --yes to revoke: " + ", ".join(f"#{i.n}" for i in auto))
        return 1
    failed = 0
    for i in auto:
        ok, msg = providers.revoke(i.kind, i.secret, i.result)
        print(f"  #{i.n} {i.kind}: {'REVOKED' if ok else 'FAILED'} ({msg})")
        if not ok:
            failed += 1
            print(f"      manual: {providers.provider(i.kind).manual}")
    return 1 if failed or manual else 0


def cmd_report(args):
    items = collect(args)
    if items and not args.no_verify:
        verify_all(items)
    target = _target(args)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report.render(items, target, verified=not args.no_verify))
    print(f"Report written to {os.path.abspath(args.output)} ({len(items)} unique secret(s)).")
    if args.replacements:
        report.write_replacements(items, args.replacements)
        print(f"Replacements for git filter-repo written to {args.replacements}. "
              "It contains the raw secrets: delete it when done and never commit it.")
    return 1 if items else 0


def parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("paths", nargs="*", help="files or directories (default: .)")
    common.add_argument("--staged", action="store_true", help="scan staged git changes")
    common.add_argument("--history", action="store_true", help="scan every commit on every branch")
    common.add_argument("--agents", action="store_true",
                        help="scan AI agents' files on this machine: MCP configs, settings, session transcripts")
    common.add_argument("--exclude-tests", action="store_true", help="skip test_* files and tests/ dirs")
    common.add_argument("--json", action="store_true", help="machine-readable output")
    common.add_argument("--baseline", metavar="FILE", help="ignore secrets listed in this baseline file")
    p = argparse.ArgumentParser(prog="leakkill", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"leakkill {__version__}")
    sub = p.add_subparsers(dest="cmd")
    for name, h in (("scan", "find secrets (offline)"), ("verify", "find secrets and check which are live")):
        sp = sub.add_parser(name, parents=[common], help=h)
        sp.add_argument("--report", metavar="FILE", help="also write the Markdown incident report to FILE")
        sp.add_argument("--sarif", metavar="FILE", help="also write SARIF 2.1.0 (GitHub Security tab) to FILE")
        sp.add_argument("--write-baseline", metavar="FILE",
                        help="accept all current findings: write their hashes to FILE and exit 0")
    r = sub.add_parser("revoke", parents=[common], help="revoke live secrets (dry run unless --yes)")
    r.add_argument("--only", help="comma-separated ids from `leakkill verify`, e.g. 1,3")
    r.add_argument("--yes", action="store_true", help="actually revoke")
    rp = sub.add_parser("report", parents=[common], help="write a Markdown incident report")
    rp.add_argument("-o", "--output", default="leakkill-report.md")
    rp.add_argument("--no-verify", action="store_true", help="don't contact providers")
    rp.add_argument("--replacements", metavar="FILE", help="also write a git filter-repo --replace-text file")
    g = sub.add_parser("guard", help="AI agent hook entry point (reads hook JSON on stdin)")
    g.add_argument("--agent", choices=guard_mod.AGENTS, default="claude")
    ia = sub.add_parser("install-agent-hooks", help="guard AI coding agents against secret leaks")
    ia.add_argument("agents", nargs="*", metavar="AGENT",
                    help="claude, cursor, copilot, codex (default: all)")
    ia.add_argument("--global", dest="global_", action="store_true",
                    help="install for your user account instead of this project")
    for name in ("install-hook", "install-claude-hook"):
        sub.add_parser(name)
    return p


def check_paths(paths):
    """A security tool must never report 'Clean.' for something it didn't scan (e.g. a typo'd command)."""
    missing = [p for p in paths if not os.path.exists(p)]
    for p in missing:
        hint = difflib.get_close_matches(p, sorted(COMMANDS), n=1)
        print(f"leakkill: no such file or directory: {p}" + (f" (did you mean `leakkill {hint[0]}`?)" if hint else ""),
              file=sys.stderr)
    return not missing


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in LEGACY:
        argv[0] = LEGACY[argv[0]]
    if not argv or (argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = parser().parse_args(argv)
    if args.cmd in ("scan", "verify", "revoke", "report") and not check_paths(args.paths):
        return 2
    if args.cmd == "guard":
        return guard_mod.guard(sys.stdin.read(), args.agent)
    if args.cmd == "install-agent-hooks":
        bad = [a for a in args.agents if a not in guard_mod.AGENTS]
        if bad:
            print(f"leakkill: unknown agent {bad[0]!r} (choose from {', '.join(guard_mod.AGENTS)})", file=sys.stderr)
            return 2
        return guard_mod.install_agent_hooks(args.agents or guard_mod.AGENTS, user_level=args.global_)
    if args.cmd == "install-hook":
        return guard_mod.install_git_hook()
    if args.cmd == "install-claude-hook":
        return guard_mod.install_claude_hook()
    if args.cmd == "revoke":
        return cmd_revoke(args)
    if args.cmd == "report":
        return cmd_report(args)
    return cmd_scan(args, verify=args.cmd == "verify")


def main_cli():
    sys.exit(main())
