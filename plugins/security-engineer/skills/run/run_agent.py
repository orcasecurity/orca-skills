#!/usr/bin/env python3
"""
Security Engineer Agent — mechanical operations CLI.
Handles: alert fetching/filtering, git branch management, PR creation.
Claude handles the code fixes; this script handles everything else.

Usage: python3 run_agent.py <subcommand> [options]
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from orca_client import (
    RISK_ORDER,
    _resolve_feature_type,
    alert_branch_name,
    branch_exists_remote,
    fetch_alert_by_id,
    fetch_alerts,
    get_token,
    is_fixable,
    normalize_cve_id,
    repos_with_cve,
)
from version_data import ecosystem_for_manifest, resolve_bump, resolve_ecosystem

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture=True, cwd=None):
    """Run a shell command. Returns (stdout, stderr, returncode)."""
    result = subprocess.run(
        cmd, shell=isinstance(cmd, str),
        capture_output=capture, text=True, cwd=cwd
    )
    if check and result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Command failed: {cmd}")
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def detect_repo():
    """Detect owner/repo from git remote."""
    try:
        url, _, _ = run(["git", "remote", "get-url", "origin"])
        if "github.com/" in url:
            return url.split("github.com/")[-1].removesuffix(".git")
        elif "github.com:" in url:
            return url.split("github.com:")[-1].removesuffix(".git")
    except Exception:
        pass
    return None


# An advisory id used as a filter token. Matched before the unknown-token
# warning, because dropping one is not a cosmetic loss: `security-engineer
# CVE-2020-7471` would otherwise discard the token and run unfiltered, fixing
# every open alert in the repo when the user named exactly one thing.
_ADVISORY_TOKEN_RE = re.compile(
    r"^(?:CVE|GHSA|PYSEC|GO|RUSTSEC|OSV)-[A-Za-z0-9.-]+$", re.IGNORECASE)


def parse_filter(filter_str):
    """Parse risk levels, feature types and advisory ids from a filter string.

    Returns (levels, types, cve_ids); each is None when nothing of that kind was
    named, so a caller can tell "not filtered" from "filtered to nothing".
    """
    valid_levels = set(RISK_ORDER)
    valid_types = {"sast", "iac", "secret", "cve", "scm_posture"}

    levels = []
    types = []
    cve_ids = []
    unknown = []

    for raw in filter_str.split(","):
        token = raw.strip().lower()
        if token in valid_levels:
            levels.append(token)
        elif token in valid_types:
            types.append(token)
        elif _ADVISORY_TOKEN_RE.match(raw.strip()):
            cve_ids.append(normalize_cve_id(raw))
        elif token:
            unknown.append(token)

    if unknown:
        print(f"Warning: ignoring unknown filter tokens: {unknown}", file=sys.stderr)

    return levels or None, types or None, cve_ids or None


def parse_cve_args(values):
    """Flatten repeated and comma-joined --cve values into normalized ids.

    `--cve CVE-1,CVE-2` and `--cve CVE-1 --cve CVE-2` mean the same thing; both
    reach here as a list because argparse appends.
    """
    ids = []
    for value in values or []:
        for part in str(value).split(","):
            part = part.strip()
            if part:
                ids.append(normalize_cve_id(part))
    # Deduplicate, preserving the order the user wrote them in.
    return list(dict.fromkeys(ids))


def min_level_from_list(levels):
    """Return the lowest-ranked (most inclusive) level from a list."""
    if not levels:
        return None
    indices = [RISK_ORDER.index(level) for level in levels if level in RISK_ORDER]
    return RISK_ORDER[max(indices)] if indices else None


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _alert_to_entry(a):
    """Convert a normalized alert dict to a list-alerts entry."""
    branch = alert_branch_name(a["alert_id"])
    return {
        "alert_id":      a["alert_id"],
        "title":         a["title"],
        "risk_level":    a["risk_level"],
        "score":         a["score"],
        "feature_type":  _resolve_feature_type(a),
        "source":        a["source"],
        "cve_ids":       a.get("cve_ids", []),
        "is_fixable":    is_fixable(a),
        "branch_exists": branch_exists_remote(branch),
        "branch_name":   branch,
    }


def cmd_list_alerts(args):
    # In multi-repo mode the orchestrator passes --repo-dir so that git
    # operations (detect_repo, branch_exists_remote) run in the right clone.
    if getattr(args, "repo_dir", None):
        os.chdir(args.repo_dir)

    token = get_token()

    # Single-alert mode: bypass bulk fetch
    if args.alert:
        try:
            a = fetch_alert_by_id(args.alert, token)
        except RuntimeError as e:
            print(json.dumps({"error": str(e)}))
            sys.exit(1)
        if not a:
            print(json.dumps({"error": f"Alert {args.alert} not found"}))
            sys.exit(1)
        result = [_alert_to_entry(a)]
        print(json.dumps({"dry_run": getattr(args, "dry_run", False), "alerts": result}, indent=2))
        return

    # Bulk mode
    repo = args.repo or detect_repo()
    if not repo:
        sys.exit("Error: could not detect repo. Pass repo as argument.")

    levels, types, filter_cves = (parse_filter(args.filter) if args.filter
                                  else (None, None, None))
    min_level = min_level_from_list(levels)
    # An advisory id can arrive either way; a run naming it twice should not
    # narrow to nothing, so the two sources are merged rather than overriding.
    cve_ids = parse_cve_args(getattr(args, "cve", None)) + list(filter_cves or [])
    cve_ids = list(dict.fromkeys(cve_ids)) or None

    try:
        alerts = fetch_alerts(repo, token, min_level=min_level,
                              feature_types=types, cve_ids=cve_ids)
    except RuntimeError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    if args.fixable_only:
        alerts = [a for a in alerts if is_fixable(a)]

    result = [_alert_to_entry(a) for a in alerts]

    if args.max:
        result = result[:args.max]

    output = {
        "dry_run": getattr(args, "dry_run", False),
        "cve_ids": cve_ids or [],
        "alerts": result,
    }
    print(json.dumps(output, indent=2))


def cmd_get_alert(args):
    token = get_token()
    try:
        alert = fetch_alert_by_id(args.alert_id, token)
    except RuntimeError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    if not alert:
        print(json.dumps({"error": f"Alert {args.alert_id} not found"}))
        sys.exit(1)

    print(json.dumps(alert, indent=2))


def cmd_find_cve(args):
    """Print which code repositories have an open alert carrying a CVE.

    Standalone like `resolve-version`, and for the same reason: "where is this
    CVE open?" is the question that comes before any fix, and answering it
    should not mean starting one. Read-only — one API query, no clone, no git.
    """
    cve_ids = parse_cve_args(args.cve_ids)
    if not cve_ids:
        print(json.dumps({"error": "no advisory ids given"}))
        sys.exit(1)

    token = get_token()
    try:
        repos = repos_with_cve(cve_ids, token)
    except RuntimeError as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)

    print(json.dumps({
        "cve_ids": cve_ids,
        "repos": [{"repo": name, "alert_count": n} for name, n in repos],
        "total_alerts": sum(n for _, n in repos),
    }, indent=2))


def cmd_resolve_version(args):
    """Print the version decision for one package as JSON.

    Deliberately usable on its own, with no Orca token and no alert: the version
    choice is the part of a CVE fix a reviewer most needs to be able to check,
    and "run this one command" beats reproducing a whole pipeline run.

    The ecosystem argument also accepts a manifest path, so an alert's `source`
    field can be pasted in directly.
    """
    eco = resolve_ecosystem(args.ecosystem) or ecosystem_for_manifest(args.ecosystem)
    if eco is None:
        print(json.dumps({"error": f"unknown ecosystem or manifest: "
                                   f"{args.ecosystem!r}"}))
        sys.exit(1)

    kwargs = {"offline": args.offline}
    if args.cache_ttl is not None:      # None means "leave the default alone"
        kwargs["cache_ttl_sec"] = args.cache_ttl
    decision = resolve_bump(eco, args.package, args.current, **kwargs)
    print(json.dumps(decision.to_dict(), indent=2))
    if decision.error:
        sys.exit(1)


def cmd_git_setup(args):
    branch = alert_branch_name(args.alert_id)

    if args.dry_run:
        print(f"dry-run: would create branch {branch} from main")
        return

    try:
        run(["git", "checkout", "main"])
        run(["git", "pull", "origin", "main"])
        _, stderr, rc = run(["git", "checkout", "-b", branch], check=False)
        if rc != 0:
            if "already exists" in stderr:
                print("branch_exists_locally")
                sys.exit(1)
            raise RuntimeError(stderr)
        print(f"ok: {branch}")
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_git_commit(args):
    if args.dry_run:
        print(f"dry-run: would commit with message: {args.message}")
        return

    try:
        run(["git", "add", "-A"])
        run(["git", "commit", "-m", args.message])
        # Extract SHA from "1 file changed" line or git log
        sha, _, _ = run(["git", "rev-parse", "--short", "HEAD"])
        print(sha)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_open_pr(args):
    branch = alert_branch_name(args.alert_id)

    if args.dry_run:
        print(f"dry-run: would push {branch} and open PR: {args.title}")
        return

    try:
        run(["git", "push", "-u", "origin", branch])
        pr_url, _, _ = run([
            "gh", "pr", "create",
            "--title", args.title,
            "--body", args.body,
            "--base", "main",
            "--head", branch
        ])
        print(pr_url)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Security Engineer Agent — mechanical ops")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without executing")
    sub = parser.add_subparsers(dest="command", required=True)

    # list-alerts
    p_list = sub.add_parser("list-alerts", help="Fetch and filter alerts as JSON")
    p_list.add_argument("repo", nargs="?", help="owner/repo (auto-detected if omitted)")
    p_list.add_argument("--filter", default=None,
                        help="Comma-separated risk levels and/or feature types (e.g. 'high,sast')")
    p_list.add_argument("--alert", default=None, help="Target a single alert ID instead of bulk fetch")
    p_list.add_argument("--cve", action="append", default=None,
                        help="Only alerts carrying this advisory id "
                             "(repeatable, or comma-separated)")
    p_list.add_argument("--max", type=int, default=None, help="Max number of alerts to return")
    p_list.add_argument("--fixable-only", action="store_true", help="Only return fixable alerts")
    p_list.add_argument("--dry-run", action="store_true", help="Signal dry-run mode in output")
    p_list.add_argument("--repo-dir", default=None,
                        help="Working directory for git operations (multi-repo mode)")

    # get-alert
    p_get = sub.add_parser("get-alert", help="Fetch single alert as JSON")
    p_get.add_argument("alert_id")

    # find-cve — read-only "where is this CVE open?"
    p_find = sub.add_parser("find-cve",
                            help="Which repos have an open alert for a CVE (JSON)")
    p_find.add_argument("cve_ids", nargs="+",
                        help="Advisory ids, e.g. CVE-2020-7471 GHSA-2p49-hgcm-8545")

    # resolve-version — no Orca token needed
    p_ver = sub.add_parser("resolve-version",
                           help="Which version fixes a vulnerable package (JSON)")
    p_ver.add_argument("ecosystem",
                       help="pypi|npm|go|maven|cargo|rubygems|nuget, "
                            "or a manifest path such as ./app/requirements.txt")
    p_ver.add_argument("package")
    p_ver.add_argument("current", help="Currently installed version")
    p_ver.add_argument("--offline", action="store_true",
                       help="Serve from cache only; never call OSV or deps.dev")
    p_ver.add_argument("--cache-ttl", type=int, default=None,
                       help="Cache lifetime in seconds (default 6h; 0 forces a refetch)")

    # git-setup
    p_git = sub.add_parser("git-setup", help="Create fix branch from main")
    p_git.add_argument("alert_id")

    # git-commit
    p_commit = sub.add_parser("git-commit", help="Stage all and commit")
    p_commit.add_argument("alert_id")
    p_commit.add_argument("message")

    # open-pr
    p_pr = sub.add_parser("open-pr", help="Push branch and open PR")
    p_pr.add_argument("alert_id")
    p_pr.add_argument("--title", required=True)
    p_pr.add_argument("--body", required=True)

    args = parser.parse_args()

    # Propagate --dry-run into subcommand args
    if not hasattr(args, "dry_run"):
        args.dry_run = False

    dispatch = {
        "list-alerts": cmd_list_alerts,
        "get-alert":   cmd_get_alert,
        "find-cve":    cmd_find_cve,
        "resolve-version": cmd_resolve_version,
        "git-setup":   cmd_git_setup,
        "git-commit":  cmd_git_commit,
        "open-pr":     cmd_open_pr,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
