#!/usr/bin/env python3
"""
Multi-phase validation pipeline for security fixes.

Phase 1: Python sanity checks — diff non-empty, size limits, no new secrets
Phase 2: LLM validation — does the fix address the vulnerability?
Phase 3: Local build/test — language-aware compile/lint
Phase 4: Orca GitHub App check — poll the orca-security-us check on the PR
Phase 5: GitHub CI gate — poll required PR checks

Phases 1-3 run pre-PR; 4 and 5 run after the PR is opened. All three pre-PR
gates read worktree_diff() so they judge exactly what the commit will contain.
"""

import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from _json_util import find_last_json_with_key
from orca_client import _resolve_feature_type


@dataclass
class ValidationResult:
    passed: bool
    phase: str                        # "sanity" | "llm" | "local_build" | "ci" | "orca_check"
    failures: list[str] = field(default_factory=list)
    needs_review: bool = False        # True when LLM verdict is "uncertain"


@dataclass
class OrcaCheckFinding:
    """A single finding from the Orca GitHub App check annotations."""
    file: str
    line: int
    message: str
    severity: str  # "failure" | "warning" | "notice"


# ---------------------------------------------------------------------------
# Shared: the diff every gate is judged against
# ---------------------------------------------------------------------------

# Flags for the single-shot "read this text, return JSON" subprocesses (LLM
# validation, impact analysis). Neither needs a tool: the alert and the diff are
# already in the prompt.
#
# `--tools ""` is the load-bearing part. It removes the tool definitions from
# the model's context entirely. `--allowedTools ""` looks equivalent but is not:
# it only *denies* the calls, so the model still emits tool_use blocks, each one
# is refused, and each refusal costs a turn. Measured over 5 trials that cost
# exactly 3 turns every time and 6.2x the money ($0.114 vs $0.018 per call),
# with a tail that ran to 7 turns — which is what kept blowing past --max-turns
# and exiting subtype=error_max_turns with an empty stderr. Both callers then
# took their silent error path: validation passed everything with needs_review,
# and every PR was labelled impact:medium regardless of the change.
#
# With no tools available there is nothing to attempt, so one turn is provably
# enough — measured at exactly 1 turn across 5 trials. The turn cap was never
# the real lever.
_SINGLE_SHOT_TOOL_FLAGS = ["--tools", ""]

# Removing the tools is necessary but not sufficient: the model does not know
# they are gone, so on a prompt that invites investigation it can open with prose
# like "I'll ground this in the actual repo contents before judging" and spend its
# single turn saying so, leaving no JSON to parse. Observed on 2 of 3 alerts in a
# live run once the impact prompt grew a Fix Context section. Every single-shot
# prompt ends with this so the constraint is the last thing read.
_SINGLE_SHOT_CONTRACT = """\
You have no tools and cannot read the repository, run commands, or fetch \
anything. The material above is everything available and it is sufficient — do \
not ask for more, do not describe what you would check first, and do not narrate \
your reasoning. Answer directly.
"""
_SINGLE_SHOT_MAX_TURNS = 1


def _subprocess_error_detail(result, limit: int = 500) -> str:
    """Best available explanation for a failed subprocess.

    `claude -p --output-format json` reports its own failures in a JSON envelope
    on *stdout* and leaves stderr empty, so a stderr-only message printed
    "(no stderr)" and threw away the actual cause. Prefer stderr when there is
    one, fall back to stdout, and surface the envelope's subtype when present
    because that is the field that names the failure (e.g. error_max_turns).
    """
    stderr = (result.stderr or "").strip()
    stdout = (result.stdout or "").strip()
    if stderr:
        return stderr[:limit]
    if not stdout:
        return "(no output)"
    try:
        envelope = json.loads(stdout)
    except json.JSONDecodeError:
        return stdout[:limit]
    if isinstance(envelope, dict):
        subtype = envelope.get("subtype") or envelope.get("error")
        if subtype:
            return f"{subtype}: {json.dumps(envelope)[:limit]}"
    return stdout[:limit]


def worktree_diff(worktree_path: Path) -> str:
    """Return the diff of everything a subsequent `git add -A` would commit.

    Plain `git diff` only reports tracked, unstaged changes, so it misses files
    the fix agent created — a fix that only adds a file looks like an empty diff.
    `git add -A -N` registers untracked files as intent-to-add so their content
    shows up, which keeps every gate (sanity, LLM, impact) judging the same set
    of changes the commit will actually contain. Honours .gitignore.
    """
    subprocess.run(["git", "add", "-A", "-N"],
                   cwd=worktree_path, capture_output=True, text=True)
    return subprocess.run(["git", "diff"],
                          cwd=worktree_path, capture_output=True, text=True).stdout


def diff_line_count(diff_text: str) -> int:
    """Count added + removed lines in a unified diff, excluding file headers."""
    total = 0
    for line in diff_text.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            total += 1
    return total


# ---------------------------------------------------------------------------
# Phase 1: Sanity checks (Python, always)
# ---------------------------------------------------------------------------

# Per-type ceilings on how much a fix may change before it needs human eyes.
#
# sast is 100 rather than 50 because the limit has to fit the worst fix in the
# category, not the typical one. Parameterising a SQL query or wrapping a URL in
# an allowlist is a handful of lines, but removing an eval() means restructuring
# the call site — measured at 73 and 79 lines on two independent attempts at the
# same alert, so at 50 that whole class of finding could never pass.
_DIFF_LIMITS = {"sast": 100, "iac": 50, "secret": 50, "cve": 200}

_SECRET_PATTERNS = [
    r'(?i)(api_?key|password|secret|token)\s*[=:]\s*["\'][^"\']{8,}["\']',
    r'sk-[A-Za-z0-9]{20,}',
    r'(?i)bearer\s+[A-Za-z0-9+/]{20,}',
]


_VERSION_TOKEN = re.compile(r"\bv?\d+\.\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?\b")


def summary_version_mismatch(diff_summary: str, diff_text: str) -> str:
    """Does the fix agent's summary name a version its own diff never contains?

    A sandbox PR shipped the body "Bumped pillow from 8.3.1 to 11.3.0" over a
    diff that read `+pillow==12.3.0`. That summary is what the PR body and the
    impact prompt are built from, so a wrong one misleads both a reviewer and the
    risk assessment. The check is deliberately narrow: only versions the summary
    presents as *new* are required to appear among the diff's added lines, so
    naming the old version, an unrelated release, or a CVE year stays fine.

    Returns a failure message, or "" when consistent.
    """
    if not diff_summary or not diff_text:
        return ""

    added = "\n".join(line for line in diff_text.splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    if not added:
        return ""
    present = set(_VERSION_TOKEN.findall(added))
    # Compare without a leading v so "v0.17.0" in a summary matches "0.17.0" in
    # the diff and vice versa.
    present_bare = {v.lstrip("vV") for v in present}

    claimed = _claimed_new_versions(diff_summary)
    missing = [v for v in claimed if v.lstrip("vV") not in present_bare]
    if not missing:
        return ""
    return (f"fix summary claims version {', '.join(missing)} but the diff adds "
            f"{', '.join(sorted(present)) or 'no version'} — the summary does not "
            "describe the change")


# "to 1.2.3", "-> 1.2.3", "to version 1.2.3". Only the destination is checked;
# the source version legitimately does not appear among added lines.
_CLAIMED_NEW = re.compile(
    r"(?:\bto\b\s+(?:version\s+)?|->\s*|→\s*)(v?\d+\.\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?)",
    re.IGNORECASE)


def _claimed_new_versions(summary: str) -> list:
    """Versions the summary presents as the new one."""
    return list(dict.fromkeys(_CLAIMED_NEW.findall(summary or "")))


def sanity_check(alert: dict, worktree_path: Path,
                 feature_type: str | None = None,
                 diff_limit: int | None = None,
                 diff_summary: str | None = None) -> ValidationResult:
    """Phase 1 gate: the diff is non-empty, within size limits, and adds no secrets.

    feature_type: the *resolved* type ("cve"/"sast"/"iac"/"secret"), which selects
                  the diff-size limit. Alert JSON carries Orca's raw feature_type,
                  and that is empty for package CVEs — they are identified by
                  category instead — so relying on it silently applied the 50-line
                  sast limit to lockfile bumps that legitimately need 200.
    diff_limit:   explicit override, supplied by the type's FixPipeline so the
                  budget lives next to the rest of that type's behaviour. Falls
                  back to the _DIFF_LIMITS table when absent.
    diff_summary: the fix agent's own account of what it did. When given, it is
                  checked against the diff — see summary_version_mismatch.
    """
    failures = []
    ft = (feature_type or _resolve_feature_type(alert) or "sast").lower()

    diff_text = worktree_diff(worktree_path)
    if not diff_text.strip():
        return ValidationResult(passed=False, phase="sanity",
                                failures=["git diff is empty — no changes were made"])

    total = diff_line_count(diff_text)
    limit = diff_limit if diff_limit is not None else _DIFF_LIMITS.get(ft, 50)
    if total > limit:
        failures.append(f"diff too large: {total} lines changed (limit {limit} for {ft})")

    if diff_summary:
        mismatch = summary_version_mismatch(diff_summary, diff_text)
        if mismatch:
            failures.append(mismatch)

    if ft == "secret":
        added = [line for line in diff_text.splitlines()
                 if line.startswith("+") and not line.startswith("+++")]
        for line in added:
            for pat in _SECRET_PATTERNS:
                if re.search(pat, line):
                    failures.append("diff adds a line matching a secret pattern")
                    break

    return ValidationResult(passed=len(failures) == 0, phase="sanity", failures=failures)


# ---------------------------------------------------------------------------
# Phase 2: LLM validation agent
# ---------------------------------------------------------------------------

_LLM_PROMPT = """\
You are reviewing a security fix diff. Does this fix correctly address the vulnerability?

## Alert
{alert_json}

## Diff Applied
```diff
{diff_text}
```

{contract}
Return ONLY this JSON, with nothing before or after it:
{{
  "verdict": "pass|fail|uncertain",
  "reason": "<one sentence>",
  "concerns": ["optional concern for reviewer"]
}}

- "pass"      → fix clearly addresses the vulnerability
- "fail"      → fix does not address it, or introduces new issues
- "uncertain" → fix seems plausible but correctness cannot be confirmed without runtime context
"""


def llm_validate(alert: dict, worktree_path: Path, timeout_sec: int = 90) -> ValidationResult:
    diff_text = worktree_diff(worktree_path)[:5000]

    prompt = _LLM_PROMPT.format(
        alert_json=json.dumps(alert, indent=2),
        diff_text=diff_text,
        contract=_SINGLE_SHOT_CONTRACT,
    )
    cmd = ["claude", "-p", prompt, *_SINGLE_SHOT_TOOL_FLAGS,
           "--output-format", "json", "--max-turns", str(_SINGLE_SHOT_MAX_TURNS)]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        print(f"[WARN] LLM validation timed out after {timeout_sec}s")
        return ValidationResult(passed=True, phase="llm", needs_review=True,
                                failures=["LLM validation timed out — flagged for human review"])

    if result.returncode != 0:
        detail = _subprocess_error_detail(result)
        print(f"[WARN] LLM validation failed (exit={result.returncode}): {detail}")
        return ValidationResult(passed=True, phase="llm", needs_review=True,
                                failures=[f"LLM validation errored (exit={result.returncode}): {detail}"])

    return _parse_llm(result.stdout)


def _parse_llm(raw: str) -> ValidationResult:
    try:
        envelope = json.loads(raw)
        text = envelope.get("result", "") or raw
    except json.JSONDecodeError:
        text = raw

    data = find_last_json_with_key(text, "verdict")
    if not data:
        snippet = text[:200] if text else "(empty)"
        print(f"[WARN] could not parse LLM validation output: {snippet}")
        return ValidationResult(passed=True, phase="llm", needs_review=True,
                                failures=[f"Could not parse LLM validation response: {snippet}"])

    verdict = data.get("verdict", "uncertain")
    reason = data.get("reason", "")
    concerns = data.get("concerns") or []

    if verdict == "fail":
        return ValidationResult(passed=False, phase="llm", failures=[reason])
    elif verdict == "uncertain":
        return ValidationResult(passed=True, phase="llm", needs_review=True, failures=concerns)
    else:
        return ValidationResult(passed=True, phase="llm")


# ---------------------------------------------------------------------------
# Phase 3: Local build/test (language-aware)
# ---------------------------------------------------------------------------

def _dominant_ext(files: list[str]) -> str | None:
    counts: dict[str, int] = {}
    for f in files:
        ext = Path(f).suffix.lower()
        counts[ext] = counts.get(ext, 0) + 1
    return max(counts, key=counts.get) if counts else None


def local_build_check(
    files_changed: list[str],
    worktree_path: Path,
    source_file: str = "",
) -> ValidationResult:
    """Run a language-appropriate build check after a fix is applied.

    source_file: the affected file path from the Orca alert (authoritative).
                 Used as the primary seed for project-root detection; falls back
                 to files_changed if empty.
    """
    # Seed with the alert's source file first — it's authoritative and available
    # before the fix agent runs, unlike files_changed which comes from agent output.
    all_files = ([source_file] if source_file else []) + list(files_changed)

    ext = _dominant_ext(all_files)
    if not ext:
        return ValidationResult(passed=True, phase="local_build")

    if ext == ".go":
        go_root = _find_project_root(all_files, worktree_path, "go.mod")
        return _run_check(["go", "build", "./..."], go_root)
    elif ext == ".py":
        return _check_python(files_changed, worktree_path)
    elif ext in (".js", ".ts"):
        npm_root = _find_project_root(all_files, worktree_path, "package.json")
        return _run_check(["npm", "run", "build", "--if-present"], npm_root)
    elif ext == ".tf":
        tf_root = _find_terraform_root(all_files, worktree_path)
        return _run_check(["terraform", "validate"], tf_root)
    else:
        # No build check for YAML/Dockerfile/etc. — skip gracefully
        return ValidationResult(passed=True, phase="local_build")


def _find_project_root(files: list[str], worktree_path: Path, marker: str) -> Path:
    """Walk up from each file to find the nearest directory containing `marker`.

    Works for any project root indicator: go.mod, package.json, etc.
    Falls back to worktree_path if not found.
    """
    for f in files:
        # Strip line number suffix (e.g. "nodejs-app/server.js:40" → "nodejs-app/server.js")
        clean = f.split(":")[0] if ":" in f else f
        candidate = (worktree_path / clean).parent
        while candidate >= worktree_path:
            if (candidate / marker).exists():
                return candidate
            if candidate == worktree_path:
                break
            candidate = candidate.parent
    return worktree_path


def _find_terraform_root(files: list[str], worktree_path: Path) -> Path:
    """Find the directory containing .tf files — the terraform module root."""
    for f in files:
        if not f.endswith(".tf"):
            continue
        tf_dir = (worktree_path / f).parent
        if tf_dir.exists():
            return tf_dir
    return worktree_path


# Keep old names as aliases for backward compat with existing callers/tests
def _find_package_json_root(files: list[str], worktree_path: Path) -> Path:
    return _find_project_root(files, worktree_path, "package.json")


def _find_go_module_root(files: list[str], worktree_path: Path) -> Path:
    return _find_project_root(files, worktree_path, "go.mod")


def _run_check(cmd: list[str], cwd: Path) -> ValidationResult:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120, cwd=cwd)
    except subprocess.TimeoutExpired:
        return ValidationResult(passed=False, phase="local_build",
                                failures=[f"local build timed out ({' '.join(cmd)})"])
    except FileNotFoundError:
        return ValidationResult(passed=True, phase="local_build")  # tool not installed — skip
    if result.returncode != 0:
        out = (result.stdout + result.stderr)[:400]
        return ValidationResult(passed=False, phase="local_build",
                                failures=[f"local build failed: {out}"])
    return ValidationResult(passed=True, phase="local_build")


def _check_python(files: list[str], cwd: Path) -> ValidationResult:
    failures = []
    for f in files:
        if not f.endswith(".py"):
            continue
        result = subprocess.run(
            ["python3", "-m", "py_compile", str(cwd / f)],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            failures.append(f"syntax error in {f}: {result.stderr[:150]}")
    return ValidationResult(passed=len(failures) == 0, phase="local_build", failures=failures)


# ---------------------------------------------------------------------------
# Phase 4: GitHub CI gate (called after PR is opened)
# ---------------------------------------------------------------------------

def has_no_ci_checks(stdout: str, stderr: str) -> bool:
    """True when the PR simply has no checks configured.

    `gh pr checks` exits 1 both for "a check went red" and for "this repo has no
    CI at all", printing `no checks reported on the '<branch>' branch` to stderr
    in the second case. They are not the same outcome: a repo without CI has
    nothing to gate on, exactly like `gh` being absent.
    """
    return "no checks reported" in (stdout + stderr).lower()


def ci_gate(pr_url: str, timeout_sec: int = 600) -> ValidationResult:
    """Poll GitHub required checks. Uses `gh pr checks --watch`."""
    try:
        result = subprocess.run(
            ["gh", "pr", "checks", pr_url, "--watch", "--fail-fast"],
            capture_output=True, text=True, timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        return ValidationResult(passed=False, phase="ci",
                                failures=[f"CI checks did not complete within {timeout_sec}s"])
    except FileNotFoundError:
        return ValidationResult(passed=True, phase="ci")  # gh not available

    if result.returncode != 0:
        if has_no_ci_checks(result.stdout, result.stderr):
            print("[INFO] no CI checks configured on this PR — nothing to gate on",
                  flush=True)
            return ValidationResult(passed=True, phase="ci", needs_review=True)
        failed_lines = [line for line in result.stdout.splitlines() if "fail" in line.lower()]
        # Fall back to stderr: gh reports several failure modes there with an
        # empty stdout, which produced a bare "CI checks failed: " with no cause.
        reason = ("; ".join(failed_lines[:3])
                  or result.stdout.strip()[:200]
                  or result.stderr.strip()[:200]
                  or f"gh pr checks exited {result.returncode}")
        return ValidationResult(passed=False, phase="ci",
                                failures=[f"CI checks failed: {reason}"])

    return ValidationResult(passed=True, phase="ci")


# ---------------------------------------------------------------------------
# Phase 5: Orca GitHub App check (post-PR)
# ---------------------------------------------------------------------------

def _parse_pr_url(pr_url: str) -> tuple[str, int]:
    """Extract (owner/repo, pr_number) from a GitHub PR URL.

    Returns (owner_repo, number) — e.g. ("owner/repo", 42).
    Raises ValueError if the URL doesn't match.
    """
    m = re.match(r"https?://github\.com/([^/]+/[^/]+)/pull/(\d+)", pr_url)
    if not m:
        raise ValueError(f"Cannot parse PR URL: {pr_url}")
    return m.group(1), int(m.group(2))


def _get_pr_head_sha(pr_url: str) -> str:
    """Get the HEAD SHA for a PR using gh CLI."""
    result = subprocess.run(
        ["gh", "pr", "view", pr_url, "--json", "headRefOid", "--jq", ".headRefOid"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh pr view failed: {result.stderr[:200]}")
    sha = result.stdout.strip()
    if not sha:
        raise RuntimeError("gh pr view returned empty SHA")
    return sha


def _find_orca_check_run(owner_repo: str, sha: str, check_name: str) -> dict | None:
    """Find the Orca check run among commit check-runs. Case-insensitive substring match."""
    result = subprocess.run(
        ["gh", "api", f"repos/{owner_repo}/commits/{sha}/check-runs",
         "--jq", ".check_runs"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return None
    try:
        runs = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    check_lower = check_name.lower()
    for run in (runs or []):
        if check_lower in (run.get("name") or "").lower():
            return run
    return None


def _get_check_annotations(owner_repo: str, check_run_id: int) -> list[OrcaCheckFinding]:
    """Fetch annotations for a check run and return structured findings."""
    result = subprocess.run(
        ["gh", "api", f"repos/{owner_repo}/check-runs/{check_run_id}/annotations"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        return []
    try:
        annotations = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    findings = []
    for ann in (annotations or []):
        findings.append(OrcaCheckFinding(
            file=ann.get("path", ""),
            line=ann.get("start_line", 0),
            message=ann.get("message", ""),
            severity=ann.get("annotation_level", "warning"),
        ))
    return findings


def orca_check_gate(
    pr_url: str,
    check_name: str = "orca-security-us",
    timeout_sec: int = 600,
    poll_interval: int = 15,
    on_not_found: str = "skip",
) -> ValidationResult:
    """Poll the Orca GitHub App check on a PR.

    Returns a ValidationResult with:
    - passed=True if the check succeeded/neutral or was not found after grace period
    - passed=False if the check completed with failure, with structured findings in failures
    - needs_review=True when the check was skipped or not found

    on_not_found: "skip" (default) passes when the check never appears, so a repo
                  without the Orca App still gets its PR. "fail" blocks instead —
                  for setups where a missing check means the gate silently did
                  nothing. Previously this setting existed in config.py and the
                  docs but was never read, so "fail" behaved as "skip".
    """
    try:
        owner_repo, _ = _parse_pr_url(pr_url)
    except ValueError as e:
        return ValidationResult(passed=True, phase="orca_check", needs_review=True,
                                failures=[str(e)])

    try:
        sha = _get_pr_head_sha(pr_url)
    except (RuntimeError, subprocess.TimeoutExpired, FileNotFoundError) as e:
        return ValidationResult(passed=True, phase="orca_check", needs_review=True,
                                failures=[f"Could not get PR head SHA: {e}"])

    deadline = time.monotonic() + timeout_sec
    grace_deadline = time.monotonic() + 30  # 30s grace period for check to appear

    while time.monotonic() < deadline:
        run = _find_orca_check_run(owner_repo, sha, check_name)

        if run is None:
            if time.monotonic() > grace_deadline:
                verb = "failing" if on_not_found == "fail" else "skipping"
                print(f"[INFO] Orca check '{check_name}' not found on {sha[:8]}, {verb}",
                      flush=True)
                return ValidationResult(passed=(on_not_found != "fail"),
                                        phase="orca_check", needs_review=True,
                                        failures=[f"Orca check '{check_name}' not found on PR"])
            time.sleep(poll_interval)
            continue

        status = run.get("status", "")
        conclusion = run.get("conclusion", "")

        if status in ("queued", "in_progress"):
            print(f"[POLL] Orca check: {status}", flush=True)
            time.sleep(poll_interval)
            continue

        if status == "completed":
            if conclusion in ("success", "neutral"):
                return ValidationResult(passed=True, phase="orca_check")
            if conclusion == "skipped":
                return ValidationResult(passed=True, phase="orca_check", needs_review=True,
                                        failures=["Orca check was skipped"])

            # failure / action_required — fetch annotations
            check_run_id = run.get("id", 0)
            findings = _get_check_annotations(owner_repo, check_run_id)
            failure_msgs = []
            for f in findings:
                failure_msgs.append(f"{f.file}:{f.line} [{f.severity}] {f.message}")
            if not failure_msgs:
                failure_msgs = [f"Orca check concluded with '{conclusion}' (no annotations)"]

            return ValidationResult(passed=False, phase="orca_check",
                                    failures=failure_msgs)

        # Unknown status — treat as in-progress
        time.sleep(poll_interval)

    return ValidationResult(passed=False, phase="orca_check",
                            failures=[f"Orca check did not complete within {timeout_sec}s"])
