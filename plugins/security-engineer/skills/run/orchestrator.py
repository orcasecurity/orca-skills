#!/usr/bin/env python3
"""
Security Engineer Orchestrator — Python state machine.

Replaces the LLM coordinator. Fetches Orca alerts, dispatches Claude fix agents
as subprocesses with timeouts, validates fixes, assesses production impact,
opens PRs, polls CI, and notifies.

Usage: python3 orchestrator.py [filter_tokens] [--scan] [--dry-run] [--alert ID] [--max N] [--remote REPO]
"""
import argparse
import copy
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

_THIS_DIR = Path(__file__).parent
_SKILLS_DIR = _THIS_DIR.parent
sys.path.insert(0, str(_SKILLS_DIR / "lib"))
sys.path.insert(0, str(_THIS_DIR))

from _json_util import find_last_json_with_key
from config import load_config
from impact_agent import ImpactResult, analyze_impact
from notifier import NotificationPayload, build_notifiers
from orca_client import (
    RISK_ORDER,
    Repository,
    _resolve_feature_type,
    alert_branch_name,
    fetch_alerts,
    get_token,
    list_repositories,
    normalize_alert_id,
    repos_with_cve,
)
from pipelines import FixPlan, get_pipeline
from validator import ci_gate, llm_validate, orca_check_gate, sanity_check, worktree_diff

_RUN_AGENT = str(_THIS_DIR / "run_agent.py")

CFG = load_config()
MAX_WORKERS = CFG.max_parallel_fixes
REPO_WORKERS = CFG.max_parallel_repos
MAX_RETRIES = 2
RETRYABLE_ERRORS = {"json_parse_failure", "subprocess_error"}
TIMEOUTS = {"sast": 180, "iac": 120, "secret": 120, "cve": 240}

# Base branch that fix branches are cut from and PRs target.
BASE_BRANCH = "main"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class FixAgentResult:
    success: bool
    skipped: bool = False
    files_changed: list[str] = field(default_factory=list)
    diff_summary: str = ""
    manual_steps: list[str] = field(default_factory=list)
    failure_reason: str | None = None
    failed_step: str | None = None
    error_code: str | None = None
    timed_out: bool = False


@dataclass
class AlertTask:
    alert_id: str
    title: str
    risk_level: str
    feature_type: str
    source: str
    alert_json: dict
    state: str = "PENDING"
    pr_url: str | None = None
    failure_reason: str | None = None
    worktree_path: Path | None = None
    fix_result: FixAgentResult | None = None
    impact: ImpactResult | None = None
    needs_review: bool = False
    attempts: int = 0
    # What the type's specialist worked out before the agent ran. Carried on the
    # task because impact analysis, the PR body and the retry loop all need it.
    fix_plan: FixPlan | None = None
    # The advisory ids this alert was selected for, when the run named any. A
    # package alert covers every CVE in its package, so without this the run has
    # no way to say which one was asked for — or to check that it was cleared.
    requested_cves: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------

def _run(cmd: list[str], check: bool = True, cwd: Path | None = None) -> tuple[str, str, int]:
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if check and r.returncode != 0:
        # Fall back to stdout before giving up on a message. run_agent.py reports
        # failures as JSON on stdout ({"error": "Alert … not found"}) and writes
        # nothing to stderr, so a stderr-only check threw away the one useful
        # line and raised a bare "Command failed: python3 …" instead.
        detail = r.stderr.strip() or r.stdout.strip()
        raise RuntimeError(detail or f"Command failed: {' '.join(str(c) for c in cmd)}")
    return r.stdout.strip(), r.stderr.strip(), r.returncode


# ---------------------------------------------------------------------------
# Git worktree helpers
# ---------------------------------------------------------------------------

class WorktreeConflict(RuntimeError):
    """The branch or worktree holds work we must not destroy — skip this alert.

    Distinct from a plain RuntimeError, which means setup genuinely failed. The
    caller maps this to SKIPPED and everything else to FAILED, so a leftover
    directory can no longer masquerade as "branch already exists".
    """


def _worktree_path(alert_id: str, repo: Repository | None = None) -> Path:
    """Namespace the worktree by repo so parallel --remote all runs cannot collide."""
    prefix = f"{repo.name.replace('/', '-')}-" if (repo and repo.name) else ""
    return Path(f"/tmp/orca-fix-{prefix}{alert_id}")


def _local_branch_exists(branch: str, cwd: str | None) -> bool:
    r = subprocess.run(["git", "rev-parse", "--verify", "--quiet",
                        f"refs/heads/{branch}"],
                       capture_output=True, text=True, cwd=cwd)
    return r.returncode == 0


def _branch_has_own_commits(branch: str, cwd: str | None) -> bool:
    """True if `branch` carries commits that BASE_BRANCH does not.

    Separates a leaked empty branch (safe to reclaim) from one holding real work —
    a human's branch, or a crashed run that got as far as committing. Anything we
    cannot inspect counts as having commits, so we never force-delete blindly.
    """
    r = subprocess.run(["git", "rev-list", "--count", f"{BASE_BRANCH}..{branch}"],
                       capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        return True
    count = (r.stdout or "").strip()
    return count != "0"


def _create_worktree(alert_id: str, branch: str, repo: Repository | None = None) -> Path:
    """Create an isolated git worktree with `branch` checked out from BASE_BRANCH.

    Clears leftovers from an earlier crashed run first — a stale directory used to
    make `git worktree add` fail with "already exists", which the caller misread as
    a pre-existing branch and skipped the alert on every subsequent run.

    repo: when set (multi-repo mode) all git commands run inside repo.clone_path.
          When None, uses the current working directory (single-repo mode).

    Raises WorktreeConflict if the alert should be skipped, RuntimeError if setup
    failed for any other reason.
    """
    path = _worktree_path(alert_id, repo)
    cwd = str(repo.clone_path) if (repo and repo.clone_path) else None

    # Drop registrations whose directories no longer exist.
    subprocess.run(["git", "worktree", "prune"], capture_output=True, cwd=cwd)

    if path.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(path)],
                       capture_output=True, cwd=cwd)
        if path.exists():
            # Not a registered worktree of this repo — e.g. the clone it belonged
            # to was already deleted. Ours by naming convention, so clear it.
            shutil.rmtree(path, ignore_errors=True)
        if path.exists():
            raise RuntimeError(f"could not clear stale worktree at {path}")

    if _local_branch_exists(branch, cwd):
        if _branch_has_own_commits(branch, cwd):
            raise WorktreeConflict(
                f"local branch {branch} has commits not in {BASE_BRANCH} — "
                f"left untouched for review")
        subprocess.run(["git", "branch", "-D", branch], capture_output=True, cwd=cwd)

    _, stderr, rc = _run(["git", "worktree", "add", "-b", branch, str(path), BASE_BRANCH],
                         check=False, cwd=cwd)
    if rc != 0:
        msg = stderr.strip() or f"git worktree add failed (exit {rc})"
        if "already used by worktree" in msg or "already exists" in msg:
            raise WorktreeConflict(msg)
        raise RuntimeError(msg)
    return path


def _remove_worktree(path: Path | None, branch: str | None = None,
                     repo: Repository | None = None) -> None:
    """Remove worktree and clean up local branch.

    repo: when set (multi-repo mode) git commands run inside repo.clone_path.
    """
    cwd = str(repo.clone_path) if (repo and repo.clone_path) else None
    if path and path.exists():
        subprocess.run(["git", "worktree", "remove", "--force", str(path)],
                       capture_output=True, cwd=cwd)
    if branch:
        subprocess.run(["git", "branch", "-D", branch], capture_output=True, cwd=cwd)


def _get_diff(worktree_path: Path) -> str:
    """Diff shown to the impact agent — same view the pre-PR gates judged."""
    return worktree_diff(worktree_path)


# ---------------------------------------------------------------------------
# Fix agent invocation
# ---------------------------------------------------------------------------

_FIX_PROMPT_LIVE = """\
You are a specialist security fix agent. Fix ONE specific vulnerability.

## Vulnerability
**Alert:** {alert_id}  |  **Severity:** {risk_level}  |  **Type:** {feature_type}
**Title:** {title}

## Location
**File:** {file_path}
**Lines:** {lines}

## Vulnerable Code
{code_snippet}

## Why It's Vulnerable
{description}
{ai_triage_explanation}

## Recommended Fix
{recommendation}

## Instructions
{instructions}

## Important
- Your branch is already created and checked out. Do NOT run git-setup.
- Do NOT run git commit or git push. The orchestrator handles those after validation.
- Apply the fix, then verify the change was applied correctly.
- Print ONLY the JSON block below as your very last output (nothing after it).

## Full Alert Data (reference)
{alert_json}

## Required Final Output
Success:
{{"status": "success", "alert_id": "{alert_id}", "files_changed": ["path/to/file"], "diff_summary": "<one sentence>", "manual_steps": ["step if needed"]}}

Failure:
{{"status": "failed", "alert_id": "{alert_id}", "reason": "<what went wrong>", "step": "file_read|fix_apply|verify"}}
"""

_FIX_PROMPT_DRY = """\
DRY RUN — read files only, do not edit anything.

You are reviewing what a fix would look like for this vulnerability.

## Vulnerability
**Alert:** {alert_id}  |  **Severity:** {risk_level}  |  **Type:** {feature_type}
**Title:** {title}

## Location
**File:** {file_path}
**Lines:** {lines}

## Vulnerable Code
{code_snippet}

## Why It's Vulnerable
{description}
{ai_triage_explanation}

## Recommended Fix
{recommendation}

## Instructions (reference only — do not execute git or edit commands)
{instructions}

Describe the planned fix:
1. Read the file at {file_path}.
2. Show before/after of what the fix would look like.
3. Explain why this addresses the vulnerability.

## Full Alert Data (reference)
{alert_json}

Print ONLY this JSON as your very last output:
{{"status": "success", "alert_id": "{alert_id}", "files_changed": ["{file_path}"], "diff_summary": "<planned change>", "manual_steps": []}}
"""


def _build_prompt_context(alert: dict) -> dict:
    """Extract structured fields from alert JSON for fix agent prompts."""
    position = alert.get("position", {}) or {}
    start_line = position.get("start_line")
    end_line = position.get("end_line")
    if start_line and end_line and start_line != end_line:
        lines = f"{start_line}–{end_line}"
    elif start_line:
        lines = str(start_line)
    else:
        lines = "see recommendation"

    raw_snippet = alert.get("code_snippet", [])
    code_snippet = (
        "\n".join(str(s) for s in raw_snippet) if isinstance(raw_snippet, list)
        else str(raw_snippet)
    ) or "(not available)"

    ai_triage = alert.get("ai_triage", {}) or {}
    ai_explanation = ai_triage.get("explanation", "")

    return {
        "file_path":            alert.get("file_path") or alert.get("source", "(unknown)"),
        "lines":                lines,
        "code_snippet":         code_snippet,
        "description":          alert.get("description", ""),
        "ai_triage_explanation": ai_explanation,
        "recommendation":       alert.get("recommendation", ""),
    }


def _invoke_fix_agent(task: AlertTask, dry_run: bool, timeout_sec: int,
                      feedback: str | None = None) -> FixAgentResult:
    instructions_path = _THIS_DIR / "fix-agents" / f"{task.feature_type}.md"
    if not instructions_path.exists():
        return FixAgentResult(
            success=False,
            failure_reason=f"No fix instructions for type: {task.feature_type}",
            error_code="no_instructions",
        )
    instructions = instructions_path.read_text()

    if dry_run:
        tmpl = _FIX_PROMPT_DRY
        tools = "Read"
    else:
        tmpl = _FIX_PROMPT_LIVE
        tools = "Read,Edit,Write,Bash"

    # A specialist's directive goes after the type instructions and before the
    # alert dump, so the concrete decision is the last thing read as guidance
    # rather than being buried under reference material.
    if task.fix_plan and task.fix_plan.prompt_extra:
        instructions = f"{instructions}\n\n---\n\n{task.fix_plan.prompt_extra}"

    ctx = _build_prompt_context(task.alert_json)
    prompt = tmpl.format(
        alert_json=json.dumps(task.alert_json, indent=2),
        instructions=instructions,
        alert_id=task.alert_id,
        title=task.title,
        risk_level=task.risk_level,
        feature_type=task.feature_type,
        **ctx,
    )

    if feedback:
        prompt += (
            "\n\n## Previous Attempt Failed\n\n"
            "Your previous fix introduced new security findings detected by "
            "the Orca security check on the PR:\n\n"
            f"{feedback}\n\n"
            "Each finding includes the file, line number, and description of the issue.\n"
            "Read the affected files, understand why your fix introduced these problems, "
            "and apply a different approach that resolves the original vulnerability "
            "without creating new ones.\n"
            "Do NOT repeat the same fix. Read the file again and find an "
            "alternative approach."
        )

    cmd = [
        "claude", "-p", prompt,
        "--allowedTools", tools,
        "--output-format", "json",
        "--max-turns", "20",
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout_sec,
            cwd=task.worktree_path,
        )
    except subprocess.TimeoutExpired:
        return FixAgentResult(
            success=False, timed_out=True,
            failure_reason=f"fix agent timed out after {timeout_sec}s",
            error_code="timeout",
        )

    if result.returncode != 0:
        return FixAgentResult(
            success=False,
            failure_reason=result.stderr[:300],
            error_code="subprocess_error",
        )

    return _parse_fix_result(result.stdout)


def _parse_fix_result(raw: str) -> FixAgentResult:
    try:
        envelope = json.loads(raw)
        text = envelope.get("result", "") or raw
    except json.JSONDecodeError:
        text = raw

    data = find_last_json_with_key(text, "status")
    if not data:
        return FixAgentResult(
            success=False, error_code="json_parse_failure",
            failure_reason="No structured output from fix agent",
        )

    status = data.get("status", "failed")
    if status == "success":
        return FixAgentResult(
            success=True,
            files_changed=data.get("files_changed") or [],
            diff_summary=data.get("diff_summary", ""),
            manual_steps=data.get("manual_steps") or [],
        )
    else:
        return FixAgentResult(
            success=False,
            failure_reason=data.get("reason", "unknown failure"),
            failed_step=data.get("step"),
        )


# ---------------------------------------------------------------------------
# Commit + PR
# ---------------------------------------------------------------------------

def _what_changed(task: AlertTask) -> str:
    """The "What Changed" section of the PR body.

    Prefers a specialist's resolved decision over the fix agent's own summary.
    The agent's prose is unverified and has been wrong in a way that matters: a
    sandbox PR shipped a body reading "Bumped pillow from 8.3.1 to 11.3.0" over a
    diff that said 12.3.0. Where a decision exists we describe what was decided,
    and mention the agent's account only if it disagrees.
    """
    summary = (task.fix_result.diff_summary if task.fix_result else "") or "See diff"
    plan = task.fix_plan
    decision = (plan.metadata.get("version_decision") if plan and plan.metadata
                else None) or {}
    ref = (plan.metadata.get("package_ref") if plan and plan.metadata
           else None) or {}
    target = decision.get("target_version")
    if not target:
        return summary

    lines = [
        (f"Bumped `{ref.get('package')}` from `{decision.get('current_version')}` "
         f"to `{target}` in `{ref.get('manifest_path')}`."),
        "",
        f"**Why this version:** {decision.get('rationale', '')}",
    ]
    cleared = decision.get("advisories_cleared") or []
    requested = (plan.metadata.get("requested_cves") if plan and plan.metadata
                 else None) or []
    if requested:
        # The alert covers a whole package, so a reviewer who opened this PR
        # looking for one CVE needs to see both that it was the trigger and that
        # the bump went wider than it.
        also = len(cleared) - len(requested)
        extra = (f", and {also} other advisor{'y' if also == 1 else 'ies'} "
                 "on the same package" if also > 0 else "")
        named = ", ".join(f"`{c}`" for c in requested)
        lines += ["", f"**Requested:** {named} — cleared by this bump{extra}."]
    if cleared:
        lines += ["", "**Advisories cleared:** "
                  + ", ".join(f"`{c}`" for c in cleared)]
    remaining = decision.get("advisories_remaining") or []
    if remaining:
        lines += ["", "**⚠️ Still affected after this bump:** "
                  + ", ".join(f"`{r}`" for r in remaining)]
    unknown = decision.get("advisories_unknown_scope") or []
    if unknown:
        lines += ["", "**⚠️ Not assessable** (the advisory carries no version "
                  "range): " + ", ".join(f"`{u}`" for u in unknown)]
    sources = decision.get("data_sources") or []
    if sources:
        lines += ["", (f"<sub>Resolved from {', '.join(sources)}. Reproduce with "
                       f"`run_agent.py resolve-version {ref.get('ecosystem')} "
                       f"{ref.get('package')} {decision.get('current_version')}`."
                       "</sub>")]
    return "\n".join(lines)


def _commit_and_pr(task: AlertTask, impact: ImpactResult | None, dry_run: bool) -> str | None:
    """Stage, commit, and open PR. Returns PR URL or None (dry-run)."""
    if dry_run:
        print(f"  [dry-run] would commit and open PR for {task.alert_id}")
        return None

    commit_msg = f"fix(security): {task.title} ({task.alert_id})"

    impact_level = impact.level if impact else "unknown"
    impact_desc = impact.description if impact else ""
    downtime = " ⚠️ Possible downtime." if (impact and impact.downtime_risk) else ""
    steps_md = ""
    if impact and impact.manual_steps:
        steps_md = "\n\n### Required Manual Steps\n" + "\n".join(
            f"- [ ] {s}" for s in impact.manual_steps
        )
    concerns_md = ""
    if impact and impact.concerns:
        concerns_md = "\n\n### Reviewer Concerns\n" + "\n".join(
            f"- {c}" for c in impact.concerns
        )

    pr_body = (
        f"## Security Fix: {task.title}\n\n"
        f"**Alert:** `{task.alert_id}`  |  "
        f"**Risk:** {task.risk_level}  |  "
        f"**Type:** {task.feature_type}  |  "
        f"**Impact:** {impact_level}{downtime}\n\n"
        f"{impact_desc}\n\n"
        f"### What Changed\n"
        f"{_what_changed(task)}"
        f"{steps_md}{concerns_md}\n\n"
        f"---\n*Auto-generated by `/security-engineer` orchestrator*"
    )
    pr_title = f"fix(security): {task.title[:60]} [{task.alert_id}]"

    _run(["python3", _RUN_AGENT, "git-commit", task.alert_id, commit_msg],
         cwd=task.worktree_path)

    stdout, _, _ = _run([
        "python3", _RUN_AGENT, "open-pr", task.alert_id,
        "--title", pr_title,
        "--body", pr_body,
    ], cwd=task.worktree_path)

    pr_url = stdout.strip().split("\n")[-1].strip()
    if not pr_url.startswith("http"):
        raise RuntimeError(f"Unexpected open-pr output: {stdout[:200]}")
    return pr_url


def _push_fix_update(task: AlertTask) -> None:
    """Stage, commit, and push updated fix to the existing PR branch."""
    commit_msg = f"fix(security): retry fix for {task.alert_id}"
    _run(["git", "add", "-A"], cwd=task.worktree_path)
    _run(["git", "commit", "-m", commit_msg], cwd=task.worktree_path)
    _run(["git", "push"], cwd=task.worktree_path)


# ---------------------------------------------------------------------------
# Per-alert state machine
# ---------------------------------------------------------------------------

def _revert(worktree_path: Path) -> None:
    """Restore the worktree to HEAD, including anything the fix agent created.

    `git checkout -- .` alone leaves untracked files in place and leaves the
    intent-to-add entries that worktree_diff() registers, so a "reverted" tree
    would still show a diff. `git clean -fd` honours .gitignore, so ignored build
    artefacts (node_modules, vendor) survive.
    """
    for cmd in (["git", "reset", "-q"],
                ["git", "checkout", "--", "."],
                ["git", "clean", "-fdq"]):
        subprocess.run(cmd, cwd=worktree_path, capture_output=True)


def _notify_payload(task: AlertTask) -> NotificationPayload:
    return NotificationPayload(
        event="",
        alert_id=task.alert_id,
        feature_type=task.feature_type,
        risk_level=task.risk_level,
        repo="",
        pr_url=task.pr_url,
        reason=task.failure_reason,
        impact_level=task.impact.level if task.impact else None,
        manual_steps=task.impact.manual_steps if task.impact else [],
        concerns=task.impact.concerns if task.impact else [],
        error_detail=task.impact.error if task.impact else None,
    )


def run_one(task: AlertTask, dry_run: bool, notifier, repo: Repository) -> AlertTask:
    """Drive a single alert through the full fix pipeline, always cleaning up.

    Worktree teardown lives in a finally so an unexpected exception cannot leak
    /tmp/orca-fix-* plus a local branch. A leak used to be self-perpetuating: the
    leftover directory made the next run fail worktree creation, which was then
    reported as "branch already exists" and skipped forever.

    repo.clone_path controls where git operations run:
      None  → current working directory (single-repo mode, existing behaviour)
      Path  → inside the cloned repo (multi-repo mode)
    """
    branch = alert_branch_name(task.alert_id)

    try:
        task.worktree_path = _create_worktree(task.alert_id, branch, repo=repo)
    except WorktreeConflict as e:
        task.state = "SKIPPED"
        task.failure_reason = str(e)
        return task
    except RuntimeError as e:
        task.state = "FAILED"
        task.failure_reason = f"worktree creation failed: {e}"
        return task

    try:
        return _run_pipeline(task, dry_run, notifier, repo)
    finally:
        _remove_worktree(task.worktree_path, branch, repo=repo)


def _next_candidate_hint(task: AlertTask) -> str:
    """Name a concrete alternative version for the retry, if one exists.

    Without this the retry prompt only says "do something different", which is
    how the same bump came back three times. With a resolved candidate list we
    can point at the next safe version instead — and when there is exactly one
    candidate, saying so is more useful than implying a choice exists.
    """
    plan = task.fix_plan
    if not plan or not plan.metadata:
        return ""
    decision = plan.metadata.get("version_decision") or {}
    candidates = decision.get("candidates") or []
    applied = decision.get("target_version")
    others = [c["version"] for c in candidates if c.get("version") != applied]
    if others:
        return ("The next safe published version after the one you tried is "
                f"{others[0]}. Prefer it over inventing a different target.")
    if applied:
        return (f"{applied} is the only published version that clears the "
                "advisories on this package — there is no safer alternative to "
                "fall back to. If it cannot be applied, report failure rather "
                "than substituting another version.")
    return ""


def _run_pipeline(task: AlertTask, dry_run: bool, notifier, repo: Repository) -> AlertTask:
    """Fix → validate → impact → PR → post-PR gates for one alert.

    Assumes the worktree exists; run_one owns its lifetime. Nothing in here
    performs cleanup, so every exit path is a plain `return task`.
    """
    p = _notify_payload(task)
    p.repo = repo.name
    notifier.notify("fix_started", p)

    pipeline = get_pipeline(task.feature_type, timeouts=TIMEOUTS)

    # Phase 0: let the type's specialist work out what it can before the agent
    # runs. A failure here is never fatal — we fall through to the agent's own
    # judgement, which is what happened for every fix before this existed.
    task.state = "PREPARING"
    plan = pipeline.prepare(task, task.worktree_path)
    if plan.error:
        print(f"[WARN] {task.alert_id} {task.feature_type} prepare failed: "
              f"{plan.error} — falling back to unguided fix", flush=True)
    elif plan.summary:
        print(f"[PLAN]  {task.alert_id} {plan.summary}", flush=True)
    if plan.needs_review:
        task.needs_review = True
    task.fix_plan = plan

    # Fix agent with retries
    task.state = "FIX_RUNNING"
    timeout = pipeline.timeout_sec
    fix_result = None

    while task.attempts < MAX_RETRIES:
        task.attempts += 1
        fix_result = _invoke_fix_agent(task, dry_run, timeout)

        if fix_result.timed_out:
            task.state = "TIMED_OUT"
            task.failure_reason = fix_result.failure_reason
            p = _notify_payload(task)
            p.repo = repo.name
            notifier.notify("timeout", p)
            return task

        if fix_result.success:
            break

        if fix_result.error_code not in RETRYABLE_ERRORS:
            break

        # Retryable: reset and retry
        _revert(task.worktree_path)

    if not fix_result or not fix_result.success:
        task.state = "FAILED"
        task.failure_reason = (fix_result.failure_reason if fix_result else "unknown")
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("fix_failed", p)
        return task

    task.fix_result = fix_result

    # Dry-run: done after fix agent describes the plan
    if dry_run:
        task.state = "DONE"
        p = _notify_payload(task)
        p.repo = repo.name
        p.detail = fix_result.diff_summary or ""
        notifier.notify("fix_planned", p)
        return task

    # Pre-PR validation (linear — no retry wrapping)
    # Phase 1: sanity
    task.state = "VALIDATE_LOCAL"
    print(f"[PHASE] {task.alert_id} sanity check", flush=True)
    sanity = sanity_check(task.alert_json, task.worktree_path,
                          feature_type=task.feature_type,
                          diff_limit=pipeline.diff_limit,
                          diff_summary=fix_result.diff_summary)
    if not sanity.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(sanity.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        return task

    # Phase 2: LLM validation
    print(f"[PHASE] {task.alert_id} LLM validation", flush=True)
    llm_val = llm_validate(task.alert_json, task.worktree_path)
    if not llm_val.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(llm_val.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        return task
    if llm_val.needs_review:
        task.needs_review = True

    # Phase 3: the type's own post-fix check. For CVEs this asserts the manifest
    # actually pins the resolved version — the check that never ran, because
    # local_build_check dispatches on file extension and a manifest bump is .txt,
    # .mod or .json.
    print(f"[PHASE] {task.alert_id} {task.feature_type} verification", flush=True)
    local_val = pipeline.verify(task, task.worktree_path, plan)
    if not local_val.passed:
        task.state = "FAILED"
        task.failure_reason = "; ".join(local_val.failures)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("validation_failed", p)
        return task

    # Impact analysis
    task.state = "IMPACT_ANALYSIS"
    print(f"[PHASE] {task.alert_id} production impact analysis", flush=True)
    diff_text = _get_diff(task.worktree_path)
    task.impact = analyze_impact(task.alert_json, diff_text,
                                 fix_context=plan.metadata or None)
    if task.impact.error:
        print(f"[WARN] {task.alert_id} impact analysis error: {task.impact.error}")

    # Commit + PR
    task.state = "COMMITTING"
    print(f"[PHASE] {task.alert_id} commit + open PR", flush=True)
    try:
        pr_url = _commit_and_pr(task, task.impact, dry_run)
    except RuntimeError as e:
        task.state = "FAILED"
        task.failure_reason = str(e)
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("fix_failed", p)
        return task

    task.pr_url = pr_url

    p = _notify_payload(task)
    p.repo = repo.name
    notifier.notify("committed", p)

    if pr_url:
        p = _notify_payload(task)
        p.repo = repo.name
        notifier.notify("pr_opened", p)

    task.state = "PR_OPENING"

    # Phase 4: Orca GitHub App check (post-PR) with retry
    if pr_url and CFG.orca_check.enabled:
        orca_cfg = CFG.orca_check
        for orca_attempt in range(orca_cfg.max_retries + 1):
            task.state = "VALIDATE_ORCA_CHECK"
            print(f"[PHASE] {task.alert_id} polling Orca check "
                  f"(attempt {orca_attempt + 1}/{orca_cfg.max_retries + 1})", flush=True)
            orca_val = orca_check_gate(
                pr_url,
                check_name=orca_cfg.check_name,
                timeout_sec=orca_cfg.timeout_sec,
                poll_interval=orca_cfg.poll_interval_sec,
                on_not_found=orca_cfg.on_not_found,
            )
            if orca_val.passed:
                if orca_val.needs_review:
                    task.needs_review = True
                break

            # Orca check failed — retry with feedback or handle per config
            if orca_attempt < orca_cfg.max_retries:
                orca_feedback = "\n".join(orca_val.failures)
                # A specialist may know a concrete alternative, which beats
                # telling the agent to think of something else.
                alt = _next_candidate_hint(task)
                if alt:
                    orca_feedback += f"\n\n{alt}"
                print(f"[RETRY] {task.alert_id} Orca check found issues, "
                      f"retrying fix (attempt {orca_attempt + 2})", flush=True)
                _revert(task.worktree_path)
                timeout = pipeline.timeout_sec
                fix_result = _invoke_fix_agent(task, dry_run, timeout,
                                               feedback=orca_feedback)
                if not fix_result.success:
                    task.state = "FAILED"
                    task.failure_reason = fix_result.failure_reason
                    p = _notify_payload(task)
                    p.repo = repo.name
                    notifier.notify("fix_failed", p)
                    return task
                task.fix_result = fix_result

                # Re-validate locally before pushing
                sanity2 = sanity_check(task.alert_json, task.worktree_path,
                                       feature_type=task.feature_type,
                                       diff_limit=pipeline.diff_limit,
                                       diff_summary=fix_result.diff_summary)
                if not sanity2.passed:
                    task.state = "FAILED"
                    task.failure_reason = "; ".join(sanity2.failures)
                    p = _notify_payload(task)
                    p.repo = repo.name
                    notifier.notify("validation_failed", p)
                    return task

                build2 = pipeline.verify(task, task.worktree_path, plan)
                if not build2.passed:
                    task.state = "FAILED"
                    task.failure_reason = "; ".join(build2.failures)
                    p = _notify_payload(task)
                    p.repo = repo.name
                    notifier.notify("validation_failed", p)
                    return task

                # Push updated fix to same PR branch
                try:
                    _push_fix_update(task)
                except RuntimeError as e:
                    task.state = "FAILED"
                    task.failure_reason = f"push fix update failed: {e}"
                    p = _notify_payload(task)
                    p.repo = repo.name
                    notifier.notify("fix_failed", p)
                    return task
                continue

            # All retries exhausted
            on_fail = orca_cfg.on_failure
            if on_fail == "skip":
                task.needs_review = True
                print(f"[WARN] {task.alert_id} Orca check failed, skipping per config",
                      flush=True)
                break
            else:
                # "fail" or default
                task.state = "FAILED"
                task.failure_reason = "; ".join(orca_val.failures)
                p = _notify_payload(task)
                p.repo = repo.name
                notifier.notify("validation_failed", p)
                return task

    # Phase 5: CI gate
    if pr_url:
        print(f"[PHASE] {task.alert_id} waiting for CI checks", flush=True)
        task.state = "VALIDATE_CI"
        ci = ci_gate(pr_url, timeout_sec=600)
        if not ci.passed:
            task.state = "CI_FAILED"
            task.failure_reason = "; ".join(ci.failures)
            r = subprocess.run(
                ["gh", "pr", "edit", pr_url, "--add-label", "ci-failed"],
                capture_output=True, text=True
            )
            if r.returncode != 0:
                print(f"[WARN] failed to add ci-failed label: {r.stderr[:200]}")
            p = _notify_payload(task)
            p.repo = repo.name
            notifier.notify("ci_failed", p)
        else:
            task.state = "DONE"
    else:
        task.state = "DONE"

    # Add needs-review label
    if task.needs_review and pr_url:
        r = subprocess.run(
            ["gh", "pr", "edit", pr_url, "--add-label", "needs-review"],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"[WARN] failed to add needs-review label: {r.stderr[:200]}")

    # Add impact label
    if task.impact and pr_url:
        r = subprocess.run(
            ["gh", "pr", "edit", pr_url, "--add-label", f"impact:{task.impact.level}"],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            print(f"[WARN] failed to add impact label: {r.stderr[:200]}")

    p = _notify_payload(task)
    p.repo = repo.name
    notifier.notify("fix_succeeded", p)
    return task


# ---------------------------------------------------------------------------
# Fetch and plan
# ---------------------------------------------------------------------------

def _detect_repo() -> Repository | None:
    """Auto-detect the current repo from git remote and return a Repository object."""
    try:
        stdout, _, _ = _run(["git", "remote", "get-url", "origin"], check=False)
        url = stdout.strip()
        for sep in ("github.com/", "github.com:"):
            if sep in url:
                name = url.split(sep)[-1].removesuffix(".git").strip("/")
                return Repository(name=name, url=url)
    except Exception:
        pass
    return None


def _fetch_and_plan(args, repo: Repository) -> tuple[list[AlertTask], list[dict], list[dict], list[dict]]:
    """Fetch alerts for a repo and partition them into fix/skip/scm/unfixable buckets.

    repo.clone_path: when set, passes --repo-dir to run_agent.py so git ops
                     (detect_repo, branch_exists_remote) run inside the clone.
    """
    cve_ids = getattr(args, "cve_ids", None) or []
    cmd = ["python3", _RUN_AGENT, "list-alerts", repo.name]
    if args.alert:
        cmd += ["--alert", args.alert]
    else:
        if args.filter_tokens:
            cmd += ["--filter", args.filter_tokens]
        for cve in cve_ids:
            cmd += ["--cve", cve]
        if args.max:
            cmd += ["--max", str(args.max)]
    cmd.append("--fixable-only")
    if repo.clone_path:
        cmd += ["--repo-dir", str(repo.clone_path)]

    stdout, _, _ = _run(cmd)
    data = json.loads(stdout)
    alerts = data.get("alerts", [])

    to_fix: list[AlertTask] = []
    skipped: list[dict] = []
    scm_posture: list[dict] = []
    unfixable: list[dict] = []

    for a in alerts:
        ft = a.get("feature_type", "")
        if ft == "scm_posture":
            scm_posture.append(a)
        elif not a.get("is_fixable"):
            unfixable.append(a)
        elif a.get("branch_exists"):
            skipped.append(a)
        else:
            stdout2, _, _ = _run(["python3", _RUN_AGENT, "get-alert", a["alert_id"]])
            full = json.loads(stdout2)
            to_fix.append(AlertTask(
                alert_id=a["alert_id"],
                title=a["title"],
                risk_level=a["risk_level"],
                feature_type=ft,
                source=a.get("source", ""),
                alert_json=full,
                requested_cves=list(cve_ids),
            ))

    return to_fix, skipped, scm_posture, unfixable


def _print_cve_elsewhere(cve_ids, current_repo):
    """On a CVE run that matched nothing, say where the CVE actually is.

    A bare "no alerts found" is a dead end when the user named a specific
    advisory: the useful next fact is whether it is open somewhere else. One
    extra query, only on the empty path, and a failure to answer is not worth
    turning into an error — the run already succeeded at finding nothing.
    """
    joined = ", ".join(cve_ids)
    try:
        elsewhere = [(name, n) for name, n in repos_with_cve(cve_ids, get_token())
                     if name != current_repo]
    except (RuntimeError, SystemExit):
        return
    if not elsewhere:
        print(f"\n{joined} is not open in any code repository Orca is scanning.")
        return
    total = sum(n for _, n in elsewhere)
    print(f"\n{joined} is open in {len(elsewhere)} other "
          f"{'repository' if len(elsewhere) == 1 else 'repositories'} "
          f"({total} alert{'s' if total != 1 else ''}):")
    for name, n in elsewhere:
        print(f"  {name}  ({n} alert{'s' if n != 1 else ''})")
    single = elsewhere[0][0] if len(elsewhere) == 1 else "all"
    print(f"\nTo fix it there:  security-engineer --cve {cve_ids[0]} "
          f"--remote {single}")


# ---------------------------------------------------------------------------
# Flag validation
# ---------------------------------------------------------------------------

def _validate_flags(args):
    """Reject invalid flag combinations. Called immediately after argparse."""
    if getattr(args, "cve_ids", None) and args.alert:
        sys.exit("Error: --cve and --alert cannot be combined. Both choose "
                 "which alerts to fix; pass one.")
    if not args.scan:
        return
    # --cve is deliberately absent from the rejections below: it narrows the
    # list, which is what scan mode is for. --dry-run, --alert and --max are
    # rejected because they are about *fixing*, which scan does not do.
    if args.dry_run:
        sys.exit("Error: --scan and --dry-run cannot be combined. "
                 "--scan already lists alerts without fixing.")
    if args.alert:
        sys.exit("Error: --scan and --alert cannot be combined. "
                 "To fix a single alert, drop --scan.")
    if args.max:
        sys.exit("Error: --scan and --max cannot be combined. "
                 "--scan lists all matching alerts.")


# ---------------------------------------------------------------------------
# Scan mode
# ---------------------------------------------------------------------------

_RISK_BADGE = {"critical": "\U0001f534", "high": "\U0001f7e0",
               "medium": "\U0001f7e1", "low": "\U0001f535",
               "informational": "\u26aa"}


def _print_scan_report(repo_name, alerts, cve_ids=None):
    """Print a risk report grouped by severity — no fixes, no git ops."""
    grouped = {lvl: [] for lvl in RISK_ORDER}
    for a in alerts:
        lvl = a["risk_level"] if a["risk_level"] in grouped else "informational"
        grouped[lvl].append(a)

    total = sum(len(v) for v in grouped.values())
    print(f"# Orca Alerts — {repo_name}")
    if cve_ids:
        print(f"\nFiltered to alerts carrying: **{', '.join(cve_ids)}**")
    print(f"\nTotal open/in-progress: **{total}**\n")

    print("| Risk Level | Count |")
    print("|---|---|")
    for lvl in RISK_ORDER:
        n = len(grouped[lvl])
        if n:
            print(f"| {_RISK_BADGE.get(lvl, '')} {lvl.capitalize()} | {n} |")

    for lvl in RISK_ORDER:
        items = grouped[lvl]
        if not items:
            continue
        print(f"\n## {_RISK_BADGE.get(lvl, '')} {lvl.capitalize()} ({len(items)})\n")
        # The advisory count only earns a column when the report was narrowed to
        # a CVE: that is when "this alert covers 41 of them" is the surprise.
        head = "| Alert ID | Title | Category | Score | Type |"
        rule = "|---|---|---|---|---|"
        print(head + (" Advisories |" if cve_ids else ""))
        print(rule + ("---|" if cve_ids else ""))
        for a in items:
            ftype = _resolve_feature_type(a)
            row = (f"| {a['alert_id']} | {a['title']} | {a['category']} | "
                   f"{a['score']} | {ftype} |")
            if cve_ids:
                row += f" {len(a.get('cve_ids') or [])} |"
            print(row)


def _run_scan(args):
    """Execute scan mode: fetch alerts and print risk report, then exit."""
    from run_agent import min_level_from_list, parse_filter

    levels, types, filter_cves = (parse_filter(args.filter_tokens)
                                  if args.filter_tokens else (None, None, None))
    min_level = min_level_from_list(levels)
    cve_ids = list(dict.fromkeys((getattr(args, "cve_ids", None) or [])
                                 + list(filter_cves or []))) or None
    token = get_token()

    if args.remote is not None:
        if args.remote == "all":
            repos = list_repositories(token)
            if not repos:
                sys.exit("No repositories found in Orca.")
            found = False
            for repo in repos:
                try:
                    alerts = fetch_alerts(repo.name, token, min_level=min_level,
                                          feature_types=types, cve_ids=cve_ids)
                except RuntimeError as e:
                    print(f"\nError fetching alerts for {repo.name}: {e}",
                          file=sys.stderr)
                    continue
                if alerts:
                    found = True
                    _print_scan_report(repo.name, alerts, cve_ids)
                    print()
            if not found and cve_ids:
                print(f"No open alert in any repository carries "
                      f"{', '.join(cve_ids)}.")
        elif "/" in args.remote:
            try:
                alerts = fetch_alerts(args.remote, token, min_level=min_level,
                                      feature_types=types, cve_ids=cve_ids)
            except RuntimeError as e:
                sys.exit(f"Error fetching alerts for {args.remote}: {e}")
            if not alerts:
                print(f"No alerts found for {args.remote}"
                      + (f" carrying {', '.join(cve_ids)}." if cve_ids else "."))
                if cve_ids:
                    _print_cve_elsewhere(cve_ids, args.remote)
                return
            _print_scan_report(args.remote, alerts, cve_ids)
        else:
            sys.exit("Error: --remote requires 'all' or 'owner/repo'")
    else:
        repo = _detect_repo()
        if not repo:
            sys.exit("Error: could not detect repo from git remote. "
                     "Run from inside a git repo or use --scan --remote owner/repo.")
        try:
            alerts = fetch_alerts(repo.name, token, min_level=min_level,
                                  feature_types=types, cve_ids=cve_ids)
        except RuntimeError as e:
            sys.exit(f"Error fetching alerts: {e}")
        if not alerts:
            print(f"No alerts found for {repo.name}"
                  + (f" carrying {', '.join(cve_ids)}." if cve_ids else "."))
            if cve_ids:
                _print_cve_elsewhere(cve_ids, repo.name)
            return
        _print_scan_report(repo.name, alerts, cve_ids)


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def _print_plan(to_fix, skipped, scm_posture, unfixable, repo, dry_run,
                cve_ids=None):
    mode = "DRY-RUN" if dry_run else "LIVE"
    total = len(to_fix) + len(skipped) + len(scm_posture) + len(unfixable)
    print(f"\nRepository: {repo}  |  Mode: {mode}")
    if cve_ids:
        print(f"CVE filter: {', '.join(cve_ids)}")
    print(f"\nFound {total} alerts:")
    print(f"  ✓  {len(to_fix)} to fix")
    print(f"  ⟳  {len(skipped)} skipped (branch exists)")
    print(f"  ℹ  {len(scm_posture)} scm_posture (manual action)")
    print(f"  ✗  {len(unfixable)} other unfixable")
    if to_fix:
        print("\nPlanned fixes:")
        for i, t in enumerate(to_fix, 1):
            print(f"  {i}. {t.alert_id} — {t.title} ({t.risk_level}, {t.feature_type}) — {t.source}")
            # A package alert covers every advisory in its package, and the
            # minimum-safe bump clears all of them. Say so before the run, not
            # in the PR body afterwards.
            covered = len(t.alert_json.get("cve_ids") or []) if t.alert_json else 0
            if cve_ids and covered > 1:
                print(f"       covers {covered} advisories in total — the bump "
                      f"clears all of them, not just {cve_ids[0]}")


def exit_code_for(tasks: list[AlertTask]) -> int:
    """Process exit code for a set of finished alerts: 0 clean, 1 if any failed.

    The run used to exit 0 even when the summary printed "Fix Failed (1)", so
    any CI wrapper or `&&` chain read a broken run as green. CI_FAILED counts as
    a failure too — the PR exists, but its checks are red, which is not success.
    Skipped alerts are not failures; nothing was attempted.
    """
    return 1 if any(t.state in ("FAILED", "TIMED_OUT", "CI_FAILED") for t in tasks) else 0


def _print_summary(tasks: list[AlertTask], skipped: list[dict], scm_posture: list[dict],
                   repo: str, dry_run: bool):
    mode = "DRY-RUN" if dry_run else "Live"
    print("\n## Security Engineer — Run Summary")
    print(f"\n**Repo:** {repo}  |  **Mode:** {mode}\n")

    done = [t for t in tasks if t.state in ("DONE", "CI_FAILED")]
    failed = [t for t in tasks if t.state in ("FAILED", "TIMED_OUT")]
    all_skipped = [t for t in tasks if t.state == "SKIPPED"] + skipped

    if done:
        print(f"### Fixed — PRs Opened ({len(done)})")
        print("| Alert | Title | Risk | Type | Impact | PR |")
        print("|---|---|---|---|---|---|")
        for t in done:
            impact = t.impact.level if t.impact else "-"
            ci_note = " ⚠️" if t.state == "CI_FAILED" else ""
            review_note = " 👁" if t.needs_review else ""
            print(f"| {t.alert_id} | {t.title} | {t.risk_level} | {t.feature_type} "
                  f"| {impact}{ci_note}{review_note} | {t.pr_url or '-'} |")

    if failed:
        print(f"\n### Fix Failed ({len(failed)})")
        print("| Alert | State | Reason |")
        print("|---|---|---|")
        for t in failed:
            print(f"| {t.alert_id} | {t.state} | {t.failure_reason or '-'} |")

    if all_skipped:
        print(f"\n### Skipped — Branch Exists ({len(all_skipped)})")
        print("| Alert | Title |")
        print("|---|---|")
        for item in all_skipped:
            if isinstance(item, AlertTask):
                print(f"| {item.alert_id} | {item.title} |")
            else:
                print(f"| {item.get('alert_id', '-')} | {item.get('title', '-')} |")

    if scm_posture:
        print(f"\n### SCM Posture — Manual Action Required ({len(scm_posture)})")
        print("| Alert | Title | Risk |")
        print("|---|---|---|")
        for a in scm_posture:
            print(f"| {a['alert_id']} | {a['title']} | {a['risk_level']} |")


# ---------------------------------------------------------------------------
# Multi-repo pipeline
# ---------------------------------------------------------------------------

def _clone_repo(repo: Repository) -> Repository:
    """Shallow-clone a GitHub repo into /tmp. Fills repo.clone_path in-place."""
    safe = repo.name.replace("/", "-")
    path = Path(f"/tmp/orca-global-{safe}")
    if path.exists():
        shutil.rmtree(path)
    _run(["gh", "repo", "clone", repo.url, str(path), "--", "--depth=1"])
    repo.clone_path = path
    return repo


def _repo_notif(repo: Repository) -> NotificationPayload:
    """Bare payload for repo-level events (no alert context)."""
    return NotificationPayload(event="", alert_id="", feature_type="", risk_level="", repo=repo.name)


def _run_repo_pipeline(repo: Repository, args) -> dict:
    """Clone a repo, run the full fix pipeline against it, clean up the clone.

    Returns a dict with keys: results, skipped, scm_posture, unfixable, error.
    """
    notifier = build_notifiers(repo.name, Path.cwd())

    p = _repo_notif(repo)
    notifier.notify("clone_started", p)
    try:
        _clone_repo(repo)
    except RuntimeError as e:
        p = _repo_notif(repo)
        p.reason = str(e)
        notifier.notify("clone_failed", p)
        return {"results": [], "skipped": [], "scm_posture": [], "unfixable": [],
                "error": f"clone failed: {e}"}

    p = _repo_notif(repo)
    p.detail = str(repo.clone_path)
    notifier.notify("clone_succeeded", p)

    try:
        local_args = copy.copy(args)
        local_args.repo = repo.name  # ensure filter uses this repo, not auto-detect

        to_fix, skipped, scm_posture, unfixable = _fetch_and_plan(local_args, repo)

        p = _repo_notif(repo)
        p.detail = f"{len(to_fix)} to fix, {len(skipped)} skipped, {len(unfixable)} unfixable"
        notifier.notify("alerts_fetched", p)

        _print_plan(to_fix, skipped, scm_posture, unfixable, repo.name,
                    args.dry_run, getattr(args, "cve_ids", None))

        results: list[AlertTask] = []
        if to_fix:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {
                    pool.submit(run_one, task, args.dry_run, notifier, repo): task
                    for task in to_fix
                }
                for future in as_completed(futures):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        task = futures[future]
                        task.state = "FAILED"
                        task.failure_reason = str(e)
                        results.append(task)

        return {"results": results, "skipped": skipped,
                "scm_posture": scm_posture, "unfixable": unfixable, "error": None}
    finally:
        if repo.clone_path and repo.clone_path.exists():
            shutil.rmtree(repo.clone_path, ignore_errors=True)
            repo.clone_path = None


def _print_global_summary(all_results: dict, dry_run: bool = False) -> None:
    """Print a per-repo breakdown and aggregate totals for --all-repos runs."""
    total_done = total_failed = total_skipped = 0

    print("\n## Security Engineer — Global Run Summary\n")
    for repo_name, data in sorted(all_results.items()):
        if data.get("error"):
            print(f"### {repo_name} — ERROR: {data['error']}")
            continue
        results = data.get("results", [])
        skipped = data.get("skipped", [])
        scm = data.get("scm_posture", [])
        _print_summary(results, skipped, scm, repo_name, dry_run)
        done = sum(1 for t in results if t.state in ("DONE", "CI_FAILED"))
        failed = sum(1 for t in results if t.state in ("FAILED", "TIMED_OUT"))
        total_done += done
        total_failed += failed
        total_skipped += len(skipped)

    print(f"\n---\n**Totals** — Fixed: {total_done}  |  Failed: {total_failed}  |  Skipped: {total_skipped}")


def _get_repo_url(repo_name: str) -> str:
    """Resolve the clone URL for an owner/repo via gh CLI."""
    stdout, _, _ = _run(["gh", "repo", "view", repo_name, "--json", "url", "--jq", ".url"])
    return stdout.strip()


def run_all_repos(args) -> int:
    """Discover all repos with open Orca alerts and run the fix pipeline on each.

    Returns a process exit code: non-zero if any repo errored or any alert failed.
    """
    token = get_token()
    repos = list_repositories(token)
    if not repos:
        print("No repositories with open alerts found in Orca.")
        return 0

    mode = "DRY-RUN" if args.dry_run else "LIVE"
    print(f"\nFound {len(repos)} repositories with open alerts. Mode: {mode}")
    print(f"Processing up to {REPO_WORKERS} repos concurrently "
          f"(up to {REPO_WORKERS * MAX_WORKERS} parallel fix agents).\n")
    for r in repos:
        print(f"  {r.name}  [{r.risk_level or 'unknown'}]  {r.url}")

    all_results: dict = {}
    with ThreadPoolExecutor(max_workers=REPO_WORKERS) as executor:
        futures = {
            executor.submit(_run_repo_pipeline, r, args): r
            for r in repos
        }
        for future in as_completed(futures):
            r = futures[future]
            try:
                all_results[r.name] = future.result()
            except Exception as e:
                all_results[r.name] = {
                    "results": [], "skipped": [], "scm_posture": [], "unfixable": [],
                    "error": str(e),
                }

    _print_global_summary(all_results, dry_run=args.dry_run)

    if any(d.get("error") for d in all_results.values()):
        return 1
    return max((exit_code_for(d.get("results", [])) for d in all_results.values()),
               default=0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="Security Engineer Orchestrator")
    parser.add_argument("--scan", action="store_true",
                        help="List alerts without fixing (risk report)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Plan only — fix agents read files but cannot edit")
    parser.add_argument("--remote", default=None, metavar="REPO",
                        help="Clone and fix: 'all' for all Orca repos, 'owner/repo' for one")
    parser.add_argument("--alert", default=None,
                        help="Target a single alert ID")
    parser.add_argument("--cve", action="append", default=None, dest="cve",
                        help="Only alerts carrying this advisory id, e.g. "
                             "CVE-2020-7471 (repeatable, or comma-separated)")
    parser.add_argument("--max", type=int, default=None,
                        help="Cap number of fixes")
    parser.add_argument("positional", nargs="*",
                        help="[filter_tokens] e.g. 'high,sast', 'cve', or an "
                             "advisory id such as 'CVE-2020-7471'")
    args = parser.parse_args(argv)

    # Canonicalize here, at the CLI boundary, and not only inside
    # fetch_alert_by_id: the raw value also reaches the plan table, the worktree
    # path and the notifier, so an ID typed as "alert-192901290" would otherwise
    # be reported back under a name Orca never uses.
    args.alert = normalize_alert_id(args.alert)

    # Same boundary, same reason: the advisory id reaches the plan header, the
    # fix directive and the PR body, not only the query.
    from run_agent import parse_cve_args, parse_filter
    args.cve_ids = parse_cve_args(args.cve)

    # All positional tokens are filter tokens — repo is always auto-detected from git remote
    args.repo = None
    args.filter_tokens = None
    for p in args.positional:
        args.filter_tokens = p

    # A bare `security-engineer CVE-2020-7471` arrives as a positional. It is a
    # selector, not a severity, and dropping it would silently widen the run to
    # every open alert — so it is promoted here rather than warned about later.
    if args.filter_tokens:
        _, _, positional_cves = parse_filter(args.filter_tokens)
        if positional_cves:
            args.cve_ids = list(dict.fromkeys(args.cve_ids + positional_cves))

    _validate_flags(args)

    # --scan: risk report only, no fixes
    if args.scan:
        _run_scan(args)
        return

    # --remote: clone-based pipeline (single repo or all Orca repos)
    if args.remote is not None:
        if args.dry_run:
            print("Mode: DRY-RUN — fix agents will read files and plan fixes, cannot edit.")
        if args.remote == "all":
            return run_all_repos(args)
        elif "/" in args.remote:
            try:
                url = _get_repo_url(args.remote)
            except RuntimeError as e:
                sys.exit(f"Error: could not resolve URL for {args.remote}: {e}")
            repo = Repository(name=args.remote, url=url)
            data = _run_repo_pipeline(repo, args)
            if data.get("error"):
                sys.exit(f"Pipeline failed: {data['error']}")
            _print_summary(data["results"], data["skipped"], data["scm_posture"],
                           args.remote, args.dry_run)
            return exit_code_for(data["results"])
        else:
            sys.exit("Error: --remote requires 'all' or 'owner/repo'")

    # Local mode — repo always auto-detected from git remote origin
    repo = _detect_repo()
    if not repo:
        sys.exit("Error: could not detect repo from git remote. "
                 "Run from inside a git repo or use --remote owner/repo.")

    notifier = build_notifiers(repo.name, Path.cwd())

    if args.dry_run:
        print("Mode: DRY-RUN — fix agents will read files and plan fixes, cannot edit.")

    # A missing token or an Orca API outage is a setup problem, not a crash. The
    # remote paths already exit with a message; local raised a bare traceback,
    # which is a poor first thing to show someone who reached this by asking in
    # plain English.
    try:
        to_fix, skipped, scm_posture, unfixable = _fetch_and_plan(args, repo)
    except RuntimeError as e:
        sys.exit(f"Error: could not fetch alerts for {repo.name}: {e}")

    _print_plan(to_fix, skipped, scm_posture, unfixable, repo.name, args.dry_run,
                args.cve_ids)

    if not to_fix:
        if args.cve_ids and not (skipped or scm_posture or unfixable):
            _print_cve_elsewhere(args.cve_ids, repo.name)
        notifier.notify("run_complete", NotificationPayload(
            event="run_complete", alert_id="-", feature_type="-", risk_level="-",
            repo=repo.name, succeeded=0, failed=0, skipped=len(skipped),
        ))
        return 0

    results: list[AlertTask] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(run_one, task, args.dry_run, notifier, repo): task
            for task in to_fix
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                task = futures[future]
                task.state = "FAILED"
                task.failure_reason = str(e)
                results.append(task)

    _print_summary(results, skipped, scm_posture, repo.name, args.dry_run)

    succeeded = sum(1 for t in results if t.state in ("DONE", "CI_FAILED"))
    failed = sum(1 for t in results if t.state in ("FAILED", "TIMED_OUT"))
    notifier.notify("run_complete", NotificationPayload(
        event="run_complete", alert_id="-", feature_type="-", risk_level="-",
        repo=repo.name, succeeded=succeeded, failed=failed, skipped=len(skipped),
    ))
    return exit_code_for(results)


if __name__ == "__main__":
    sys.exit(main())
