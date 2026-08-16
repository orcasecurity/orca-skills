#!/usr/bin/env python3
"""
The per-finding-type seam in the fix pipeline.

`_run_pipeline` used to hold every type's quirks inline, with the only
per-type knobs being two module-level dicts (`TIMEOUTS`, `_DIFF_LIMITS`) far
away from the code that cared. A pipeline object collects them in one place and
adds two hooks around the fix agent:

  prepare()  before the agent runs — work out anything the agent should be told
             rather than left to decide
  verify()   after the agent runs — check the thing that actually matters for
             this type, which is not the same check for a manifest bump as for
             a rewritten SQL query

Specializing a type means adding a pipeline, not editing the orchestrator.
"""
from dataclasses import dataclass, field
from pathlib import Path

from validator import ValidationResult, local_build_check


@dataclass
class FixPlan:
    """What a specialist worked out before the fix agent was invoked.

    prompt_extra is appended to the fix prompt, so a pipeline can turn "figure
    out what to do" into "do this". metadata travels on to impact analysis and
    the PR body, which is how a decision made here becomes reviewable later.
    """
    summary: str = ""
    prompt_extra: str = ""
    metadata: dict = field(default_factory=dict)
    needs_review: bool = False
    error: str | None = None

    @property
    def prepared(self) -> bool:
        return self.error is None and bool(self.prompt_extra or self.metadata)


class FixPipeline:
    """Default behaviour: exactly what the pipeline did before this existed.

    Subclasses override `prepare` and `verify`. The base class is not abstract on
    purpose — sast, iac and secret genuinely have nothing to prepare yet, and a
    no-op base keeps them on the old path byte for byte until someone
    specializes them.
    """

    feature_type = "generic"

    def __init__(self, feature_type: str = "generic", timeout_sec: int = 180,
                 diff_limit: int = 50):
        self.feature_type = feature_type
        self.timeout_sec = timeout_sec
        self.diff_limit = diff_limit

    def prepare(self, task, worktree_path: Path) -> FixPlan:
        """Nothing to work out ahead of time."""
        return FixPlan()

    def verify(self, task, worktree_path: Path,
               plan: FixPlan | None = None) -> ValidationResult:
        """Language-appropriate build check — the pre-existing Phase 3."""
        alert = task.alert_json or {}
        files = task.fix_result.files_changed if task.fix_result else []
        return local_build_check(
            files, worktree_path,
            source_file=alert.get("file_path") or alert.get("source", ""),
        )
