#!/usr/bin/env python3
"""
Impact analysis agent — invokes Claude to analyze a security fix diff
and produce a structured production risk assessment.

Not a lookup table. Claude reads the actual diff and alert context.
"""
import json
import subprocess
from dataclasses import dataclass, field

from _json_util import find_last_json_with_key
from validator import (
    _SINGLE_SHOT_CONTRACT,
    _SINGLE_SHOT_MAX_TURNS,
    _SINGLE_SHOT_TOOL_FLAGS,
    _subprocess_error_detail,
)


@dataclass
class ImpactResult:
    level: str                        # "low" | "medium" | "high"
    description: str
    downtime_risk: bool
    requires_deploy: bool
    manual_steps: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)
    error: str | None = None


_PROMPT = """\
You are assessing the production risk of a security fix before it is deployed.

## Alert Details
{alert_json}
{fix_context}
## Git Diff
```diff
{diff_text}
```

Analyze the diff in the context of the vulnerability and answer:
1. What is the production risk of deploying this change?
2. Is there a risk of downtime or service disruption?
3. Does this require a redeployment or infrastructure action after merge?
4. What manual steps must an operator take before or after deploying?
5. Are there concerns a code reviewer should know?

Guidelines:
- "low"   → code logic change only, no infra impact, no redeploy needed
- "medium" → rebuild/redeploy required, dep version bump, possible brief disruption
- "high"  → secret rotation required, env var must be set before deploy, significant breaking risk

{contract}
Return ONLY this JSON, with nothing before or after it:
{{
  "level": "low|medium|high",
  "description": "<one sentence: what is the production risk>",
  "downtime_risk": true|false,
  "requires_deploy": true|false,
  "manual_steps": ["step 1", "step 2"],
  "concerns": ["optional reviewer concern"]
}}
"""


def _render_fix_context(fix_context: dict | None) -> str:
    """Ground-truth facts about the fix, for the prompt.

    Without this the assessment is inferred from the diff plus the fix agent's
    own prose, and the prose can be wrong: one sandbox PR bumped pillow to
    12.3.0 while its summary said 11.3.0, and the same diff scored medium once
    and high twice across three runs. A resolved bump distance is a fact, so
    stating it removes the guesswork rather than adding to it.
    """
    if not fix_context:
        return ""
    decision = fix_context.get("version_decision") or {}
    ref = fix_context.get("package_ref") or {}
    if not decision.get("target_version"):
        return ""

    lines = ["", "## Fix Context (resolved from advisory data, not inferred)", ""]
    lines.append(f"- Package: {ref.get('package')} ({ref.get('ecosystem')})")
    lines.append(f"- Version: {decision.get('current_version')} → "
                 f"{decision.get('target_version')}")
    span = decision.get("bump_class", "unknown")
    majors = decision.get("majors_crossed") or 0
    if majors > 1:
        span += f", crossing {majors} major versions"
    lines.append(f"- Bump: {span}")
    if not ref.get("exact_pin", True):
        lines.append("- The previous pin was a version range, so the installed "
                     "version was inferred rather than read exactly")

    cleared = decision.get("advisories_cleared") or []
    if cleared:
        shown = ", ".join(cleared[:8])
        more = f" (+{len(cleared) - 8} more)" if len(cleared) > 8 else ""
        lines.append(f"- Advisories cleared: {shown}{more}")
    remaining = decision.get("advisories_remaining") or []
    if remaining:
        lines.append(f"- Still affected after this bump: {', '.join(remaining)}")
    unknown = decision.get("advisories_unknown_scope") or []
    if unknown:
        lines.append(f"- Could not be assessed (no version range in the "
                     f"advisory): {', '.join(unknown)}")
    others = [c.get("version") for c in (decision.get("candidates") or [])
              if c.get("version") != decision.get("target_version")]
    # Hoisted out of the f-string rather than inlined: a line break inside a
    # replacement field is Python 3.12+ syntax (PEP 701), and this module has to
    # import on the 3.10 floor README.md advertises.
    alternatives = ", ".join(others) if others else (
        "none — this is the only published version that clears them")
    lines.append(f"- Other safe versions available: {alternatives}")
    lines.append("")
    lines.append("Weigh the bump distance when judging risk: a major-version jump "
                 "can remove public APIs and raise language or runtime floors, "
                 "even though the diff itself is one line.")
    lines.append("")
    return "\n".join(lines)


def analyze_impact(
    alert_json: dict,
    diff_text: str,
    timeout_sec: int = 120,
    fix_context: dict | None = None,
) -> ImpactResult:
    """Invoke claude subprocess to assess production impact. Returns ImpactResult.

    fix_context: a specialist's FixPlan.metadata, when the type produced one.
                 Facts the model would otherwise have to infer from the diff.
    """
    prompt = _PROMPT.format(
        alert_json=json.dumps(alert_json, indent=2),
        diff_text=diff_text[:6000],
        fix_context=_render_fix_context(fix_context),
        contract=_SINGLE_SHOT_CONTRACT,
    )
    # No tools at all — see _SINGLE_SHOT_TOOL_FLAGS for why denying them was
    # not the same thing, and cost 6x more.
    cmd = [
        "claude", "-p", prompt,
        *_SINGLE_SHOT_TOOL_FLAGS,
        "--output-format", "json",
        "--max-turns", str(_SINGLE_SHOT_MAX_TURNS),
    ]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_sec
        )
    except subprocess.TimeoutExpired:
        print(f"[WARN] impact analysis timed out after {timeout_sec}s")
        return ImpactResult(
            level="medium",
            description="Impact analysis timed out — treating as medium risk",
            downtime_risk=False, requires_deploy=True,
            error=f"timeout after {timeout_sec}s",
        )

    if result.returncode != 0:
        # claude reports its own failures on stdout, not stderr — see
        # _subprocess_error_detail. Logging stderr alone printed an empty string.
        detail = _subprocess_error_detail(result)
        print(f"[WARN] impact analysis failed (exit={result.returncode}): {detail}")
        return ImpactResult(
            level="medium",
            description="Impact analysis failed — treating as medium risk",
            downtime_risk=False, requires_deploy=True,
            error=f"exit_code={result.returncode}: {detail}",
        )

    return _parse(result.stdout)


def _parse(raw: str) -> ImpactResult:
    try:
        envelope = json.loads(raw)
        text = envelope.get("result", "") or raw
    except json.JSONDecodeError:
        text = raw

    data = find_last_json_with_key(text, "level")
    if not data:
        snippet = text[:200] if text else "(empty)"
        print(f"[WARN] could not parse impact analysis output: {snippet}")
        return ImpactResult(
            level="medium",
            description="Could not parse impact analysis — treating as medium risk",
            downtime_risk=False, requires_deploy=True,
            error=f"no_json_output: {snippet}",
        )

    return ImpactResult(
        level=data.get("level", "medium"),
        description=data.get("description", ""),
        downtime_risk=bool(data.get("downtime_risk", False)),
        requires_deploy=bool(data.get("requires_deploy", True)),
        manual_steps=data.get("manual_steps") or [],
        concerns=data.get("concerns") or [],
    )
