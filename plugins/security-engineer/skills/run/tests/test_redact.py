#!/usr/bin/env python3
"""
Tests for credential redaction on egress (skills/run/redact.py) and its wiring.

The property under protection is narrow and absolute: for a secret finding, no
path that leaves this process carries the credential. "Leaves" means the two
model prompts, the PR title and body, and the notification payload that reaches
the run log and the webhook.

The commit diff is the deliberate exception — a commit that removes a line
renders that line — so the tests assert the PR body carries the rotation warning
instead, which is what makes the residue honest.

The second property is the inverse, and it is just as load-bearing: a non-secret
finding must be redacted *not at all*, or gate 2 would be judging a diff with its
subject blanked out.

Hermetic: no network, no claude subprocess.

Run with: python3 tests/test_redact.py
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))                 # skills/run/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # skills/lib/

import impact_agent
import orchestrator
import validator
from redact import PLACEHOLDER, Redactor, build_redactor

# A deliberately fake credential. redact.py only needs a value of length >= 6;
# this one wears the `sk-live-` shape on purpose, because the fixture has to look
# like the thing the redactor is being tested against. It is not a real key and
# has never been valid anywhere.
# orca-secrets ignore-line
SECRET = "sk-live-9f3a2b7c1d8e4f6a0b2c"

SECRET_ALERT = {
    "alert_id": "orca-abc123",
    "feature_type": "secret",
    "category": "Secrets",
    "code_snippet": [f'API_KEY = "{SECRET}"'],
    "description": "Hardcoded API key",
}

CVE_ALERT = {
    "alert_id": "orca-def456",
    "feature_type": "",
    "category": "Vulnerabilities",
    "code_snippet": ["pillow==8.3.1"],
}


class TestCandidateExtraction(unittest.TestCase):
    def test_assignment_value_is_a_candidate(self):
        self.assertIn(SECRET, build_redactor(SECRET_ALERT).candidates)

    def test_key_is_never_a_candidate(self):
        """The env var name is what the PR must tell an operator to set."""
        self.assertNotIn("API_KEY", build_redactor(SECRET_ALERT).candidates)

    def test_whole_line_is_a_candidate(self):
        """The form a unified diff actually contains."""
        self.assertIn(f'API_KEY = "{SECRET}"', build_redactor(SECRET_ALERT).candidates)

    def test_bare_env_assignment(self):
        """.env and Dockerfile ENV lines have no quotes to anchor on."""
        alert = dict(SECRET_ALERT, code_snippet=[f"API_KEY={SECRET}"])
        self.assertIn(SECRET, build_redactor(alert).candidates)

    def test_candidates_are_longest_first(self):
        lengths = [len(c) for c in build_redactor(SECRET_ALERT).candidates]
        self.assertEqual(lengths, sorted(lengths, reverse=True))

    def test_short_values_are_not_candidates(self):
        """Below the floor a candidate matches prose, not a credential."""
        alert = dict(SECRET_ALERT, code_snippet=['x = "ab"'])
        self.assertNotIn("ab", build_redactor(alert).candidates)

    def test_non_secret_alert_gets_null_redactor(self):
        r = build_redactor(CVE_ALERT)
        self.assertFalse(r)
        self.assertEqual(r("pillow==8.3.1 is vulnerable"), "pillow==8.3.1 is vulnerable")

    def test_none_alert_is_safe(self):
        self.assertFalse(build_redactor(None))


class TestRedactor(unittest.TestCase):
    def setUp(self):
        self.r = build_redactor(SECRET_ALERT)

    def test_value_scrubbed_from_prose(self):
        out = self.r(f"The key {SECRET} should be rotated")
        self.assertNotIn(SECRET, out)
        self.assertIn(PLACEHOLDER, out)

    def test_diff_line_scrubbed(self):
        out = self.r(f'-API_KEY = "{SECRET}"\n+API_KEY = os.environ["API_KEY"]')
        self.assertNotIn(SECRET, out)
        self.assertIn("os.environ", out, "the fix side must survive")

    def test_scrub_recurses_into_lists_and_dicts(self):
        out = Redactor([SECRET]).scrub({"steps": [f"rotate {SECRET}"], "n": 3})
        self.assertNotIn(SECRET, str(out))
        self.assertEqual(out["n"], 3, "non-strings pass through unchanged")

    def test_non_string_passes_through(self):
        self.assertIsNone(self.r(None))
        self.assertEqual(self.r(7), 7)


class TestSanityGateRunsForEveryType(unittest.TestCase):
    """A CVE or SAST fix that introduces a credential must fail gate 1 too."""

    def _run(self, feature_type, diff):
        with patch.object(validator, "worktree_diff", return_value=diff):
            return validator.sanity_check({}, Path("/tmp/x"), feature_type=feature_type)

    def test_cve_fix_adding_a_secret_fails(self):
        diff = '+++ b/app.py\n+password = "hunter2hunter2"\n'
        self.assertFalse(self._run("cve", diff).passed)

    def test_sast_fix_adding_a_secret_fails(self):
        diff = "+++ b/app.py\n+token = 'abcdefghijklmnop'\n"
        self.assertFalse(self._run("sast", diff).passed)

    def test_clean_cve_diff_still_passes(self):
        self.assertTrue(self._run("cve", "+++ b/req.txt\n+pillow==11.3.0\n").passed)


class TestModelPromptsAreScrubbed(unittest.TestCase):
    """Neither model subprocess may receive the credential."""

    def test_llm_validate_prompt(self):
        diff = f'-API_KEY = "{SECRET}"\n'
        with patch.object(validator, "worktree_diff", return_value=diff), \
             patch.object(validator.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"verdict": "pass"}'
            validator.llm_validate(SECRET_ALERT, Path("/tmp/x"))
        prompt = run.call_args.kwargs["input"]
        self.assertNotIn(SECRET, prompt)

    def test_impact_prompt(self):
        with patch.object(impact_agent.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"level": "low", "description": "ok"}'
            impact_agent.analyze_impact(SECRET_ALERT, f'-API_KEY = "{SECRET}"\n')
        prompt = run.call_args.kwargs["input"]
        self.assertNotIn(SECRET, prompt)

    def test_model_prose_is_scrubbed_on_the_way_back(self):
        """A model asked to explain the risk will name the credential."""
        raw = f'{{"level": "high", "description": "removes {SECRET}", "concerns": ["{SECRET} is live"]}}'
        with patch.object(impact_agent.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = raw
            result = impact_agent.analyze_impact(SECRET_ALERT, "diff")
        self.assertNotIn(SECRET, result.description)
        self.assertNotIn(SECRET, " ".join(result.concerns))

    def test_validator_reason_is_scrubbed(self):
        raw = f'{{"verdict": "fail", "reason": "still contains {SECRET}"}}'
        with patch.object(validator, "worktree_diff", return_value="d"), \
             patch.object(validator.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = raw
            result = validator.llm_validate(SECRET_ALERT, Path("/tmp/x"))
        self.assertNotIn(SECRET, " ".join(result.failures))

    def test_cve_diff_reaches_the_model_intact(self):
        """The inverse property: gate 2 must still see a non-secret diff."""
        diff = "+pillow==11.3.0\n"
        with patch.object(validator, "worktree_diff", return_value=diff), \
             patch.object(validator.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = '{"verdict": "pass"}'
            validator.llm_validate(CVE_ALERT, Path("/tmp/x"))
        self.assertIn("pillow==11.3.0", run.call_args.kwargs["input"])


class TestPullRequestBody(unittest.TestCase):
    """The PR is the one place the credential survives — so it must say so."""

    def _open_pr(self, alert, feature_type, impact=None, diff_summary="removed the key"):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="Hardcoded secret", risk_level="high",
            feature_type=feature_type, source="app.py:14",
            alert_json=alert, worktree_path=Path("/tmp/x"),
        )
        # files_changed is what _commit_and_pr stages by name, so a task without
        # it is not one the pipeline could ever produce.
        task.fix_result = orchestrator.FixAgentResult(
            success=True, diff_summary=diff_summary, files_changed=["app.py"])
        with patch("orchestrator._run",
                   return_value=("https://github.com/o/r/pull/1", "", 0)) as run:
            orchestrator._commit_and_pr(task, impact=impact, dry_run=False)
        argv = run.call_args_list[-1][0][0]
        return argv[argv.index("--body") + 1]

    def test_secret_pr_carries_the_rotation_warning(self):
        body = self._open_pr(SECRET_ALERT, "secret")
        self.assertIn("does not remediate", body)
        self.assertIn("Rotate the credential first", body)
        self.assertIn("git history", body)

    def test_warning_is_the_first_thing_in_the_body(self):
        body = self._open_pr(SECRET_ALERT, "secret")
        self.assertTrue(body.startswith("> [!WARNING]"), body[:40])

    def test_secret_value_never_reaches_the_body(self):
        impact = impact_agent.ImpactResult(
            level="high", description=f"drops {SECRET}", downtime_risk=False,
            requires_deploy=True, concerns=[f"{SECRET} is live"],
        )
        body = self._open_pr(SECRET_ALERT, "secret", impact=impact,
                             diff_summary=f'removed API_KEY = "{SECRET}"')
        self.assertNotIn(SECRET, body)

    def test_commit_message_is_scrubbed(self):
        """A commit message is permanent, so it gets the same treatment."""
        alert = dict(SECRET_ALERT, code_snippet=[f'KEY = "{SECRET}"'])
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title=f'leaked {SECRET}', risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=alert, worktree_path=Path("/tmp/x"),
        )
        task.fix_result = orchestrator.FixAgentResult(
            success=True, diff_summary="x", files_changed=["app.py"])
        with patch("orchestrator._run",
                   return_value=("https://github.com/o/r/pull/1", "", 0)) as run:
            orchestrator._commit_and_pr(task, impact=None, dry_run=False)
        commit_argv = run.call_args_list[0][0][0]
        self.assertNotIn(SECRET, " ".join(commit_argv))

    def test_cve_pr_has_no_warning(self):
        body = self._open_pr(CVE_ALERT, "cve")
        self.assertNotIn("does not remediate", body)


class TestRotationStep(unittest.TestCase):

    def _impact(self, steps):
        return impact_agent.ImpactResult(
            level="low", description="", downtime_risk=False,
            requires_deploy=False, manual_steps=list(steps),
        )

    def test_rotation_is_prepended_for_secrets(self):
        out = orchestrator._with_rotation_step(self._impact(["Redeploy"]), "secret")
        self.assertIn("Rotate", out.manual_steps[0])
        self.assertEqual(out.manual_steps[1], "Redeploy")

    def test_not_duplicated_when_the_model_already_said_it(self):
        out = orchestrator._with_rotation_step(
            self._impact(["Rotate the credential immediately"]), "secret")
        self.assertEqual(len(out.manual_steps), 1)

    def test_other_types_untouched(self):
        out = orchestrator._with_rotation_step(self._impact(["Redeploy"]), "cve")
        self.assertEqual(out.manual_steps, ["Redeploy"])

    def test_none_impact_is_safe(self):
        self.assertIsNone(orchestrator._with_rotation_step(None, "secret"))


class TestNotificationPayload(unittest.TestCase):
    """One chokepoint feeding the console, the run log and the webhook."""

    def _payload(self, alert, **task_kw):
        task = orchestrator.AlertTask(
            alert_id="orca-abc123", title="t", risk_level="high",
            feature_type="secret", source="app.py:14",
            alert_json=alert, worktree_path=Path("/tmp/x"), **task_kw)
        return orchestrator._notify_payload(task)

    def test_failure_reason_is_scrubbed(self):
        p = self._payload(SECRET_ALERT, failure_reason=f"could not remove {SECRET}")
        self.assertNotIn(SECRET, p.reason)

    def test_impact_fields_are_scrubbed(self):
        task = orchestrator.AlertTask(
            alert_id="a", title="t", risk_level="high", feature_type="secret",
            source="app.py:14", alert_json=SECRET_ALERT, worktree_path=Path("/tmp/x"))
        task.impact = impact_agent.ImpactResult(
            level="high", description="d", downtime_risk=False, requires_deploy=True,
            manual_steps=[f"rotate {SECRET}"], concerns=[f"{SECRET} live"],
            error=f"failed on {SECRET}")
        p = orchestrator._notify_payload(task)
        self.assertNotIn(SECRET, " ".join(p.manual_steps))
        self.assertNotIn(SECRET, " ".join(p.concerns))
        self.assertNotIn(SECRET, p.error_detail)

    def test_none_reason_survives(self):
        self.assertIsNone(self._payload(SECRET_ALERT).reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
