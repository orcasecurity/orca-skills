#!/usr/bin/env python3
"""
Tests for the per-type fix pipelines (skills/run/pipelines/).

Two things are being protected here:

  1. The CVE specialist does what it claims — decides the version up front, and
     afterwards actually checks the manifest, which Phase 3 never did.
  2. sast, iac and secret are untouched. The registry exists to let CVE diverge
     without dragging the other three with it, so the generic pipeline is pinned
     against the very tables the orchestrator reads.

Hermetic: no network, no claude subprocess.

Run with: python3 tests/test_pipelines.py
"""
import copy
import inspect
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))                 # security-engineer/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # lib/

import orchestrator
from orchestrator import TIMEOUTS, AlertTask, FixAgentResult
from pipelines import CvePipeline, FixPipeline, FixPlan, get_pipeline
from validator import _DIFF_LIMITS, ValidationResult

# config.load_config() reads its YAML through PyYAML, and without it the loader
# warns and hands back defaults instead of raising. Tests that assert on parsed
# values therefore describe behaviour that only exists where PyYAML is
# installed; skipped rather than left to fail with a defaults-vs-file mismatch
# that says nothing about the missing package. CI installs it so these run for
# real — see .github/workflows/ci.yml.
try:
    import yaml as _yaml
except ImportError:
    _yaml = None

requires_yaml = unittest.skipIf(
    _yaml is None, "config parsing needs PyYAML (pip install pyyaml)")

_REQUIREMENTS = ("numpy==1.21.0\n"
                 "pillow==8.3.1\n"
                 "flask==1.0.2\n")

_PILLOW_ALERT = {
    "alert_id": "orca-1",
    "title": "pillow Package Vulnerabilities",
    "source": "./python-ml/requirements.txt",
    "file_path": "./python-ml/requirements.txt",
    "labels": ["CVE-2023-4863"],
    "description": "pillow 8.3.1 has known vulnerabilities",
    "recommendation": "Upgrade pillow",
}


class FakeFetcher:
    """OSV/deps.dev stand-in. Mirrors VersionDataFetcher's contract."""

    def __init__(self, vulns=None, versions=None, raises=None):
        self._vulns = vulns or []
        self._versions = versions or []
        self._raises = raises
        self.sources = ["fake"]

    def osv_advisories(self, package, ecosystem):
        if self._raises:
            raise self._raises
        return self._vulns

    def published_versions(self, package, ecosystem):
        if self._raises:
            raise self._raises
        return self._versions


def _vuln(vid, events, package="pillow", ecosystem="PyPI"):
    return {"id": vid, "aliases": [],
            "affected": [{"package": {"name": package, "ecosystem": ecosystem},
                          "ranges": [{"type": "ECOSYSTEM", "events": events}]}]}


def _pillow_fetcher(fixed="10.0.1", versions=None):
    return FakeFetcher(
        vulns=[_vuln("CVE-2023-4863", [{"introduced": "0"}, {"fixed": fixed}])],
        versions=versions or ["8.3.1", "9.0.0", "10.0.1", "11.0.0"])


def _task(feature_type="cve", alert=None, files_changed=None):
    alert = alert if alert is not None else dict(_PILLOW_ALERT)
    task = AlertTask(alert_id=alert.get("alert_id", "orca-1"),
                     title=alert.get("title", ""), risk_level="high",
                     feature_type=feature_type,
                     source=alert.get("source", ""), alert_json=alert)
    task.fix_result = FixAgentResult(success=True,
                                     files_changed=files_changed or [],
                                     diff_summary="bumped")
    return task


class _TreeCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
        return path


# ---------------------------------------------------------------------------
# 1. Registry
# ---------------------------------------------------------------------------

class TestRegistry(unittest.TestCase):
    """Which pipeline a finding type gets."""

    # (description, feature_type, expected_class, expected_ft)
    CASES = [
        ("cve is specialized",  "cve",     CvePipeline,  "cve"),
        ("sast is generic",     "sast",    FixPipeline,  "sast"),
        ("iac is generic",      "iac",     FixPipeline,  "iac"),
        ("secret is generic",   "secret",  FixPipeline,  "secret"),
        ("uppercase tolerated", "CVE",     CvePipeline,  "cve"),
    ]

    def test_routing(self):
        for desc, ft, klass, expected_ft in self.CASES:
            with self.subTest(desc):
                p = get_pipeline(ft)
                self.assertIsInstance(p, klass, desc)
                self.assertEqual(p.feature_type, expected_ft, desc)

    def test_unknown_type_gets_generic_not_an_error(self):
        """Routing is decided upstream by is_fixable; nothing is dropped here."""
        p = get_pipeline("something-new")
        self.assertIsInstance(p, FixPipeline)
        self.assertNotIsInstance(p, CvePipeline)

    def test_empty_type_gets_generic(self):
        self.assertIsInstance(get_pipeline(""), FixPipeline)

    def test_cve_pipeline_is_a_fix_pipeline(self):
        """Substitutable, so the orchestrator needs no per-type branching."""
        self.assertIsInstance(get_pipeline("cve"), FixPipeline)


class TestGenericPipelineIsUnchanged(unittest.TestCase):
    """The non-CVE types must behave exactly as they did before pipelines existed."""

    # (description, feature_type)
    TYPES = [("sast", "sast"), ("iac", "iac"), ("secret", "secret")]

    def test_timeouts_match_the_orchestrator_table(self):
        for desc, ft in self.TYPES:
            with self.subTest(desc):
                self.assertEqual(get_pipeline(ft, timeouts=TIMEOUTS).timeout_sec,
                                 TIMEOUTS[ft], desc)

    def test_diff_limits_match_the_validator_table(self):
        for desc, ft in self.TYPES:
            with self.subTest(desc):
                self.assertEqual(get_pipeline(ft).diff_limit, _DIFF_LIMITS[ft], desc)

    def test_cve_budgets_also_come_from_the_tables(self):
        p = get_pipeline("cve", timeouts=TIMEOUTS)
        self.assertEqual(p.timeout_sec, TIMEOUTS["cve"])
        self.assertEqual(p.diff_limit, _DIFF_LIMITS["cve"])

    def test_fallback_timeout_table_matches_the_orchestrator(self):
        """pipelines._DEFAULT_TIMEOUTS is only used by direct callers, so drift
        would go unnoticed until a tool disagreed with a real run."""
        import pipelines
        self.assertEqual(pipelines._DEFAULT_TIMEOUTS, TIMEOUTS)

    def test_unknown_type_falls_back_to_the_old_defaults(self):
        p = get_pipeline("mystery", timeouts=TIMEOUTS)
        self.assertEqual(p.timeout_sec, 180, "the pre-existing default")
        self.assertEqual(p.diff_limit, 50, "the pre-existing default")

    def test_prepare_is_a_no_op(self):
        """Nothing is prepared for these types, so nothing changes for them."""
        for desc, ft in self.TYPES:
            with self.subTest(desc):
                plan = get_pipeline(ft).prepare(_task(ft), Path("/tmp/nope"))
                self.assertEqual(plan.prompt_extra, "", desc)
                self.assertEqual(plan.metadata, {}, desc)
                self.assertIsNone(plan.error, desc)
                self.assertFalse(plan.needs_review, desc)
                self.assertFalse(plan.prepared, desc)

    def test_verify_delegates_to_local_build_check_with_the_old_arguments(self):
        """Same call the orchestrator used to make inline, argument for argument."""
        alert = {"file_path": "app/server.js", "source": "app/server.js:40"}
        task = _task("sast", alert=alert, files_changed=["app/server.js"])
        expected = ValidationResult(passed=True, phase="local_build")
        with patch("pipelines.base.local_build_check",
                   return_value=expected) as mock_build:
            got = get_pipeline("sast").verify(task, Path("/tmp/wt"))
        self.assertIs(got, expected)
        mock_build.assert_called_once_with(["app/server.js"], Path("/tmp/wt"),
                                           source_file="app/server.js")

    def test_verify_falls_back_to_source_when_file_path_is_absent(self):
        task = _task("sast", alert={"source": "app/server.js:40"},
                     files_changed=["app/server.js"])
        with patch("pipelines.base.local_build_check") as mock_build:
            get_pipeline("sast").verify(task, Path("/tmp/wt"))
        self.assertEqual(mock_build.call_args.kwargs["source_file"],
                         "app/server.js:40")

    def test_verify_survives_a_task_with_no_fix_result(self):
        task = _task("sast")
        task.fix_result = None
        with patch("pipelines.base.local_build_check") as mock_build:
            get_pipeline("sast").verify(task, Path("/tmp/wt"))
        self.assertEqual(mock_build.call_args[0][0], [])


# ---------------------------------------------------------------------------
# 2. CvePipeline.prepare
# ---------------------------------------------------------------------------

class TestCvePrepare(_TreeCase):
    """The version is decided here, not by the agent."""

    def setUp(self):
        super().setUp()
        self.write("python-ml/requirements.txt", _REQUIREMENTS)

    def _prepare(self, fetcher=None, alert=None):
        p = CvePipeline(fetcher=fetcher or _pillow_fetcher(),
                        allow_llm_identify=False)
        return p.prepare(_task("cve", alert=alert), self.root)

    def test_resolves_and_states_the_target(self):
        plan = self._prepare()
        self.assertIsNone(plan.error)
        self.assertTrue(plan.prepared)
        self.assertIn("10.0.1", plan.prompt_extra)
        self.assertIn("pillow", plan.prompt_extra)
        self.assertIn("./python-ml/requirements.txt", plan.prompt_extra)

    def test_directive_forbids_substitution(self):
        """The freelancing this replaces is what produced three rationales."""
        plan = self._prepare()
        lowered = plan.prompt_extra.lower()
        self.assertIn("do not", lowered)
        self.assertIn("already decided", lowered)
        self.assertIn("report failure", lowered)

    def test_metadata_carries_the_decision_onward(self):
        """Impact analysis and the PR body both read this."""
        plan = self._prepare()
        decision = plan.metadata["version_decision"]
        ref = plan.metadata["package_ref"]
        self.assertEqual(decision["target_version"], "10.0.1")
        self.assertEqual(decision["bump_class"], "major")
        self.assertEqual(decision["advisories_cleared"], ["CVE-2023-4863"])
        self.assertEqual(ref["package"], "pillow")
        self.assertEqual(ref["current_version"], "8.3.1")
        self.assertEqual(ref["ecosystem"], "pypi")

    def test_metadata_is_json_serializable(self):
        json.dumps(self._prepare().metadata)

    def test_summary_is_the_rationale(self):
        plan = self._prepare()
        self.assertIn("pillow 8.3.1 → 10.0.1", plan.summary)

    def test_multi_major_jump_is_spelled_out(self):
        plan = self._prepare(fetcher=_pillow_fetcher(
            fixed="12.3.0", versions=["8.3.1", "12.3.0"]))
        self.assertIn("4 major versions", plan.prompt_extra)
        self.assertEqual(plan.metadata["version_decision"]["majors_crossed"], 4)

    def test_alternatives_are_offered_only_as_a_fallback(self):
        plan = self._prepare(fetcher=_pillow_fetcher(
            fixed="9.0.0", versions=["8.3.1", "9.0.0", "9.1.0"]))
        self.assertIn("9.1.0", plan.prompt_extra)
        self.assertIn("if and only if", plan.prompt_extra)

    def test_sole_candidate_offers_no_alternatives(self):
        plan = self._prepare(fetcher=_pillow_fetcher(
            fixed="12.3.0", versions=["8.3.1", "12.3.0"]))
        self.assertNotIn("Safe alternatives", plan.prompt_extra)

    # (description, fetcher, expect_needs_review)
    REVIEW_CASES = [
        ("clean single-advisory bump", _pillow_fetcher(), False),
    ]

    def test_needs_review_on_a_clean_bump_is_false(self):
        for desc, fetcher, expected in self.REVIEW_CASES:
            with self.subTest(desc):
                self.assertEqual(self._prepare(fetcher=fetcher).needs_review,
                                 expected, desc)

    def test_needs_review_when_advisories_remain(self):
        """A partial fix must not merge unread."""
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-1", [{"introduced": "0"}, {"fixed": "9.0.0"}]),
                   _vuln("CVE-2", [{"introduced": "0"}])],       # never fixed
            versions=["8.3.1", "9.0.0"])
        plan = self._prepare(fetcher=fetcher)
        self.assertTrue(plan.needs_review)
        self.assertEqual(plan.metadata["version_decision"]["advisories_remaining"],
                         ["CVE-2"])

    def test_needs_review_when_an_advisory_could_not_be_assessed(self):
        fetcher = FakeFetcher(
            vulns=[{"id": "CVE-9", "aliases": [], "affected": []}],
            versions=["8.3.1", "9.0.0"])
        plan = self._prepare(fetcher=fetcher)
        self.assertTrue(plan.needs_review)

    def test_needs_review_when_the_pin_was_a_range(self):
        self.write("web/package.json", {"dependencies": {"lodash": "^4.17.4"}})
        alert = {"alert_id": "orca-2", "title": "lodash Package Vulnerabilities",
                 "file_path": "web/package.json", "labels": []}
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-1", [{"introduced": "0"}, {"fixed": "4.17.21"}],
                         package="lodash", ecosystem="npm")],
            versions=["4.17.4", "4.17.21"])
        plan = self._prepare(fetcher=fetcher, alert=alert)
        self.assertTrue(plan.needs_review,
                        "a range spec means the installed version was inferred")

    # (description, alert overrides, expected error fragment)
    FAILURE_CASES = [
        ("no manifest path", {"file_path": "", "source": ""},
         "package identification failed"),
        ("package not in manifest",
         {"title": "django Package Vulnerabilities", "description": "",
          "recommendation": ""},
         "package identification failed"),
        ("unknown manifest type", {"file_path": "server.js"},
         "package identification failed"),
    ]

    def test_identification_failures_degrade(self):
        """A failure here must flag for review, never abort the fix."""
        for desc, overrides, fragment in self.FAILURE_CASES:
            with self.subTest(desc):
                plan = self._prepare(alert={**_PILLOW_ALERT, **overrides})
                self.assertIn(fragment, plan.error or "", desc)
                self.assertTrue(plan.needs_review, desc)
                self.assertEqual(plan.prompt_extra, "", desc)

    def test_data_layer_outage_degrades(self):
        plan = self._prepare(fetcher=FakeFetcher(raises=RuntimeError("HTTP 503")))
        self.assertIn("version resolution failed", plan.error)
        self.assertIn("HTTP 503", plan.error)
        self.assertTrue(plan.needs_review)
        self.assertEqual(plan.prompt_extra, "")

    def test_no_safe_version_degrades(self):
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-1", [{"introduced": "0"}])],
            versions=["8.3.1", "9.0.0"])
        plan = self._prepare(fetcher=fetcher)
        self.assertIn("version resolution failed", plan.error)
        self.assertTrue(plan.needs_review)

    def test_prepare_never_raises(self):
        for alert in ({}, {"file_path": None}, {"file_path": 1, "labels": None}):
            with self.subTest(str(alert)):
                plan = self._prepare(alert=alert)
                self.assertIsNotNone(plan.error)


# ---------------------------------------------------------------------------
# 3. CvePipeline.verify — the check Phase 3 never performed
# ---------------------------------------------------------------------------

class TestCveVerify(_TreeCase):
    """Did the manifest actually end up pinning a safe version?"""

    def setUp(self):
        super().setUp()
        self.pipeline = CvePipeline(fetcher=_pillow_fetcher(),
                                    allow_llm_identify=False)

    def _plan(self, target="10.0.1", package="pillow",
              manifest="python-ml/requirements.txt", ecosystem="pypi"):
        return FixPlan(metadata={
            "package_ref": {"package": package, "manifest_path": manifest,
                            "ecosystem": ecosystem, "current_version": "8.3.1"},
            "version_decision": {"target_version": target},
        })

    def test_target_applied_passes(self):
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", "pillow==10.0.1"))
        got = self.pipeline.verify(_task(), self.root, self._plan())
        self.assertTrue(got.passed, got.failures)

    def test_untouched_manifest_fails(self):
        """The whole point: an unbumped manifest used to sail through Phase 3."""
        self.write("python-ml/requirements.txt", _REQUIREMENTS)
        got = self.pipeline.verify(_task(), self.root, self._plan())
        self.assertFalse(got.passed)
        self.assertIn("No bump was applied", got.failures[0])
        self.assertIn("8.3.1", got.failures[0])

    def test_dependency_removed_fails(self):
        self.write("python-ml/requirements.txt",
                   "numpy==1.21.0\nflask==1.0.2\n")
        got = self.pipeline.verify(_task(), self.root, self._plan())
        self.assertFalse(got.passed)
        self.assertIn("no longer declared", got.failures[0])

    def test_different_but_safe_version_is_allowed_with_a_warning(self):
        """A clean version that is not the target is worth noting, not rejecting."""
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", "pillow==11.0.0"))
        got = self.pipeline.verify(_task(), self.root, self._plan())
        self.assertTrue(got.passed, got.failures)

    def test_different_and_still_vulnerable_version_fails(self):
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", "pillow==9.0.0"))
        got = self.pipeline.verify(_task(), self.root, self._plan())
        self.assertFalse(got.passed)
        self.assertIn("9.0.0", got.failures[0])
        self.assertIn("still covered", got.failures[0])

    def test_version_comparison_tolerates_spelling(self):
        """1.0 and 1.0.0 are the same pin; a v prefix does not change a Go bump."""
        self.write("python-ml/requirements.txt", "pillow==10.0.1.0\n")
        got = self.pipeline.verify(_task(), self.root, self._plan())
        self.assertTrue(got.passed, got.failures)

    def test_stale_lockfile_fails(self):
        """Catches a manifest edited without regenerating the lockfile."""
        self.write("web/package.json", {"dependencies": {"lodash": "4.17.21"}})
        self.write("web/package-lock.json", {
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"name": "lodash",
                                                 "version": "4.17.4"}}})
        pipeline = CvePipeline(fetcher=FakeFetcher(vulns=[], versions=[]),
                              allow_llm_identify=False)
        got = pipeline.verify(_task(), self.root,
                              self._plan(target="4.17.21", package="lodash",
                                         manifest="web/package.json",
                                         ecosystem="npm"))
        self.assertFalse(got.passed)
        self.assertIn("was not regenerated", got.failures[0])

    def test_fresh_lockfile_passes(self):
        self.write("web/package.json", {"dependencies": {"lodash": "4.17.21"}})
        self.write("web/package-lock.json", {
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"name": "lodash",
                                                 "version": "4.17.21"}}})
        pipeline = CvePipeline(fetcher=FakeFetcher(vulns=[], versions=[]),
                              allow_llm_identify=False)
        got = pipeline.verify(_task(), self.root,
                              self._plan(target="4.17.21", package="lodash",
                                         manifest="web/package.json",
                                         ecosystem="npm"))
        self.assertTrue(got.passed, got.failures)

    def test_unbumped_manifest_fails_even_during_an_outage(self):
        """Needs no advisory lookup: still on the version the alert names.

        The advisory check fails open so an outage cannot reject a good bump,
        which would otherwise let an untouched manifest through here.
        """
        self.write("python-ml/requirements.txt", _REQUIREMENTS)
        pipeline = CvePipeline(fetcher=FakeFetcher(raises=RuntimeError("HTTP 503")),
                              allow_llm_identify=False)
        got = pipeline.verify(_task(), self.root, self._plan())
        self.assertFalse(got.passed)
        self.assertIn("No bump was applied", got.failures[0])

    def test_advisory_lookup_failure_does_not_reject_a_real_bump(self):
        """Fails open: an outage must not turn a valid bump into a rejection."""
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", "pillow==11.0.0"))
        pipeline = CvePipeline(fetcher=FakeFetcher(raises=RuntimeError("HTTP 503")),
                              allow_llm_identify=False)
        got = pipeline.verify(_task(), self.root, self._plan())
        self.assertTrue(got.passed, got.failures)

    # (description, plan) — cases with nothing to verify against
    FALLBACK_CASES = [
        ("no plan at all", None),
        ("plan with no metadata", FixPlan()),
        ("plan missing the target", FixPlan(metadata={"package_ref": {}})),
    ]

    def test_falls_back_to_the_generic_check_without_a_decision(self):
        """No decision means no verdict to invent, so run the old check."""
        for desc, plan in self.FALLBACK_CASES:
            with self.subTest(desc):
                with patch("pipelines.base.local_build_check") as mock_build:
                    mock_build.return_value = ValidationResult(
                        passed=True, phase="local_build")
                    self.pipeline.verify(_task(), self.root, plan)
                mock_build.assert_called_once()

    def test_go_gets_a_resolve_check(self):
        self.write("svc/go.mod",
                   'module x\nrequire (\n\tgolang.org/x/net v0.17.0\n)\n')
        pipeline = CvePipeline(fetcher=FakeFetcher(vulns=[], versions=[]),
                              allow_llm_identify=False)
        with patch("pipelines.cve._run_check") as mock_check:
            mock_check.return_value = ValidationResult(passed=True,
                                                      phase="local_build")
            pipeline.verify(_task(), self.root,
                            self._plan(target="v0.17.0",
                                       package="golang.org/x/net",
                                       manifest="svc/go.mod", ecosystem="go"))
        self.assertEqual(mock_check.call_args[0][0], ["go", "build", "./..."])

    def test_pypi_gets_no_resolve_check(self):
        """pip install is slow, online and rewrites lockfiles; CI covers it."""
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", "pillow==10.0.1"))
        with patch("pipelines.cve._run_check") as mock_check:
            got = self.pipeline.verify(_task(), self.root, self._plan())
        mock_check.assert_not_called()
        self.assertTrue(got.passed)


# ---------------------------------------------------------------------------
# 3b. The advisory the run was asked for
#
# A package alert covers every CVE in its package, and the minimum-safe policy
# bumps past all of them — so "did the bump work?" and "did it fix the CVE
# somebody asked about?" are genuinely different questions. Phase 3 answers the
# first; these cover the second.
# ---------------------------------------------------------------------------

class TestRequestedCveGate(_TreeCase):

    def _plan(self, requested, target="10.0.1"):
        return FixPlan(metadata={
            "package_ref": {"package": "pillow",
                            "manifest_path": "python-ml/requirements.txt",
                            "ecosystem": "pypi", "current_version": "8.3.1"},
            "version_decision": {"target_version": target},
            "requested_cves": requested,
        })

    def _verify(self, applied, requested, fetcher):
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", f"pillow=={applied}"))
        pipeline = CvePipeline(fetcher=fetcher, allow_llm_identify=False)
        return pipeline.verify(_task(), self.root,
                               self._plan(requested, target=applied))

    def test_requested_cve_cleared_passes(self):
        got = self._verify("10.0.1", ["CVE-2023-4863"], _pillow_fetcher())
        self.assertTrue(got.passed, got.failures)

    def test_requested_cve_still_open_fails(self):
        """The bump landed somewhere the requested advisory still covers."""
        fetcher = _pillow_fetcher(fixed="11.0.0")
        got = self._verify("10.0.1", ["CVE-2023-4863"], fetcher)
        self.assertFalse(got.passed)
        joined = " ".join(got.failures)
        self.assertIn("CVE-2023-4863", joined)
        self.assertIn("asked to fix", joined)

    def test_alias_only_match_is_recognized(self):
        """OSV collapses CVE+GHSA records for one flaw to a single id.

        The requested CVE then survives only in `aliases`, so an id-only
        comparison would call a still-vulnerable bump clean.
        """
        vuln = _vuln("GHSA-xxxx-yyyy-zzzz",
                     [{"introduced": "0"}, {"fixed": "11.0.0"}])
        vuln["aliases"] = ["CVE-2023-4863"]
        fetcher = FakeFetcher(vulns=[vuln],
                              versions=["8.3.1", "10.0.1", "11.0.0"])
        got = self._verify("10.0.1", ["CVE-2023-4863"], fetcher)
        self.assertFalse(got.passed)
        self.assertIn("CVE-2023-4863", " ".join(got.failures))

    def test_alias_cleared_passes(self):
        vuln = _vuln("GHSA-xxxx-yyyy-zzzz",
                     [{"introduced": "0"}, {"fixed": "10.0.1"}])
        vuln["aliases"] = ["CVE-2023-4863"]
        fetcher = FakeFetcher(vulns=[vuln],
                              versions=["8.3.1", "10.0.1", "11.0.0"])
        got = self._verify("10.0.1", ["CVE-2023-4863"], fetcher)
        self.assertTrue(got.passed, got.failures)

    def test_case_insensitive_match(self):
        got = self._verify("10.0.1", ["cve-2023-4863"],
                           _pillow_fetcher(fixed="11.0.0"))
        self.assertFalse(got.passed)

    def test_unrelated_requested_cve_does_not_fail_the_bump(self):
        """Only the requested advisory gates; the package's others are the
        existing package-wide check's business."""
        got = self._verify("10.0.1", ["CVE-1999-0001"],
                           _pillow_fetcher(fixed="11.0.0"))
        # 10.0.1 is still covered by CVE-2023-4863, but that is not what was
        # asked for, and the target matches — so this gate stays quiet.
        self.assertTrue(got.passed, got.failures)

    def test_osv_outage_fails_open(self):
        """An unreachable OSV must cost the check, not the fix."""
        got = self._verify("10.0.1", ["CVE-2023-4863"],
                           FakeFetcher(raises=RuntimeError("HTTP 503")))
        self.assertTrue(got.passed, got.failures)

    def test_no_requested_cve_skips_the_gate(self):
        """A run that named no advisory behaves exactly as it did before."""
        self.write("python-ml/requirements.txt",
                   _REQUIREMENTS.replace("pillow==8.3.1", "pillow==10.0.1"))
        pipeline = CvePipeline(fetcher=_pillow_fetcher(fixed="11.0.0"),
                               allow_llm_identify=False)
        plan = self._plan([], target="10.0.1")
        with patch.object(CvePipeline, "_requested_still_open") as gate:
            got = pipeline.verify(_task(), self.root, plan)
        gate.assert_not_called()
        self.assertTrue(got.passed, got.failures)


class TestRequestedCveReachesTheAgent(_TreeCase):
    """prepare() has to hand the advisory on, or nothing downstream knows it."""

    def _prepare(self, requested):
        self.write("python-ml/requirements.txt", _REQUIREMENTS)
        task = _task()
        task.requested_cves = requested
        pipeline = CvePipeline(fetcher=_pillow_fetcher(),
                               allow_llm_identify=False)
        return pipeline.prepare(task, self.root)

    def test_metadata_carries_the_request(self):
        plan = self._prepare(["CVE-2023-4863"])
        self.assertEqual(plan.metadata["requested_cves"], ["CVE-2023-4863"])

    def test_directive_names_the_advisory(self):
        plan = self._prepare(["CVE-2023-4863"])
        self.assertIn("CVE-2023-4863", plan.prompt_extra)
        self.assertIn("do not narrow the bump", plan.prompt_extra)

    def test_directive_unchanged_without_a_request(self):
        """No advisory named means the prompt the agent has always seen."""
        plan = self._prepare([])
        self.assertEqual(plan.metadata["requested_cves"], [])
        self.assertNotIn("This alert was selected because", plan.prompt_extra)

    def test_target_version_still_stated(self):
        """The requested-CVE line must not displace the actual instruction."""
        plan = self._prepare(["CVE-2023-4863"])
        self.assertIn("Set **pillow** to exactly **10.0.1**", plan.prompt_extra)


# ---------------------------------------------------------------------------
# 4. Orchestrator wiring
# ---------------------------------------------------------------------------

class TestOrchestratorUsesThePipeline(unittest.TestCase):
    """The seams the orchestrator relies on, pinned so a refactor cannot
    silently bypass them the way Phase 3 was silently bypassed."""

    def test_prepare_runs_before_the_fix_agent(self):
        import inspect
        src = inspect.getsource(orchestrator._run_pipeline)
        prepare_at = src.index("pipeline.prepare")
        invoke_at = src.index("_invoke_fix_agent")
        self.assertLess(prepare_at, invoke_at)

    def test_phase_three_goes_through_the_pipeline(self):
        import inspect
        src = inspect.getsource(orchestrator._run_pipeline)
        self.assertIn("pipeline.verify", src)
        # Match a call, not the bare name — the name still appears in the comment
        # explaining why Phase 3 moved.
        self.assertNotIn("local_build_check(", src,
                         "Phase 3 must run through the type's pipeline")

    def test_budgets_come_from_the_pipeline(self):
        import inspect
        src = inspect.getsource(orchestrator._run_pipeline)
        self.assertIn("pipeline.timeout_sec", src)
        self.assertIn("diff_limit=pipeline.diff_limit", src)
        self.assertNotIn("TIMEOUTS.get", src,
                         "the per-type timeout now belongs to the pipeline")

    def test_directive_reaches_the_fix_prompt(self):
        """A plan nobody puts in the prompt is a plan the agent cannot follow."""
        task = _task("cve")
        task.fix_plan = FixPlan(prompt_extra="SET pillow TO 10.0.1")
        with patch("orchestrator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"result": json.dumps(
                    {"status": "success", "alert_id": "orca-1",
                     "files_changed": [], "diff_summary": "x"})}),
                stderr="")
            task.worktree_path = Path("/tmp/wt")
            orchestrator._invoke_fix_agent(task, dry_run=False, timeout_sec=10)
        prompt = mock_run.call_args[0][0][2]
        self.assertIn("SET pillow TO 10.0.1", prompt)

    def test_prompt_is_unchanged_without_a_plan(self):
        task = _task("sast")
        task.fix_plan = FixPlan()
        with patch("orchestrator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"result": json.dumps(
                    {"status": "success", "alert_id": "orca-1",
                     "files_changed": [], "diff_summary": "x"})}),
                stderr="")
            task.worktree_path = Path("/tmp/wt")
            orchestrator._invoke_fix_agent(task, dry_run=False, timeout_sec=10)
        prompt = mock_run.call_args[0][0][2]
        self.assertNotIn("---\n\n", prompt.split("## Full Alert Data")[0][-40:])


class TestNextCandidateHint(unittest.TestCase):
    """What the retry is told when the Orca check rejects a bump."""

    def _hint(self, decision):
        task = _task("cve")
        task.fix_plan = FixPlan(metadata={"version_decision": decision})
        return orchestrator._next_candidate_hint(task)

    def test_names_the_next_safe_version(self):
        hint = self._hint({"target_version": "9.0.0",
                           "candidates": [{"version": "9.0.0"},
                                          {"version": "9.1.0"}]})
        self.assertIn("9.1.0", hint)

    def test_says_so_when_there_is_no_alternative(self):
        """Implying a choice exists is how the same bump came back three times."""
        hint = self._hint({"target_version": "12.3.0",
                           "candidates": [{"version": "12.3.0"}]})
        self.assertIn("only published version", hint)
        self.assertIn("report failure", hint)

    # (description, plan) — nothing to say
    EMPTY_CASES = [
        ("no plan", None),
        ("no metadata", FixPlan()),
        ("no decision", FixPlan(metadata={})),
    ]

    def test_silent_without_a_decision(self):
        for desc, plan in self.EMPTY_CASES:
            with self.subTest(desc):
                task = _task("sast")
                task.fix_plan = plan
                self.assertEqual(orchestrator._next_candidate_hint(task), "", desc)


# ---------------------------------------------------------------------------
# 4b. Agent instructions
# ---------------------------------------------------------------------------

class TestEcosystemFragments(unittest.TestCase):
    """Per-ecosystem instructions appended to the CVE directive."""

    def setUp(self):
        from version_data import ECOSYSTEMS
        self.ecosystems = ECOSYSTEMS
        self.pipeline = CvePipeline(allow_llm_identify=False)

    def test_every_supported_ecosystem_has_one(self):
        """A resolved ecosystem with no fragment leaves the agent guessing at
        the package-manager command."""
        for key in self.ecosystems:
            with self.subTest(key):
                fragment = self.pipeline._ecosystem_fragment(key)
                self.assertTrue(fragment.strip(),
                                f"fix-agents/cve/{key}.md is missing or empty")

    def test_each_fragment_names_a_command_or_says_there_is_none(self):
        for key in self.ecosystems:
            with self.subTest(key):
                text = self.pipeline._ecosystem_fragment(key).lower()
                self.assertTrue("```" in text,
                                f"{key}.md should show the concrete edit")

    def test_missing_fragment_degrades_quietly(self):
        """An ecosystem we have not written up must not break the directive."""
        self.assertEqual(self.pipeline._ecosystem_fragment("cpan"), "")

    def test_cve_md_no_longer_tells_the_agent_to_find_the_version(self):
        """That decision moved out of the prompt and into the data layer."""
        text = (Path(__file__).parent.parent / "fix-agents" / "cve.md").read_text()
        self.assertNotIn("Finding the Patched Version", text)
        self.assertIn("already been decided", text)
        self.assertIn("Do not substitute a different version", text)

    def test_cve_md_warns_about_the_summary_gate(self):
        text = (Path(__file__).parent.parent / "fix-agents" / "cve.md").read_text()
        self.assertIn("diff_summary", text)
        self.assertIn("rejects a", text)

    def test_directive_carries_the_fragment(self):
        """The fragment has to actually reach the prompt, not just exist."""
        import tempfile as tf
        with tf.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "python-ml").mkdir()
            (root / "python-ml" / "requirements.txt").write_text(_REQUIREMENTS)
            pipeline = CvePipeline(fetcher=_pillow_fetcher(),
                                   allow_llm_identify=False)
            plan = pipeline.prepare(_task("cve"), root)
        self.assertIn("Python (PyPI)", plan.prompt_extra)
        self.assertIn("requirements.txt", plan.prompt_extra)


# ---------------------------------------------------------------------------
# 5. Where the decision ends up: impact analysis, the PR body, the sanity gate
# ---------------------------------------------------------------------------

_DECISION = {
    "package_ref": {"package": "pillow", "ecosystem": "pypi",
                    "manifest_path": "./python-ml/requirements.txt",
                    "current_version": "8.3.1", "exact_pin": True},
    "version_decision": {
        "current_version": "8.3.1", "target_version": "12.3.0",
        "bump_class": "major", "majors_crossed": 4,
        "advisories_cleared": ["CVE-2023-4863", "CVE-2026-55379"],
        "advisories_remaining": [], "advisories_unknown_scope": [],
        "candidates": [{"version": "12.3.0", "bump_class": "major"}],
        "rationale": "pillow 8.3.1 → 12.3.0; major bump, 4 major versions.",
        "data_sources": ["osv:pypi/pillow (cache)"],
    },
}


class TestImpactFixContext(unittest.TestCase):
    """Impact analysis should be told the bump distance, not left to infer it."""

    def _render(self, ctx):
        import impact_agent
        return impact_agent._render_fix_context(ctx)

    def test_states_the_bump_and_distance(self):
        out = self._render(_DECISION)
        self.assertIn("8.3.1 → 12.3.0", out)
        self.assertIn("crossing 4 major versions", out)
        self.assertIn("pillow", out)

    def test_lists_cleared_advisories(self):
        self.assertIn("CVE-2026-55379", self._render(_DECISION))

    def test_says_when_there_is_no_alternative(self):
        self.assertIn("only published version", self._render(_DECISION))

    def test_lists_alternatives_when_they_exist(self):
        ctx = copy.deepcopy(_DECISION)
        ctx["version_decision"]["candidates"] = [{"version": "12.3.0"},
                                                 {"version": "12.4.0"}]
        self.assertIn("12.4.0", self._render(ctx))

    def test_flags_remaining_advisories(self):
        ctx = copy.deepcopy(_DECISION)
        ctx["version_decision"]["advisories_remaining"] = ["CVE-9999-1"]
        self.assertIn("Still affected", self._render(ctx))

    def test_flags_an_inferred_installed_version(self):
        ctx = copy.deepcopy(_DECISION)
        ctx["package_ref"]["exact_pin"] = False
        self.assertIn("inferred", self._render(ctx))

    # (description, context) — nothing to add to the prompt
    EMPTY_CASES = [
        ("no context", None),
        ("empty context", {}),
        ("no decision", {"version_decision": {}}),
        ("decision without a target", {"version_decision": {"bump_class": "minor"}}),
    ]

    def test_renders_nothing_without_a_decision(self):
        """sast/iac/secret must get exactly the prompt they got before."""
        for desc, ctx in self.EMPTY_CASES:
            with self.subTest(desc):
                self.assertEqual(self._render(ctx), "", desc)

    def test_prompt_omits_the_section_cleanly(self):
        import impact_agent
        with patch("impact_agent.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"result": json.dumps(
                    {"level": "low", "description": "x", "downtime_risk": False,
                     "requires_deploy": False})}),
                stderr="")
            impact_agent.analyze_impact({"alert_id": "a"}, "diff")
        prompt = mock_run.call_args[0][0][2]
        self.assertNotIn("Fix Context", prompt)

    def test_prompt_includes_the_section_when_given(self):
        import impact_agent
        with patch("impact_agent.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({"result": json.dumps(
                    {"level": "high", "description": "x", "downtime_risk": True,
                     "requires_deploy": True})}),
                stderr="")
            impact_agent.analyze_impact({"alert_id": "a"}, "diff",
                                        fix_context=_DECISION)
        prompt = mock_run.call_args[0][0][2]
        self.assertIn("Fix Context", prompt)
        self.assertIn("crossing 4 major versions", prompt)

    def test_orchestrator_passes_the_plan_metadata(self):
        import inspect
        src = inspect.getsource(orchestrator._run_pipeline)
        self.assertIn("fix_context=plan.metadata", src)


class TestSingleShotContract(unittest.TestCase):
    """Every no-tools prompt must say so, or it spends its turn asking to look.

    Live run 20260802T030948Z: 2 of 3 alerts lost their impact assessment once
    the prompt grew a Fix Context section — one replied "I'll ground this in the
    actual repo contents before judging" and produced no JSON, the other ran past
    its timeout. Removing the tools is not enough; the model has to be told.
    """

    def _prompts(self):
        import impact_agent
        import validator
        return {"impact": impact_agent._PROMPT, "llm_validate": validator._LLM_PROMPT}

    def test_both_prompts_take_the_contract(self):
        for name, template in self._prompts().items():
            with self.subTest(name):
                self.assertIn("{contract}", template,
                              f"{name} prompt does not include the contract")

    def test_contract_states_the_key_constraints(self):
        from validator import _SINGLE_SHOT_CONTRACT
        lowered = _SINGLE_SHOT_CONTRACT.lower()
        for phrase in ("no tools", "cannot read", "do not narrate",
                       "answer directly"):
            with self.subTest(phrase):
                self.assertIn(phrase, lowered)

    def test_contract_is_last_before_the_json_block(self):
        """It has to be the final instruction, not buried mid-prompt."""
        for name, template in self._prompts().items():
            with self.subTest(name):
                after = template.split("{contract}", 1)[1]
                self.assertIn("Return ONLY this JSON", after)
                self.assertNotIn("##", after,
                                 f"{name}: content follows the contract")

    def test_json_block_forbids_a_preamble(self):
        """"nothing after" allowed the prose-then-nothing failure."""
        for name, template in self._prompts().items():
            with self.subTest(name):
                self.assertIn("nothing before or after", template)

    def test_rendered_impact_prompt_ends_with_the_json_shape(self):
        import impact_agent
        from validator import _SINGLE_SHOT_CONTRACT
        rendered = impact_agent._PROMPT.format(
            alert_json="{}", diff_text="d",
            fix_context=impact_agent._render_fix_context(_DECISION),
            contract=_SINGLE_SHOT_CONTRACT)
        self.assertIn("no tools", rendered.lower())
        self.assertLess(rendered.index("no tools"), rendered.index('"level"'))

    def test_impact_timeout_has_headroom_for_the_richer_prompt(self):
        """90s was the budget before Fix Context existed; one alert overran it."""
        import impact_agent
        default = inspect.signature(
            impact_agent.analyze_impact).parameters["timeout_sec"].default
        self.assertGreaterEqual(default, 120)


class TestWhatChangedSection(unittest.TestCase):
    """The PR body should describe the decision, not the agent's account of it."""

    def _body(self, plan=None, summary="bumped something"):
        task = _task("cve")
        task.fix_result = FixAgentResult(success=True, diff_summary=summary)
        task.fix_plan = plan
        return orchestrator._what_changed(task)

    def test_renders_from_the_decision(self):
        body = self._body(FixPlan(metadata=copy.deepcopy(_DECISION)))
        self.assertIn("`pillow`", body)
        self.assertIn("`8.3.1`", body)
        self.assertIn("`12.3.0`", body)
        self.assertIn("./python-ml/requirements.txt", body)

    def test_includes_the_rationale_and_advisories(self):
        body = self._body(FixPlan(metadata=copy.deepcopy(_DECISION)))
        self.assertIn("Why this version", body)
        self.assertIn("CVE-2026-55379", body)

    def test_includes_a_reproduce_command(self):
        """A reviewer should be able to re-derive the choice in one command."""
        body = self._body(FixPlan(metadata=copy.deepcopy(_DECISION)))
        self.assertIn("resolve-version pypi pillow 8.3.1", body)

    def test_ignores_a_contradictory_agent_summary(self):
        """The PR #9 defect: body said 11.3.0 over a diff that said 12.3.0."""
        body = self._body(FixPlan(metadata=copy.deepcopy(_DECISION)),
                          summary="Bumped pillow from 8.3.1 to 11.3.0")
        self.assertIn("12.3.0", body)
        self.assertNotIn("11.3.0", body)

    def test_flags_remaining_advisories(self):
        meta = copy.deepcopy(_DECISION)
        meta["version_decision"]["advisories_remaining"] = ["CVE-9999-1"]
        self.assertIn("Still affected", self._body(FixPlan(metadata=meta)))

    def test_flags_unassessable_advisories(self):
        meta = copy.deepcopy(_DECISION)
        meta["version_decision"]["advisories_unknown_scope"] = ["CVE-9999-2"]
        self.assertIn("Not assessable", self._body(FixPlan(metadata=meta)))

    def test_names_the_requested_advisory(self):
        """A reviewer who opened this PR looking for one CVE has to find it.

        The alert covers a whole package, so the trigger is not otherwise
        recoverable from the diff or the version decision.
        """
        meta = copy.deepcopy(_DECISION)
        meta["requested_cves"] = ["CVE-2023-4863"]
        body = self._body(FixPlan(metadata=meta))
        self.assertIn("**Requested:**", body)
        self.assertIn("CVE-2023-4863", body)

    def test_says_how_much_wider_the_bump_went(self):
        """_DECISION clears two advisories; one was requested, so one is extra."""
        meta = copy.deepcopy(_DECISION)
        meta["requested_cves"] = ["CVE-2023-4863"]
        body = self._body(FixPlan(metadata=meta))
        self.assertIn("1 other advisory on the same package", body)

    def test_pluralizes_the_extra_count(self):
        meta = copy.deepcopy(_DECISION)
        meta["requested_cves"] = ["CVE-2023-4863"]
        meta["version_decision"]["advisories_cleared"] = [
            "CVE-2023-4863", "CVE-1", "CVE-2", "CVE-3"]
        self.assertIn("3 other advisories on the same package",
                      self._body(FixPlan(metadata=meta)))

    def test_no_requested_line_without_a_request(self):
        """A severity-driven run's PR body is unchanged."""
        self.assertNotIn("**Requested:**",
                         self._body(FixPlan(metadata=copy.deepcopy(_DECISION))))

    # (description, plan) — falls back to the agent's summary
    FALLBACK_CASES = [
        ("no plan", None),
        ("no metadata", FixPlan()),
        ("no decision", FixPlan(metadata={"package_ref": {}})),
    ]

    def test_falls_back_to_the_agent_summary(self):
        """sast/iac/secret keep the body they had before."""
        for desc, plan in self.FALLBACK_CASES:
            with self.subTest(desc):
                self.assertEqual(self._body(plan, summary="patched traversal"),
                                 "patched traversal", desc)

    def test_falls_back_to_see_diff_when_there_is_nothing(self):
        task = _task("sast")
        task.fix_result = None
        task.fix_plan = None
        self.assertEqual(orchestrator._what_changed(task), "See diff")


class TestSummaryVersionMismatch(unittest.TestCase):
    """The gate that would have caught PR #9."""

    def _check(self, summary, diff):
        from validator import summary_version_mismatch
        return summary_version_mismatch(summary, diff)

    DIFF_12 = ("--- a/requirements.txt\n+++ b/requirements.txt\n"
               "-pillow==8.3.1\n+pillow==12.3.0\n")

    def test_the_pr_9_case_is_caught(self):
        got = self._check("Bumped pillow from 8.3.1 to 11.3.0", self.DIFF_12)
        self.assertTrue(got)
        self.assertIn("11.3.0", got)
        self.assertIn("12.3.0", got)

    # (description, summary) — consistent with DIFF_12
    CONSISTENT = [
        ("exact match", "Bumped pillow from 8.3.1 to 12.3.0"),
        ("arrow form", "pillow 8.3.1 -> 12.3.0"),
        ("unicode arrow", "pillow 8.3.1 → 12.3.0"),
        ("to version form", "Upgraded pillow to version 12.3.0"),
        ("no version claimed", "Bumped pillow to the patched release"),
        ("mentions a CVE year only", "Fixes CVE-2023-4863 in pillow"),
        ("names only the old version", "pillow 8.3.1 was vulnerable"),
        ("empty summary", ""),
    ]

    def test_consistent_summaries_pass(self):
        for desc, summary in self.CONSISTENT:
            with self.subTest(desc):
                self.assertEqual(self._check(summary, self.DIFF_12), "", desc)

    def test_v_prefix_is_tolerated_in_either_direction(self):
        go_diff = "--- a/go.mod\n+++ b/go.mod\n-\tx v0.1.0\n+\tx v0.17.0\n"
        self.assertEqual(self._check("bumped x to 0.17.0", go_diff), "")
        self.assertEqual(self._check("bumped x to v0.17.0", go_diff), "")

    def test_only_added_lines_count(self):
        """A version that only appears on a removed line is not what shipped."""
        got = self._check("bumped pillow to 8.3.1", self.DIFF_12)
        self.assertTrue(got, "8.3.1 is only on the removed line")

    # (description, summary, diff) — nothing to compare against
    INERT = [
        ("empty diff", "bumped to 1.2.3", ""),
        ("diff with no added lines", "bumped to 1.2.3",
         "--- a/f\n+++ b/f\n-removed\n"),
        ("sast summary with no versions", "parameterized the query",
         "--- a/f\n+++ b/f\n+cur.execute(q, (a,))\n"),
    ]

    def test_inert_cases_pass(self):
        for desc, summary, diff in self.INERT:
            with self.subTest(desc):
                self.assertEqual(self._check(summary, diff), "", desc)

    def test_wired_into_sanity_check(self):
        import inspect

        from validator import sanity_check
        self.assertIn("diff_summary", inspect.signature(sanity_check).parameters)
        src = inspect.getsource(sanity_check)
        self.assertIn("summary_version_mismatch", src)

    def test_orchestrator_passes_the_summary(self):
        import inspect
        src = inspect.getsource(orchestrator._run_pipeline)
        self.assertEqual(src.count("diff_summary=fix_result.diff_summary"), 2,
                         "both the first pass and the retry must check it")


# ---------------------------------------------------------------------------
# 6. Config
# ---------------------------------------------------------------------------

class TestVersionDataConfig(unittest.TestCase):
    """The new config section, and the sharp edge it removed."""

    def setUp(self):
        self._saved = os.environ.pop("SECURITY_ENGINEER_CONFIG", None)

    def tearDown(self):
        if self._saved is not None:
            os.environ["SECURITY_ENGINEER_CONFIG"] = self._saved
        else:
            os.environ.pop("SECURITY_ENGINEER_CONFIG", None)

    def _load(self, yaml_text):
        import config as config_mod
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_text)
            path = f.name
        try:
            os.environ["SECURITY_ENGINEER_CONFIG"] = path
            return config_mod.load_config()
        finally:
            os.unlink(path)

    def test_defaults(self):
        from config import Config
        vd = Config().version_data
        self.assertTrue(vd.enabled)
        self.assertEqual(vd.cache_ttl_sec, 6 * 3600)
        self.assertFalse(vd.offline)

    @requires_yaml
    def test_section_parses(self):
        cfg = self._load("version_data:\n"
                         "  cache_ttl_sec: 60\n"
                         "  offline: true\n")
        self.assertEqual(cfg.version_data.cache_ttl_sec, 60)
        self.assertTrue(cfg.version_data.offline)

    @requires_yaml
    def test_both_sections_parse_together(self):
        """The old top-level filter hardcoded != "orca_check"; a second section
        would have leaked into the Config constructor."""
        cfg = self._load("orca_check:\n"
                         "  check_name: Orca Security\n"
                         "version_data:\n"
                         "  offline: true\n"
                         "max_parallel_fixes: 2\n")
        self.assertEqual(cfg.orca_check.check_name, "Orca Security")
        self.assertTrue(cfg.version_data.offline)
        self.assertEqual(cfg.max_parallel_fixes, 2)

    @requires_yaml
    def test_unknown_keys_are_dropped(self):
        cfg = self._load("version_data:\n  nonsense: 1\n  offline: true\n")
        self.assertTrue(cfg.version_data.offline)
        self.assertFalse(hasattr(cfg.version_data, "nonsense"))

    def test_absent_section_uses_defaults(self):
        cfg = self._load("max_parallel_fixes: 1\n")
        self.assertTrue(cfg.version_data.enabled)

    def test_disabled_reverts_to_the_generic_pipeline(self):
        """An off switch has to be an exact revert, not a broken specialist."""
        from config import Config, VersionDataConfig
        disabled = Config(version_data=VersionDataConfig(enabled=False))
        with patch("pipelines.load_config", return_value=disabled):
            p = get_pipeline("cve", timeouts=TIMEOUTS)
        self.assertNotIsInstance(p, CvePipeline)
        self.assertEqual(p.feature_type, "cve")
        self.assertEqual(p.timeout_sec, TIMEOUTS["cve"])
        self.assertEqual(p.diff_limit, _DIFF_LIMITS["cve"])

    def test_enabled_builds_a_configured_fetcher(self):
        from config import Config, VersionDataConfig
        cfg = Config(version_data=VersionDataConfig(offline=True,
                                                    cache_ttl_sec=99))
        with patch("pipelines.load_config", return_value=cfg):
            p = get_pipeline("cve", timeouts=TIMEOUTS)
        self.assertIsInstance(p, CvePipeline)
        self.assertTrue(p.fetcher.offline)
        self.assertEqual(p.fetcher.cache_ttl_sec, 99)

    def test_injected_fetcher_wins_over_config(self):
        """Tests must not be able to reach the network by accident."""
        sentinel = FakeFetcher()
        with patch("pipelines.load_config") as mock_load:
            p = get_pipeline("cve", fetcher=sentinel)
        mock_load.assert_not_called()
        self.assertIs(p.fetcher, sentinel)


class TestAlertPassthrough(unittest.TestCase):
    """AssetData was requested and dropped; keep it so it can be looked at."""

    def _normalize(self, item):
        from orca_client import _normalize_alert
        return _normalize_alert(item)

    def test_asset_data_is_preserved(self):
        got = self._normalize({"data": {
            "AlertId": {"value": "orca-1"},
            "AssetData": {"value": {"repo": "owner/name"}},
        }})
        self.assertEqual(got["asset_data"], {"repo": "owner/name"})

    def test_unknown_risk_findings_keys_are_preserved(self):
        got = self._normalize({"data": {
            "AlertId": {"value": "orca-1"},
            "RiskFindings": {"value": {"feature_type": "sast",
                                       "package_name": "pillow",
                                       "installed_version": "8.3.1"}},
        }})
        self.assertEqual(got["extra_findings"],
                         {"package_name": "pillow", "installed_version": "8.3.1"})

    def test_known_keys_are_not_duplicated(self):
        got = self._normalize({"data": {
            "AlertId": {"value": "orca-1"},
            "RiskFindings": {"value": {"feature_type": "sast",
                                       "origin_url": "http://x",
                                       "is_test_file": True}},
        }})
        self.assertEqual(got["extra_findings"], {})

    def test_absent_payloads_give_empty_dicts(self):
        got = self._normalize({"data": {"AlertId": {"value": "orca-1"}}})
        self.assertEqual(got["asset_data"], {})
        self.assertEqual(got["extra_findings"], {})

    def test_oversized_payload_is_dropped_not_inlined(self):
        """The alert is pretty-printed into the fix prompt."""
        big = {"blob": "x" * 10000}
        got = self._normalize({"data": {"AlertId": {"value": "orca-1"},
                                        "AssetData": {"value": big}}})
        self.assertIn("_dropped", got["asset_data"])
        self.assertLess(len(json.dumps(got["asset_data"])), 200)

    def test_unserializable_payload_is_handled(self):
        got = self._normalize({"data": {"AlertId": {"value": "orca-1"},
                                        "AssetData": {"value": {"o": object()}}}})
        self.assertIn("_dropped", got["asset_data"])


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestRegistry,
        TestGenericPipelineIsUnchanged,
        TestCvePrepare,
        TestCveVerify,
        TestRequestedCveGate,
        TestRequestedCveReachesTheAgent,
        TestOrchestratorUsesThePipeline,
        TestNextCandidateHint,
        TestEcosystemFragments,
        TestImpactFixContext,
        TestSingleShotContract,
        TestWhatChangedSection,
        TestSummaryVersionMismatch,
        TestVersionDataConfig,
        TestAlertPassthrough,
    ]

    # Same guard as test_orchestrator.py: an unregistered class does not fail,
    # it silently never runs, which is indistinguishable from passing.
    _missing = sorted(
        {name for name, obj in list(globals().items())
         if isinstance(obj, type) and issubclass(obj, unittest.TestCase)
         and obj not in (unittest.TestCase, _TreeCase)}
        - {cls.__name__ for cls in test_classes})
    if _missing:
        sys.exit(f"Test classes defined but never run — add them to "
                 f"test_classes: {', '.join(_missing)}")

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
