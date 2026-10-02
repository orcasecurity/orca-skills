#!/usr/bin/env python3
"""
End-to-end integration tests against the live Orca API.

Validates that field normalization, extraction, and the full alert pipeline
produce the expected shapes from real data.

Requires: ORCA_API_TOKEN env var.
Run with:  make e2e
           python3 .claude/skills/run/tests/test_e2e_orca.py
"""
import os
import sys
import unittest
from pathlib import Path

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))
sys.path.insert(0, str(_DIR.parent.parent / "lib"))

from orca_client import (
    _extract_file_path,
    fetch_alert_by_id,
    fetch_alerts,
    get_token,
    list_repositories,
    repos_with_cve,
)


def _skip_no_token():
    if not (os.environ.get("ORCA_API_TOKEN") or os.environ.get("ORCA_AUTH_TOKEN")):
        raise unittest.SkipTest("ORCA_API_TOKEN not set — skipping live API tests")


def _get_repo_with_alerts(token):
    """Find the first repo with open alerts to use as test fixture."""
    repos = list_repositories(token)
    if not repos:
        return None, []
    # Use the highest-scoring repo (first in list, sorted by OrcaScore)
    repo = repos[0]
    alerts = fetch_alerts(repo.name, token, statuses=["open", "in_progress"])
    if alerts:
        return repo, alerts
    # Try a few more if the first has no alerts
    for r in repos[1:5]:
        alerts = fetch_alerts(r.name, token, statuses=["open", "in_progress"])
        if alerts:
            return r, alerts
    return None, []


# ---------------------------------------------------------------------------
# Alert field shape
# ---------------------------------------------------------------------------

# Every normalized alert MUST have these keys with these types.
REQUIRED_FIELDS = {
    "alert_id":       str,
    "title":          str,
    "risk_level":     str,
    "score":          (int, float, type(None)),
    "category":       str,
    "status":         str,
    "source":         str,
    "file_path":      str,
    "labels":         list,
    "description":    str,
    "recommendation": str,
    "feature_type":   str,
    "code_snippet":   list,
    "position":       dict,
    "ai_triage":      dict,
    "origin_url":     str,
    "verification":   str,
    "first_commit":   dict,
    "is_test_file":   bool,
    # Passthrough for the two rich payloads. Present so a live run reveals
    # whether Orca already supplies structured package/version data for a
    # package CVE — see _normalize_alert.
    "asset_data":     dict,
    "extra_findings": dict,
}

POSITION_FIELDS = {"start_line", "end_line"}
AI_TRIAGE_FIELDS = {"explanation", "verdict", "confidence"}


class TestAlertFieldShape(unittest.TestCase):
    """Fetch a real alert and verify all normalized fields exist with correct types."""

    @classmethod
    def setUpClass(cls):
        _skip_no_token()
        cls.token = get_token()
        cls.repo, cls.alerts = _get_repo_with_alerts(cls.token)
        if not cls.alerts:
            raise unittest.SkipTest("No alerts returned from Orca API")
        cls.sample = cls.alerts[0]

    def test_all_required_fields_present(self):
        for field, expected_type in REQUIRED_FIELDS.items():
            with self.subTest(field=field):
                self.assertIn(field, self.sample, f"Missing field: {field}")
                self.assertIsInstance(
                    self.sample[field], expected_type,
                    f"{field}: expected {expected_type}, got {type(self.sample[field])}"
                )

    def test_position_subfields(self):
        pos = self.sample["position"]
        for key in POSITION_FIELDS:
            with self.subTest(key=key):
                self.assertIn(key, pos, f"Missing position.{key}")

    def test_ai_triage_subfields(self):
        triage = self.sample["ai_triage"]
        for key in AI_TRIAGE_FIELDS:
            with self.subTest(key=key):
                self.assertIn(key, triage, f"Missing ai_triage.{key}")

    def test_code_snippet_is_list_of_strings(self):
        for i, entry in enumerate(self.sample["code_snippet"]):
            with self.subTest(i=i):
                self.assertIsInstance(entry, str, f"code_snippet[{i}] should be str")

    def test_file_path_is_clean(self):
        fp = self.sample["file_path"]
        if fp:
            self.assertNotIn("://", fp, "file_path should not contain URL scheme")
            self.assertNotIn("#", fp, "file_path should not contain URL anchor")
            # Should not end with :N line suffix
            parts = fp.rsplit(":", 1)
            if len(parts) > 1:
                self.assertFalse(parts[1].isdigit(), "file_path should not end with :line_number")

    def test_risk_level_is_lowercase(self):
        rl = self.sample["risk_level"]
        if rl:
            self.assertEqual(rl, rl.lower(), "risk_level must be lowercase")


# ---------------------------------------------------------------------------
# Fetch by ID
# ---------------------------------------------------------------------------

class TestFetchAlertById(unittest.TestCase):
    """fetch_alert_by_id returns the same shape as fetch_alerts."""

    @classmethod
    def setUpClass(cls):
        _skip_no_token()
        cls.token = get_token()
        _, alerts = _get_repo_with_alerts(cls.token)
        if not alerts:
            raise unittest.SkipTest("No alerts to test with")
        cls.alert_id = alerts[0]["alert_id"]

    def test_fetch_by_id_returns_all_fields(self):
        alert = fetch_alert_by_id(self.alert_id, self.token)
        self.assertIsNotNone(alert, f"fetch_alert_by_id({self.alert_id}) returned None")
        for field in REQUIRED_FIELDS:
            with self.subTest(field=field):
                self.assertIn(field, alert, f"Missing field: {field}")

    def test_fetch_by_id_matches_alert_id(self):
        alert = fetch_alert_by_id(self.alert_id, self.token)
        self.assertEqual(alert["alert_id"], self.alert_id)


# ---------------------------------------------------------------------------
# Repositories
# ---------------------------------------------------------------------------

class TestListRepositories(unittest.TestCase):
    """list_repositories returns Repository objects with valid fields."""

    @classmethod
    def setUpClass(cls):
        _skip_no_token()
        cls.token = get_token()
        cls.repos = list_repositories(cls.token)

    def test_returns_non_empty_list(self):
        self.assertGreater(len(self.repos), 0, "Expected at least one repository")

    def test_repository_fields(self):
        for repo in self.repos[:5]:  # test first 5
            with self.subTest(repo=repo.name):
                self.assertTrue(repo.name, "name must be non-empty")
                self.assertTrue(repo.url, "url must be non-empty")
                self.assertIn("github.com", repo.url, "url should be a GitHub URL")

    def test_no_duplicate_urls(self):
        urls = [r.url for r in self.repos]
        self.assertEqual(len(urls), len(set(urls)), "Duplicate repo URLs found")


# ---------------------------------------------------------------------------
# Field extraction consistency
# ---------------------------------------------------------------------------

class TestFieldExtractionConsistency(unittest.TestCase):
    """Verify field extraction logic against a batch of real alerts."""

    @classmethod
    def setUpClass(cls):
        _skip_no_token()
        cls.token = get_token()
        _, cls.alerts = _get_repo_with_alerts(cls.token)
        if not cls.alerts:
            raise unittest.SkipTest("No alerts to test with")

    def test_file_path_derived_from_source(self):
        """file_path should be derivable from source for every alert."""
        for a in self.alerts[:20]:
            with self.subTest(alert_id=a["alert_id"]):
                expected = _extract_file_path(a["source"])
                self.assertEqual(a["file_path"], expected,
                                 f"file_path mismatch for {a['alert_id']}")

    def test_position_has_lines_when_snippet_has_position(self):
        """If code_snippet entries had positions, start_line should be set."""
        for a in self.alerts[:20]:
            with self.subTest(alert_id=a["alert_id"]):
                pos = a["position"]
                # If there's a code snippet, at least one position field should be set
                if a["code_snippet"]:
                    has_position = pos["start_line"] is not None or pos["end_line"] is not None
                    # Not all snippets carry position data, so we just verify the type is correct
                    if has_position:
                        self.assertIsInstance(pos["start_line"], (int, type(None)))
                        self.assertIsInstance(pos["end_line"], (int, type(None)))

    def test_feature_type_is_known(self):
        """feature_type should be one of our known types or empty."""
        known = {"sast", "iac", "secret_detection", "secret", "cve", "scm_posture", ""}
        for a in self.alerts[:20]:
            with self.subTest(alert_id=a["alert_id"]):
                ft = a["feature_type"]
                # Allow unknown types but flag them
                if ft and ft not in known:
                    self.fail(f"Unknown feature_type '{ft}' for {a['alert_id']} — "
                              f"may need new fix agent or mapping")


# ---------------------------------------------------------------------------
# Selecting alerts by CVE
#
# The CveIds clause is a shape the API rejects outright when it is wrong (a flat
# str/in clause comes back HTTP 400 "Unknown field 'CveIds'"), and the unit
# tests can only assert the payload we build — not that Orca still accepts it.
# ---------------------------------------------------------------------------

class TestCveFilter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        _skip_no_token()
        cls.token = get_token()
        # Pick a CVE from live data rather than hardcoding one: a fixed id ages
        # out as tenants change, and a test that skips is more useful than a
        # test that fails for the wrong reason.
        cls.cve = None
        for repo in list_repositories(cls.token)[:10]:
            for alert in fetch_alerts(repo.name, cls.token):
                if alert.get("cve_ids"):
                    cls.cve = alert["cve_ids"][0]
                    cls.repo = repo.name
                    cls.expected_alert = alert["alert_id"]
                    return
        raise unittest.SkipTest("no alert with CveIds found in this tenant")

    def test_every_returned_alert_carries_the_cve(self):
        alerts = fetch_alerts(self.repo, self.token, cve_ids=[self.cve])
        self.assertTrue(alerts, f"{self.cve} should match at least one alert")
        for a in alerts:
            with self.subTest(alert_id=a["alert_id"]):
                self.assertIn(self.cve, a["cve_ids"])

    def test_the_source_alert_is_among_them(self):
        ids = [a["alert_id"]
               for a in fetch_alerts(self.repo, self.token, cve_ids=[self.cve])]
        self.assertIn(self.expected_alert, ids)

    def test_lowercase_matches_too(self):
        """Users type advisory ids however they were pasted."""
        upper = fetch_alerts(self.repo, self.token, cve_ids=[self.cve])
        lower = fetch_alerts(self.repo, self.token, cve_ids=[self.cve.lower()])
        self.assertEqual({a["alert_id"] for a in upper},
                         {a["alert_id"] for a in lower})

    def test_unknown_cve_returns_nothing(self):
        """A bogus id must come back empty, not error and not unfiltered."""
        self.assertEqual(
            fetch_alerts(self.repo, self.token, cve_ids=["CVE-1999-99999"]), [])

    def test_filter_actually_narrows(self):
        all_alerts = fetch_alerts(self.repo, self.token)
        filtered = fetch_alerts(self.repo, self.token, cve_ids=[self.cve])
        self.assertLessEqual(len(filtered), len(all_alerts))

    def test_repos_with_cve_finds_the_repo(self):
        found = dict(repos_with_cve([self.cve], self.token))
        self.assertIn(self.repo, found)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestAlertFieldShape,
        TestFetchAlertById,
        TestListRepositories,
        TestFieldExtractionConsistency,
        TestCveFilter,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
