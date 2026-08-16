#!/usr/bin/env python3
"""
Tests for the version-decision data layer (skills/lib/version_data.py).

Hermetic: no network. Fetching is injected, and the pillow regression case runs
against trimmed recordings of the real OSV and deps.dev responses in
tests/fixtures/version_data/.

Run with: python3 tests/test_version_data.py
"""
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))                 # security-engineer/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # lib/

import version_data
from version_data import (
    ECOSYSTEMS,
    AdvisoryScope,
    VersionDataFetcher,
    _events_to_intervals,
    _preferred_id,
    _safe_upgrades,
    advisory_scopes,
    bump_class,
    ecosystem_for_manifest,
    parse_version,
    resolve_bump,
    resolve_ecosystem,
)

_FIXTURES = _DIR / "fixtures" / "version_data"
_PYPI = ECOSYSTEMS["pypi"]


def _load(name):
    with open(_FIXTURES / name) as f:
        return json.load(f)


class FakeFetcher:
    """Stands in for VersionDataFetcher so tests never touch the network.

    Mirrors the real fetcher's contract exactly, including that a failure
    surfaces as a raised exception for resolve_bump to swallow.
    """

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


def _vuln(vid, events, aliases=None, package="pkg", ecosystem="PyPI"):
    """A minimal OSV record with one ECOSYSTEM range."""
    return {
        "id": vid,
        "aliases": aliases or [],
        "affected": [{
            "package": {"name": package, "ecosystem": ecosystem},
            "ranges": [{"type": "ECOSYSTEM", "events": events}],
        }],
    }


# ---------------------------------------------------------------------------
# 1. Version parsing
# ---------------------------------------------------------------------------

class TestParseVersion(unittest.TestCase):
    """Table-driven: (release tuple, is_prerelease, understood) per version."""

    # (description, raw, expected_release, expected_is_prerelease, expected_understood)
    CASES = [
        ("plain three-part",        "1.2.3",        (1, 2, 3), False, True),
        ("trailing zeros stripped", "1.0.0",        (1,),      False, True),
        ("single component",        "5",            (5,),      False, True),
        ("go v prefix",             "v0.17.0",      (0, 17),   False, True),
        ("semver prerelease",       "2.0.0-alpha.1", (2,),     True,  True),
        ("semver build metadata",   "1.2.3+build.5", (1, 2, 3), False, True),
        ("go +incompatible",        "v2.0.0+incompatible", (2,), False, True),
        ("pep440 rc",               "1.0rc1",       (1,),      True,  True),
        ("pep440 post",             "1.0.post1",    (1,),      False, True),
        ("pep440 dev",              "1.0.dev2",     (1,),      True,  True),
        ("pep440 epoch",            "1!2.0",        (2,),      False, True),
        ("java RELEASE qualifier",  "2.7.18.RELEASE", (2, 7, 18), False, True),
        ("java Final qualifier",    "1.0.Final",    (1,),      False, True),
        ("maven snapshot",          "1.0-SNAPSHOT", (1,),      True,  True),
        # A pseudo-version is a prerelease of 0.0.0, which is where it belongs.
        ("go pseudo-version",       "v0.0.0-20210119194325-5f4716e94777",
         (0,), True, True),
        # Unreadable suffixes are reported as prereleases so they are never
        # chosen as a bump target.
        ("unknown suffix",          "1.7.5-py2.4-win32", (1, 7, 5), True, False),
    ]

    def test_cases(self):
        for desc, raw, release, is_pre, understood in self.CASES:
            with self.subTest(desc):
                v = parse_version(raw)
                self.assertIsNotNone(v, desc)
                self.assertEqual(v.release, release, f"{desc}: release")
                self.assertEqual(v.is_prerelease, is_pre, f"{desc}: is_prerelease")
                self.assertEqual(v.understood, understood, f"{desc}: understood")

    # (description, raw)
    UNPARSEABLE = [
        ("empty string", ""),
        ("whitespace only", "   "),
        ("None", None),
        ("no numeric release", "latest"),
        ("leading text", "version-one"),
    ]

    def test_unparseable(self):
        for desc, raw in self.UNPARSEABLE:
            with self.subTest(desc):
                self.assertIsNone(parse_version(raw), desc)


class TestVersionOrdering(unittest.TestCase):
    """Table-driven: (lower, higher) pairs that must compare strictly."""

    # (description, lower, higher)
    CASES = [
        ("patch order",            "1.2.3", "1.2.4"),
        ("minor order",            "1.2.9", "1.3.0"),
        ("major order",            "9.9.9", "10.0.0"),
        ("numeric not lexical",    "1.9.0", "1.10.0"),
        ("prerelease before release", "2.0.0-alpha.1", "2.0.0"),
        ("rc before release",      "1.0rc1", "1.0"),
        ("dev before rc",          "1.0.dev1", "1.0rc1"),
        ("alpha before beta",      "1.0a1", "1.0b1"),
        ("release before post",    "1.0", "1.0.post1"),
        ("epoch dominates",        "9.0", "1!1.0"),
        ("pseudo-version below release", "v0.0.0-20210119194325-5f4716e94777",
         "v0.1.0"),
        ("snapshot before release", "1.0-SNAPSHOT", "1.0"),
    ]

    def test_ordering(self):
        for desc, lower, higher in self.CASES:
            with self.subTest(desc):
                lo, hi = parse_version(lower), parse_version(higher)
                self.assertTrue(lo < hi, f"{desc}: expected {lower} < {higher}")
                self.assertFalse(hi < lo, f"{desc}: expected NOT {higher} < {lower}")

    # (description, a, b) — must compare equal
    EQUAL = [
        ("trailing zero",     "1.0", "1"),
        ("two trailing zeros", "1.0.0", "1"),
        ("v prefix ignored",  "v1.2.3", "1.2.3"),
        ("build metadata ignored", "1.2.3+abc", "1.2.3"),
    ]

    def test_equality(self):
        for desc, a, b in self.EQUAL:
            with self.subTest(desc):
                va, vb = parse_version(a), parse_version(b)
                self.assertEqual(va.sort_key(), vb.sort_key(), desc)


class TestBumpClass(unittest.TestCase):
    """Table-driven: how far does current -> target reach?"""

    # (description, current, target, expected)
    CASES = [
        ("patch",            "1.2.3", "1.2.9", "patch"),
        ("minor",            "1.2.3", "1.5.0", "minor"),
        ("major",            "8.3.1", "9.0.0", "major"),
        ("four majors",      "8.3.1", "12.3.0", "major"),
        ("same version",     "1.2.3", "1.2.3", "patch"),
        ("zero-major minor", "0.1.0", "0.2.0", "minor"),
        ("unparseable current", None, "1.0.0", "unknown"),
        ("unparseable target",  "1.0.0", None, "unknown"),
    ]

    def test_cases(self):
        for desc, current, target, expected in self.CASES:
            with self.subTest(desc):
                cur = parse_version(current) if current else None
                tgt = parse_version(target) if target else None
                self.assertEqual(bump_class(cur, tgt), expected, desc)


# ---------------------------------------------------------------------------
# 2. Ecosystems
# ---------------------------------------------------------------------------

class TestEcosystemResolution(unittest.TestCase):
    """Every spelling a caller might have must land on one canonical key."""

    # (description, input, expected_key)
    CASES = [
        ("canonical pypi",   "pypi",      "pypi"),
        ("alias pip",        "pip",       "pypi"),
        ("uppercase",        "PyPI",      "pypi"),
        ("padded",           "  npm  ",   "npm"),
        ("osv crates.io",    "crates.io", "cargo"),
        ("alias golang",     "golang",    "go"),
        ("alias java",       "java",      "maven"),
        ("alias dotnet",     "dotnet",    "nuget"),
        ("unknown",          "cpan",      None),
        ("empty",            "",          None),
    ]

    def test_cases(self):
        for desc, raw, expected in self.CASES:
            with self.subTest(desc):
                eco = resolve_ecosystem(raw)
                self.assertEqual(eco.key if eco else None, expected, desc)


class TestEcosystemForManifest(unittest.TestCase):
    """The manifest path in an Orca alert is how we learn the ecosystem."""

    # (description, path, expected_key)
    CASES = [
        ("requirements.txt",     "./python-ml/requirements.txt", "pypi"),
        ("pyproject",            "pyproject.toml",               "pypi"),
        ("go.mod",               "services/api/go.mod",          "go"),
        ("go.sum",               "go.sum",                       "go"),
        ("package.json",         "web/package.json",             "npm"),
        ("lockfile counts",      "web/package-lock.json",        "npm"),
        ("pom.xml",              "java/pom.xml",                 "maven"),
        ("Cargo.toml",           "Cargo.toml",                   "cargo"),
        ("Gemfile",              "Gemfile",                      "rubygems"),
        ("case-insensitive",     "REQUIREMENTS.TXT",             "pypi"),
        ("unrelated file",       "server.js",                    None),
        ("empty",                "",                             None),
    ]

    def test_cases(self):
        for desc, path, expected in self.CASES:
            with self.subTest(desc):
                eco = ecosystem_for_manifest(path)
                self.assertEqual(eco.key if eco else None, expected, desc)


# ---------------------------------------------------------------------------
# 3. OSV ranges -> intervals -> coverage
# ---------------------------------------------------------------------------

class TestEventsToIntervals(unittest.TestCase):
    """Table-driven: OSV events folded into (introduced, fixed, last_affected)."""

    # (description, events, expected) where expected uses strings / None
    CASES = [
        ("introduced and fixed",
         [{"introduced": "1.0"}, {"fixed": "2.0"}],
         [("1.0", "2.0", None)]),
        # "0" is OSV's sentinel for "from the beginning" and must become an open
        # lower bound, not a literal version 0.
        ("zero sentinel opens the range",
         [{"introduced": "0"}, {"fixed": "12.3.0"}],
         [(None, "12.3.0", None)]),
        ("last_affected instead of fixed",
         [{"introduced": "1.0"}, {"last_affected": "1.9"}],
         [("1.0", None, "1.9")]),
        ("two disjoint intervals",
         [{"introduced": "1.0"}, {"fixed": "1.5"},
          {"introduced": "2.0"}, {"fixed": "2.5"}],
         [("1.0", "1.5", None), ("2.0", "2.5", None)]),
        # An advisory with no fix yet leaves the interval open at the top.
        ("unclosed interval stays open",
         [{"introduced": "3.0"}],
         [("3.0", None, None)]),
        ("consecutive introduced without fix",
         [{"introduced": "1.0"}, {"introduced": "2.0"}],
         [("1.0", None, None), ("2.0", None, None)]),
        ("no events", [], []),
        ("junk events ignored", ["nonsense", {"unknown_key": "x"}], []),
    ]

    def test_cases(self):
        for desc, events, expected in self.CASES:
            with self.subTest(desc):
                got = _events_to_intervals(events)
                as_str = [tuple(str(x) if x is not None else None for x in iv)
                          for iv in got]
                self.assertEqual(as_str, expected, desc)


class TestAdvisoryCoverage(unittest.TestCase):
    """Table-driven: is a given version inside an advisory's vulnerable set?"""

    def _scope(self, events=None, exact=None):
        scope = AdvisoryScope(advisory_id="CVE-0000-1")
        if events:
            scope.intervals = _events_to_intervals(events)
        if exact:
            scope.exact_versions = set(exact)
        return scope

    # (description, events, exact_versions, version, expected_covered)
    CASES = [
        ("inside range",       [{"introduced": "1.0"}, {"fixed": "2.0"}], None,
         "1.5", True),
        ("at introduced bound (inclusive)",
         [{"introduced": "1.0"}, {"fixed": "2.0"}], None, "1.0", True),
        ("at fixed bound (exclusive)",
         [{"introduced": "1.0"}, {"fixed": "2.0"}], None, "2.0", False),
        ("below range",        [{"introduced": "1.0"}, {"fixed": "2.0"}], None,
         "0.9", False),
        ("above range",        [{"introduced": "1.0"}, {"fixed": "2.0"}], None,
         "2.1", False),
        ("zero sentinel covers everything below fixed",
         [{"introduced": "0"}, {"fixed": "12.3.0"}], None, "8.3.2", True),
        ("zero sentinel stops at fixed",
         [{"introduced": "0"}, {"fixed": "12.3.0"}], None, "12.3.0", False),
        ("last_affected is inclusive",
         [{"introduced": "1.0"}, {"last_affected": "1.9"}], None, "1.9", True),
        ("above last_affected",
         [{"introduced": "1.0"}, {"last_affected": "1.9"}], None, "1.10", False),
        ("open interval covers everything above",
         [{"introduced": "3.0"}], None, "99.0", True),
        ("explicit version list matches",  None, ["1.2.3"], "1.2.3", True),
        ("explicit version list misses",   None, ["1.2.3"], "1.2.4", False),
        ("second of two intervals",
         [{"introduced": "1.0"}, {"fixed": "1.5"},
          {"introduced": "2.0"}, {"fixed": "2.5"}], None, "2.1", True),
        ("gap between two intervals",
         [{"introduced": "1.0"}, {"fixed": "1.5"},
          {"introduced": "2.0"}, {"fixed": "2.5"}], None, "1.7", False),
    ]

    def test_cases(self):
        for desc, events, exact, version, expected in self.CASES:
            with self.subTest(desc):
                scope = self._scope(events, exact)
                self.assertEqual(scope.covers(parse_version(version)), expected,
                                 desc)


class TestAdvisoryScopeFiltering(unittest.TestCase):
    """Only ranges for the right package, right ecosystem, and right type count."""

    def test_other_package_ignored(self):
        vulns = [_vuln("CVE-1", [{"introduced": "0"}, {"fixed": "2.0"}],
                       package="somethingelse")]
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertEqual(len(scopes), 1)
        self.assertFalse(scopes[0].scoped,
                         "a record that names another package gives us nothing "
                         "to compare and must be reported as unscoped")

    def test_other_ecosystem_ignored(self):
        vulns = [_vuln("CVE-1", [{"introduced": "0"}, {"fixed": "2.0"}],
                       ecosystem="npm")]
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertFalse(scopes[0].scoped)

    def test_suffixed_ecosystem_still_matches(self):
        """OSV suffixes distro ecosystems; a prefix match must still bind."""
        vulns = [_vuln("CVE-1", [{"introduced": "0"}, {"fixed": "2.0"}],
                       ecosystem="PyPI")]
        vulns[0]["affected"][0]["package"]["ecosystem"] = "PyPI"
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertTrue(scopes[0].scoped)

    def test_git_ranges_skipped(self):
        """Commit hashes are not versions; a GIT-only record is unscoped."""
        vulns = [{
            "id": "OSV-1", "aliases": [],
            "affected": [{
                "package": {"name": "pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "GIT", "repo": "https://x/y",
                            "events": [{"introduced": "abc123"},
                                       {"fixed": "def456"}]}],
            }],
        }]
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertFalse(scopes[0].scoped)
        self.assertEqual(scopes[0].intervals, [])

    def test_record_without_id_dropped(self):
        scopes = advisory_scopes([{"affected": []}], "pkg", _PYPI)
        self.assertEqual(scopes, [])


# ---------------------------------------------------------------------------
# 4. Alias merging
# ---------------------------------------------------------------------------

class TestPreferredId(unittest.TestCase):
    """Reviewers think in CVEs, so a CVE id wins when the group has one."""

    # (description, ids, expected)
    CASES = [
        ("cve preferred over ghsa", {"GHSA-aaa", "CVE-2024-1"}, "CVE-2024-1"),
        ("ghsa preferred over pysec", {"PYSEC-2024-1", "GHSA-aaa"}, "GHSA-aaa"),
        ("pysec over unknown", {"PYSEC-2024-1", "BIT-x-1"}, "PYSEC-2024-1"),
        ("lowest cve when several", {"CVE-2024-2", "CVE-2024-1"}, "CVE-2024-1"),
        ("falls back to sorted", {"BIT-b", "BIT-a"}, "BIT-a"),
        ("empty", set(), ""),
    ]

    def test_cases(self):
        for desc, ids, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(_preferred_id(ids), expected, desc)


class TestAliasMerge(unittest.TestCase):
    """OSV returns the same flaw several times; counting twice misleads reviewers."""

    def test_ghsa_and_pysec_collapse(self):
        vulns = [
            _vuln("GHSA-aaa", [{"introduced": "0"}, {"fixed": "2.0"}],
                  aliases=["CVE-2024-1", "PYSEC-2024-9"]),
            _vuln("PYSEC-2024-9", [{"introduced": "0"}, {"fixed": "2.0"}],
                  aliases=["CVE-2024-1"]),
        ]
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertEqual(len(scopes), 1, "two records for one flaw must merge")
        self.assertEqual(scopes[0].advisory_id, "CVE-2024-1")
        self.assertEqual(len(scopes[0].intervals), 1,
                         "identical intervals should be deduped")

    def test_transitive_merge(self):
        """A record bridging two groups must pull them together, not orphan one."""
        vulns = [
            _vuln("GHSA-a", [{"introduced": "0"}, {"fixed": "2.0"}]),
            _vuln("PYSEC-b", [{"introduced": "0"}, {"fixed": "2.0"}]),
            _vuln("CVE-2024-7", [{"introduced": "0"}, {"fixed": "2.0"}],
                  aliases=["GHSA-a", "PYSEC-b"]),
        ]
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertEqual(len(scopes), 1)
        self.assertEqual(scopes[0].advisory_id, "CVE-2024-7")

    def test_distinct_flaws_stay_separate(self):
        vulns = [
            _vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "2.0"}]),
            _vuln("CVE-2024-2", [{"introduced": "0"}, {"fixed": "3.0"}]),
        ]
        self.assertEqual(len(advisory_scopes(vulns, "pkg", _PYPI)), 2)

    def test_scoped_if_any_record_has_ranges(self):
        """One database filling in the ranges is enough to reason about a flaw."""
        unscoped = {"id": "PYSEC-1", "aliases": ["CVE-2024-5"], "affected": []}
        scoped = _vuln("CVE-2024-5", [{"introduced": "0"}, {"fixed": "2.0"}])
        scopes = advisory_scopes([unscoped, scoped], "pkg", _PYPI)
        self.assertEqual(len(scopes), 1)
        self.assertTrue(scopes[0].scoped)

    def test_differing_intervals_are_unioned(self):
        vulns = [
            _vuln("GHSA-a", [{"introduced": "0"}, {"fixed": "2.0"}],
                  aliases=["CVE-2024-1"]),
            _vuln("CVE-2024-1", [{"introduced": "3.0"}, {"fixed": "3.5"}]),
        ]
        scopes = advisory_scopes(vulns, "pkg", _PYPI)
        self.assertEqual(len(scopes), 1)
        self.assertEqual(len(scopes[0].intervals), 2)
        self.assertTrue(scopes[0].covers(parse_version("1.0")))
        self.assertTrue(scopes[0].covers(parse_version("3.1")))
        self.assertFalse(scopes[0].covers(parse_version("2.5")))


# ---------------------------------------------------------------------------
# 5. Candidate selection
# ---------------------------------------------------------------------------

class TestSafeUpgrades(unittest.TestCase):
    """What may be offered as a bump target, and in what order."""

    def _scopes(self, events):
        return advisory_scopes([_vuln("CVE-1", events)], "pkg", _PYPI)

    def test_lowest_first(self):
        published = ["1.0.0", "3.0.0", "2.0.0", "1.5.0"]
        scopes = self._scopes([{"introduced": "0"}, {"fixed": "1.5.0"}])
        got = [raw for raw, _ in _safe_upgrades(published,
                                                parse_version("1.0.0"), scopes)]
        self.assertEqual(got, ["1.5.0", "2.0.0", "3.0.0"])

    def test_excludes_current_and_below(self):
        published = ["1.0.0", "0.9.0", "2.0.0"]
        got = [raw for raw, _ in _safe_upgrades(published,
                                                parse_version("1.0.0"), [])]
        self.assertEqual(got, ["2.0.0"],
                         "a bump must go up; equal or lower is not an upgrade")

    def test_prereleases_excluded_for_stable_current(self):
        published = ["2.0.0-rc1", "2.0.0"]
        got = [raw for raw, _ in _safe_upgrades(published,
                                                parse_version("1.0.0"), [])]
        self.assertEqual(got, ["2.0.0"],
                         "upgrading a pinned stable release onto an rc is not a fix")

    def test_prereleases_allowed_within_the_same_release(self):
        """Pinned to 2.0.0-alpha.1, moving to 2.0.0-rc1 is a real upgrade."""
        published = ["2.0.0-rc1", "2.0.0"]
        got = [raw for raw, _ in _safe_upgrades(published,
                                                parse_version("2.0.0-alpha.1"), [])]
        self.assertEqual(got, ["2.0.0-rc1", "2.0.0"])

    def test_prereleases_of_other_releases_still_excluded(self):
        """The Go pseudo-version trap: being on a prerelease must not make every
        later prerelease a candidate, or retry offers a commit snapshot."""
        published = [
            "v0.56.0",
            "v0.56.1-0.20260623201039-5a3baee349e6",
            "v0.57.0-rc1",
        ]
        current = parse_version("v0.0.0-20210119194325-5f4716e94777")
        got = [raw for raw, _ in _safe_upgrades(published, current, [])]
        self.assertEqual(got, ["v0.56.0"])

    def test_unreadable_versions_excluded(self):
        """We do not bump to something we could not parse confidently."""
        published = ["1.7.5-py2.4-win32", "2.0.0"]
        got = [raw for raw, _ in _safe_upgrades(published,
                                                parse_version("1.0.0"), [])]
        self.assertEqual(got, ["2.0.0"])

    def test_vulnerable_versions_excluded(self):
        published = ["1.1.0", "1.2.0", "1.3.0"]
        scopes = self._scopes([{"introduced": "0"}, {"fixed": "1.3.0"}])
        got = [raw for raw, _ in _safe_upgrades(published,
                                                parse_version("1.0.0"), scopes)]
        self.assertEqual(got, ["1.3.0"])


# ---------------------------------------------------------------------------
# 6. resolve_bump
# ---------------------------------------------------------------------------

class TestResolveBump(unittest.TestCase):
    """The decision, end to end, against an injected fetcher."""

    def test_minimum_safe_not_latest(self):
        """The policy is lowest safe version — not newest, which is the bug
        this module exists to remove."""
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "1.5.0"}])],
            versions=["1.0.0", "1.5.0", "1.6.0", "2.0.0", "3.0.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual(d.target_version, "1.5.0")
        self.assertEqual(d.bump_class, "minor")
        self.assertEqual(d.majors_crossed, 0)
        self.assertEqual(d.advisories_cleared, ["CVE-2024-1"])
        self.assertEqual(d.advisories_remaining, [])
        self.assertTrue(d.resolved)

    def test_candidates_carry_alternatives(self):
        """The retry loop needs a next candidate to advance to."""
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "1.5.0"}])],
            versions=["1.0.0", "1.5.0", "1.6.0", "2.0.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual([c["version"] for c in d.candidates],
                         ["1.5.0", "1.6.0", "2.0.0"])
        self.assertEqual([c["bump_class"] for c in d.candidates],
                         ["minor", "minor", "major"])

    def test_candidates_capped(self):
        fetcher = FakeFetcher(vulns=[], versions=[f"1.0.{n}" for n in range(20)])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual(len(d.candidates), version_data._MAX_CANDIDATES)

    def test_crossing_majors_is_labelled_not_refused(self):
        """Policy is minimum-safe at any distance: cross the boundary, label it."""
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "12.3.0"}])],
            versions=["8.3.1", "9.0.0", "11.0.0", "12.3.0"])
        d = resolve_bump("pypi", "pkg", "8.3.1", fetcher=fetcher)
        self.assertEqual(d.target_version, "12.3.0")
        self.assertEqual(d.bump_class, "major")
        self.assertEqual(d.majors_crossed, 4)

    def test_avoids_bumping_into_a_different_advisory(self):
        """Querying package-wide is the point: 2.0.0 fixes CVE-1 but has CVE-2."""
        fetcher = FakeFetcher(
            vulns=[
                _vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "2.0.0"}]),
                _vuln("CVE-2024-2", [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]),
            ],
            versions=["1.0.0", "2.0.0", "2.1.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual(d.target_version, "2.1.0",
                         "2.0.0 clears CVE-1 but introduces CVE-2")
        self.assertEqual(d.advisories_cleared, ["CVE-2024-1"])

    def test_unaffected_current_version(self):
        fetcher = FakeFetcher(vulns=[], versions=["1.0.0", "1.1.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual(d.target_version, "1.1.0")
        self.assertEqual(d.advisories_cleared, [])
        self.assertIn("no advisory in OSV covers", d.rationale)

    def test_unscoped_advisories_are_reported(self):
        """An advisory we cannot assess must be surfaced, never silently dropped."""
        fetcher = FakeFetcher(
            vulns=[{"id": "CVE-2024-9", "aliases": [], "affected": []}],
            versions=["1.0.0", "1.1.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual(d.advisories_unknown_scope, ["CVE-2024-9"])
        self.assertIn("could not be assessed", d.rationale)

    def test_partial_upgrade_when_nothing_is_fully_safe(self):
        """A partial fix that says so beats no fix that pretends."""
        fetcher = FakeFetcher(
            vulns=[
                _vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "2.0.0"}]),
                _vuln("CVE-2024-2", [{"introduced": "0"}]),      # never fixed
            ],
            versions=["1.0.0", "2.0.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertEqual(d.target_version, "2.0.0")
        self.assertEqual(d.advisories_cleared, ["CVE-2024-1"])
        self.assertEqual(d.advisories_remaining, ["CVE-2024-2"])
        self.assertIn("still affected by", d.rationale)

    def test_no_upgrade_clears_anything(self):
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-2024-2", [{"introduced": "0"}])],
            versions=["1.0.0", "2.0.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertIsNone(d.target_version)
        self.assertIsNotNone(d.error)
        self.assertIn("Needs a human decision", d.rationale)

    def test_rationale_names_the_bump_and_the_advisories(self):
        fetcher = FakeFetcher(
            vulns=[_vuln("CVE-2024-1", [{"introduced": "0"}, {"fixed": "1.5.0"}])],
            versions=["1.0.0", "1.5.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertIn("pkg 1.0.0 → 1.5.0", d.rationale)
        self.assertIn("CVE-2024-1", d.rationale)


class TestResolveBumpErrors(unittest.TestCase):
    """Never raises: every failure returns a decision the caller can degrade on."""

    def test_unknown_ecosystem(self):
        d = resolve_bump("cpan", "pkg", "1.0.0", fetcher=FakeFetcher())
        self.assertIsNone(d.target_version)
        self.assertIn("unknown ecosystem", d.error)

    def test_unparseable_current_version(self):
        d = resolve_bump("pypi", "pkg", "latest", fetcher=FakeFetcher())
        self.assertIsNone(d.target_version)
        self.assertIn("cannot parse current version", d.error)

    def test_fetch_failure_is_swallowed(self):
        fetcher = FakeFetcher(raises=RuntimeError("HTTP 503 from api.osv.dev"))
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        self.assertIsNone(d.target_version)
        self.assertIn("HTTP 503", d.error)
        self.assertFalse(d.resolved)

    def test_no_published_versions(self):
        d = resolve_bump("pypi", "pkg", "1.0.0",
                         fetcher=FakeFetcher(vulns=[], versions=[]))
        self.assertIn("no published versions", d.error)

    def test_to_dict_is_json_serializable(self):
        """The decision is handed to a prompt and a PR body, so it must serialize."""
        fetcher = FakeFetcher(vulns=[], versions=["1.0.0", "1.1.0"])
        d = resolve_bump("pypi", "pkg", "1.0.0", fetcher=fetcher)
        json.dumps(d.to_dict())


# ---------------------------------------------------------------------------
# 7. The pillow regression — the case that motivated this module
# ---------------------------------------------------------------------------

class TestPillowRegression(unittest.TestCase):
    """Recorded from the real OSV and deps.dev responses.

    Three consecutive live runs bumped pillow 8.3.1 -> 12.3.0 behind three
    different explanations ("lowest with no unfixed CVEs", "latest with no
    advisories", and a body claiming 11.3.0 over a diff that said 12.3.0).
    12.3.0 turns out to be right — CVE-2026-55379 is `introduced: 0, fixed:
    12.3.0`, so nothing below it is safe — but it was right by luck. This test
    pins the *derivation*: the same inputs must produce the same target, the
    same distance, and a rationale naming the advisories that forced it.
    """

    @classmethod
    def setUpClass(cls):
        osv = _load("pillow.osv.json")
        versions = [v["versionKey"]["version"]
                    for v in _load("pillow.versions.json")["versions"]]
        cls.fetcher = FakeFetcher(vulns=osv["vulns"], versions=versions)

    def test_resolves_to_12_3_0(self):
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        self.assertIsNone(d.error)
        self.assertEqual(d.target_version, "12.3.0")

    def test_distance_is_recorded(self):
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        self.assertEqual(d.bump_class, "major")
        self.assertEqual(d.majors_crossed, 4,
                         "the four-major distance is exactly what impact "
                         "analysis needs told to it, not left to infer")

    def test_no_safer_alternative_exists(self):
        """One candidate means the retry loop has nowhere lower to fall back to."""
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        self.assertEqual([c["version"] for c in d.candidates], ["12.3.0"])

    def test_nothing_left_unresolved(self):
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        self.assertEqual(d.advisories_remaining, [])

    def test_advisories_are_deduped_across_databases(self):
        """OSV carries pillow as both GHSA and PYSEC records; counting both
        would overstate what the bump achieves by roughly double.

        Note some advisories genuinely have no alias at all (the fixture holds a
        GHSA and a PYSEC record with empty `aliases`), so the assertion is that
        no two reported ids describe the same flaw — not that every id is a CVE.
        """
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        ids = d.advisories_cleared
        self.assertEqual(len(ids), len(set(ids)), "ids must be unique")
        self.assertLess(len(ids), len(self.fetcher._vulns),
                        "merged ids must be fewer than raw records")

        groups = advisory_scopes(self.fetcher._vulns, "pillow", _PYPI)
        by_id = {g.advisory_id: set(g.aliases) for g in groups}
        for i, first in enumerate(ids):
            for second in ids[i + 1:]:
                self.assertFalse(
                    by_id.get(first, set()) & by_id.get(second, set()),
                    f"{first} and {second} share an alias — same flaw twice")

    def test_cve_id_wins_when_the_group_has_one(self):
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        groups = {g.advisory_id: g for g in
                  advisory_scopes(self.fetcher._vulns, "pillow", _PYPI)}
        for reported in d.advisories_cleared:
            cves = [a for a in groups[reported].aliases if a.startswith("CVE-")]
            if cves:
                self.assertTrue(reported.startswith("CVE-"),
                                f"{reported} has CVE aliases {cves} but was "
                                "reported under a less recognizable id")

    def test_rationale_is_specific(self):
        d = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        self.assertIn("pillow 8.3.1 → 12.3.0", d.rationale)
        self.assertIn("4 major versions", d.rationale)

    def test_decision_is_deterministic(self):
        """The original failure was non-determinism, so repeat and compare."""
        first = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
        for _ in range(3):
            again = resolve_bump("pypi", "pillow", "8.3.1", fetcher=self.fetcher)
            self.assertEqual(again.to_dict(), first.to_dict())


# ---------------------------------------------------------------------------
# 8. Cache
# ---------------------------------------------------------------------------

class TestCache(unittest.TestCase):
    """A cache we cannot write is a slow run, not a broken one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "cache"

    def tearDown(self):
        self.tmp.cleanup()

    def _fetcher(self, **kw):
        kw.setdefault("cache_dir", self.dir)
        return VersionDataFetcher(**kw)

    def test_write_then_read_round_trip(self):
        f = self._fetcher()
        path = f._cache_path("osv", _PYPI, "pkg")
        f._write_cache(path, {"vulns": [1, 2]})
        self.assertEqual(f._read_cache(path), {"vulns": [1, 2]})

    def test_second_call_hits_cache_and_does_not_refetch(self):
        f = self._fetcher()
        calls = []

        def fetch():
            calls.append(1)
            return {"payload": "x"}

        f._cached("osv", _PYPI, "pkg", fetch)
        f._cached("osv", _PYPI, "pkg", fetch)
        self.assertEqual(len(calls), 1)
        self.assertIn("(cache)", f.sources[-1])

    def test_expired_entry_is_refetched(self):
        f = self._fetcher(cache_ttl_sec=0)
        path = f._cache_path("osv", _PYPI, "pkg")
        f._write_cache(path, {"v": 1})
        time.sleep(0.01)
        self.assertIsNone(f._read_cache(path), "a stale entry must not be served")

    def test_offline_ignores_ttl(self):
        """When we cannot refresh, stale data beats no data."""
        writer = self._fetcher()
        path = writer._cache_path("osv", _PYPI, "pkg")
        writer._write_cache(path, {"v": 1})
        # Backdate well past any TTL.
        blob = json.loads(path.read_text())
        blob["fetched_at"] = time.time() - 10_000_000
        path.write_text(json.dumps(blob))

        offline = self._fetcher(offline=True)
        self.assertEqual(offline._read_cache(path), {"v": 1})

    def test_offline_never_fetches(self):
        f = self._fetcher(offline=True)
        called = []
        got = f._cached("osv", _PYPI, "pkg", lambda: called.append(1))
        self.assertIsNone(got)
        self.assertEqual(called, [])
        self.assertIn("offline", f.sources[-1])

    def test_format_change_invalidates(self):
        f = self._fetcher()
        path = f._cache_path("osv", _PYPI, "pkg")
        f._write_cache(path, {"v": 1})
        blob = json.loads(path.read_text())
        blob["cache_format"] = 999
        path.write_text(json.dumps(blob))
        self.assertIsNone(f._read_cache(path))

    def test_corrupt_cache_is_ignored_not_fatal(self):
        f = self._fetcher()
        path = f._cache_path("osv", _PYPI, "pkg")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json")
        self.assertIsNone(f._read_cache(path))

    def test_missing_cache_is_ignored(self):
        f = self._fetcher()
        self.assertIsNone(f._read_cache(f._cache_path("osv", _PYPI, "nope")))

    def test_no_temp_files_left_behind(self):
        """Write-then-rename must not litter, since 12 fixes share the dir."""
        f = self._fetcher()
        path = f._cache_path("osv", _PYPI, "pkg")
        f._write_cache(path, {"v": 1})
        leftovers = list(path.parent.glob("*.tmp"))
        self.assertEqual(leftovers, [])

    # (description, package name) — names that must not escape the cache dir
    UNSAFE_NAMES = [
        ("scoped npm package", "@babel/core"),
        ("go module path", "golang.org/x/net"),
        ("parent traversal", "../../etc/passwd"),
        ("absolute path", "/etc/passwd"),
    ]

    def test_package_names_cannot_escape_cache_dir(self):
        f = self._fetcher()
        root = self.dir.resolve()
        for desc, name in self.UNSAFE_NAMES:
            with self.subTest(desc):
                path = f._cache_path("osv", _PYPI, name).resolve()
                self.assertTrue(str(path).startswith(str(root)),
                                f"{desc}: {path} escaped {root}")
                self.assertEqual(path.parent, root / _PYPI.key, desc)


class TestFetcherParsesResponses(unittest.TestCase):
    """Shape of the two upstream payloads, pinned without touching the network."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = VersionDataFetcher(cache_dir=Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_osv_vulns_extracted(self):
        path = self.f._cache_path("osv", _PYPI, "pkg")
        self.f._write_cache(path, {"vulns": [{"id": "CVE-1"}]})
        self.assertEqual(self.f.osv_advisories("pkg", _PYPI), [{"id": "CVE-1"}])

    def test_osv_missing_vulns_key(self):
        path = self.f._cache_path("osv", _PYPI, "pkg")
        self.f._write_cache(path, {})
        self.assertEqual(self.f.osv_advisories("pkg", _PYPI), [])

    def test_deps_dev_versions_extracted(self):
        path = self.f._cache_path("versions", _PYPI, "pkg")
        self.f._write_cache(path, {"versions": [
            {"versionKey": {"version": "1.0.0"}},
            {"versionKey": {"version": "1.1.0"}},
            {"versionKey": {}},          # malformed entry must be skipped
            {},
        ]})
        self.assertEqual(self.f.published_versions("pkg", _PYPI),
                         ["1.0.0", "1.1.0"])


# ---------------------------------------------------------------------------
# 9. The resolve-version subcommand
# ---------------------------------------------------------------------------

class TestResolveVersionCommand(unittest.TestCase):
    """`run_agent.py resolve-version` — the by-hand entry point to the layer."""

    def _run(self, ecosystem="pypi", package="pkg", current="1.0.0",
             offline=False, cache_ttl=None, decision=None):
        """Invoke the subcommand with resolve_bump stubbed; return (json, exit)."""
        import argparse
        import contextlib
        import io

        import run_agent

        args = argparse.Namespace(ecosystem=ecosystem, package=package,
                                  current=current, offline=offline,
                                  cache_ttl=cache_ttl)
        captured = {}

        def fake_resolve_bump(eco, pkg, cur, **kwargs):
            captured["ecosystem"] = eco
            captured["kwargs"] = kwargs
            return decision or resolve_bump(
                "pypi", pkg, cur,
                fetcher=FakeFetcher(vulns=[], versions=["1.0.0", "1.1.0"]))

        buf = io.StringIO()
        code = 0
        with patch.object(run_agent, "resolve_bump", fake_resolve_bump):
            with contextlib.redirect_stdout(buf):
                try:
                    run_agent.cmd_resolve_version(args)
                except SystemExit as e:
                    code = e.code
        return json.loads(buf.getvalue()), code, captured

    def test_happy_path_prints_decision_and_exits_zero(self):
        payload, code, _ = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(payload["target_version"], "1.1.0")
        self.assertIn("rationale", payload)

    # (description, ecosystem argument, expected canonical key)
    ECOSYSTEM_CASES = [
        ("canonical name",        "pypi",                         "pypi"),
        ("alias",                 "pip",                          "pypi"),
        ("manifest path",         "./python-ml/requirements.txt", "pypi"),
        ("go manifest path",      "services/api/go.mod",          "go"),
        ("npm lockfile path",     "web/package-lock.json",        "npm"),
    ]

    def test_ecosystem_argument_accepts_names_and_manifest_paths(self):
        """An alert's `source` field should be pasteable straight in."""
        for desc, raw, expected in self.ECOSYSTEM_CASES:
            with self.subTest(desc):
                _, code, captured = self._run(ecosystem=raw)
                self.assertEqual(code, 0, desc)
                self.assertEqual(captured["ecosystem"].key, expected, desc)

    def test_unknown_ecosystem_errors_and_exits_one(self):
        payload, code, _ = self._run(ecosystem="cpan")
        self.assertEqual(code, 1)
        self.assertIn("unknown ecosystem or manifest", payload["error"])

    def test_decision_error_exits_one(self):
        """Non-zero exit so the command is usable in a && chain."""
        broken = resolve_bump("pypi", "pkg", "1.0.0",
                              fetcher=FakeFetcher(raises=RuntimeError("HTTP 503")))
        payload, code, _ = self._run(decision=broken)
        self.assertEqual(code, 1)
        self.assertIn("HTTP 503", payload["error"])

    def test_cache_ttl_omitted_when_not_given(self):
        """Forwarding None would break the TTL comparison in the fetcher."""
        _, _, captured = self._run(cache_ttl=None)
        self.assertNotIn("cache_ttl_sec", captured["kwargs"])
        self.assertEqual(captured["kwargs"]["offline"], False)

    def test_cache_ttl_forwarded_when_given(self):
        _, _, captured = self._run(cache_ttl=0)
        self.assertEqual(captured["kwargs"]["cache_ttl_sec"], 0)

    def test_offline_forwarded(self):
        _, _, captured = self._run(offline=True)
        self.assertEqual(captured["kwargs"]["offline"], True)

    def test_registered_in_dispatch(self):
        """A subcommand missing from the dispatch table fails only at runtime."""
        import inspect

        import run_agent
        src = inspect.getsource(run_agent.main)
        self.assertIn('"resolve-version"', src)
        self.assertIn("cmd_resolve_version", src)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestParseVersion,
        TestVersionOrdering,
        TestBumpClass,
        TestEcosystemResolution,
        TestEcosystemForManifest,
        TestEventsToIntervals,
        TestAdvisoryCoverage,
        TestAdvisoryScopeFiltering,
        TestPreferredId,
        TestAliasMerge,
        TestSafeUpgrades,
        TestResolveBump,
        TestResolveBumpErrors,
        TestPillowRegression,
        TestCache,
        TestFetcherParsesResponses,
        TestResolveVersionCommand,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
