#!/usr/bin/env python3
"""
Tests for package identification (skills/run/package_identity.py).

Hermetic: no network, no claude subprocess. Manifests are written to temp
directories rather than mocked, because the bugs worth catching here are in the
parsing of real file formats.

Run with: python3 tests/test_package_identity.py
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))                 # security-engineer/
sys.path.insert(0, str(_DIR.parent.parent / "lib"))  # lib/

import package_identity
from package_identity import (
    cve_ids_from_alert,
    find_dependency,
    identify_package,
    normalize_name,
    parse_spec,
    read_manifest,
)
from version_data import ECOSYSTEMS

# tomllib is stdlib only from 3.11, and package_identity degrades to "no
# dependencies found" without it rather than refusing to import. On the 3.10
# floor these manifests genuinely parse to nothing, so the assertions below
# describe 3.11+ behaviour and are skipped rather than made to lie.
requires_tomllib = unittest.skipIf(
    package_identity.tomllib is None,
    "TOML manifests are only parsed where tomllib exists (Python 3.11+)",
)

_PYPI = ECOSYSTEMS["pypi"]
_NPM = ECOSYSTEMS["npm"]

# A realistic slice of the sandbox repo the dev loop runs against.
_REQUIREMENTS = ("numpy==1.21.0\n"
                 "pillow==8.3.1\n"
                 "flask==1.0.2\n"
                 "requests==2.20.0\n"
                 "pyyaml==5.3\n")

_PILLOW_ALERT = {
    "title": "pillow Package Vulnerabilities",
    "source": "./python-ml/requirements.txt",
    "file_path": "./python-ml/requirements.txt",
    "labels": ["CVE-2023-4863", "CVE-2023-50447"],
    "description": "pillow 8.3.1 has known vulnerabilities",
    "recommendation": "Upgrade pillow to a patched version",
}


class _TreeCase(unittest.TestCase):
    """Base that writes a file tree to a temp dir."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, content):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str)
                        else json.dumps(content))
        return path


# ---------------------------------------------------------------------------
# 1. Name normalization
# ---------------------------------------------------------------------------

class TestNormalizeName(unittest.TestCase):
    """PEP 503 folds -, _ and . for PyPI; other ecosystems only fold case."""

    # (description, name, ecosystem, expected)
    CASES = [
        ("pypi lowercases",          "Pillow",      _PYPI, "pillow"),
        ("pypi folds underscore",    "zope_event",  _PYPI, "zope-event"),
        ("pypi folds dot",           "zope.event",  _PYPI, "zope-event"),
        ("pypi collapses runs",      "a__b",        _PYPI, "a-b"),
        ("npm keeps separators",     "is_odd",      _NPM,  "is_odd"),
        ("npm lowercases",           "Lodash",      _NPM,  "lodash"),
        ("npm scope preserved",      "@babel/core", _NPM,  "@babel/core"),
        ("no ecosystem given",       "Zope.Event",  None,  "zope.event"),
        ("padding stripped",         "  pillow  ",  _PYPI, "pillow"),
        ("empty",                    "",            _PYPI, ""),
    ]

    def test_cases(self):
        for desc, name, eco, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(normalize_name(name, eco), expected, desc)


# ---------------------------------------------------------------------------
# 2. Version specs
# ---------------------------------------------------------------------------

class TestParseSpec(unittest.TestCase):
    """Table-driven: (concrete version, is_exact) per version spec."""

    # (description, spec, expected_version, expected_exact)
    CASES = [
        ("pypi exact",            "==8.3.1",   "8.3.1", True),
        ("pypi arbitrary equal",  "===8.3.1",  "8.3.1", True),
        ("bare version is a pin", "8.3.1",     "8.3.1", True),
        ("npm caret is a range",  "^4.17.4",   "4.17.4", False),
        ("npm tilde is a range",  "~4.17.4",   "4.17.4", False),
        ("at-least is a range",   ">=2.20.0",  "2.20.0", False),
        ("compound is a range",   ">=2.20.0,<3", "2.20.0", False),
        ("space-separated range", ">=1.0 <2.0", "1.0",   False),
        ("wildcard",              "4.*",       "4",     False),
        # Go's leading v must survive: it is required in go.mod and in OSV.
        ("go version keeps v",    "v0.17.0",   "v0.17.0", True),
        ("go pseudo-version",     "v0.0.0-20210119194325-5f4716e94777",
         "v0.0.0-20210119194325-5f4716e94777", True),
        ("prerelease preserved",  "==2.0.0-rc1", "2.0.0-rc1", True),
        ("build metadata kept",   "1.2.3+build5", "1.2.3+build5", True),
        ("empty spec",            "",          "",      False),
        ("no version at all",     "*",         "",      False),
    ]

    def test_cases(self):
        for desc, spec, version, exact in self.CASES:
            with self.subTest(desc):
                got_version, got_exact = parse_spec(spec)
                self.assertEqual(got_version, version, f"{desc}: version")
                self.assertEqual(got_exact, exact, f"{desc}: exact")


# ---------------------------------------------------------------------------
# 3. Manifest readers
# ---------------------------------------------------------------------------

class TestReadRequirements(_TreeCase):
    """requirements.txt, including the lines that are not requirements."""

    def test_exact_pins(self):
        deps = read_manifest(self.write("requirements.txt", _REQUIREMENTS))
        self.assertEqual(sorted(deps), ["flask", "numpy", "pillow", "pyyaml",
                                        "requests"])
        self.assertEqual(deps["pillow"].version, "8.3.1")
        self.assertTrue(deps["pillow"].exact)

    def test_noise_lines_skipped(self):
        text = ("# a comment\n"
                "\n"
                "-r base.txt\n"
                "--index-url https://example.invalid\n"
                "-e .\n"
                "pillow==8.3.1  # trailing comment\n")
        deps = read_manifest(self.write("requirements.txt", text))
        self.assertEqual(list(deps), ["pillow"])
        self.assertEqual(deps["pillow"].version, "8.3.1")

    def test_extras_and_markers(self):
        text = ('requests[security]==2.20.0\n'
                'importlib-metadata==1.0; python_version < "3.8"\n')
        deps = read_manifest(self.write("requirements.txt", text))
        self.assertEqual(deps["requests"].version, "2.20.0")
        self.assertEqual(deps["importlib-metadata"].version, "1.0")

    def test_unpinned_requirement(self):
        deps = read_manifest(self.write("requirements.txt", "pillow>=8.0\n"))
        self.assertEqual(deps["pillow"].version, "8.0")
        self.assertFalse(deps["pillow"].exact)


class TestReadPackageJson(_TreeCase):
    """A CVE can sit in any dependency section, so all of them are read."""

    def test_all_sections(self):
        path = self.write("package.json", {
            "dependencies": {"lodash": "^4.17.4"},
            "devDependencies": {"jest": "29.0.0"},
            "optionalDependencies": {"fsevents": "~2.3.2"},
            "peerDependencies": {"react": ">=17"},
        })
        deps = read_manifest(path)
        self.assertEqual(sorted(deps), ["fsevents", "jest", "lodash", "react"])
        self.assertEqual(deps["lodash"].version, "4.17.4")
        self.assertFalse(deps["lodash"].exact, "^ is a range, not a pin")
        self.assertTrue(deps["jest"].exact)

    def test_scoped_package(self):
        path = self.write("package.json", {"dependencies": {"@babel/core": "7.1.0"}})
        self.assertIn("@babel/core", read_manifest(path))

    def test_malformed_json_is_not_fatal(self):
        self.assertEqual(read_manifest(self.write("package.json", "{oops")), {})


class TestReadGoMod(_TreeCase):
    """Both require forms, and indirect dependencies still count."""

    GO_MOD = ('module example.com/x\n'
              '\n'
              'go 1.21\n'
              '\n'
              'require (\n'
              '\tgolang.org/x/net v0.0.0-20210119194325-5f4716e94777 // indirect\n'
              '\tgithub.com/gin-gonic/gin v1.7.0\n'
              ')\n'
              '\n'
              'require github.com/stretchr/testify v1.8.0\n')

    def test_block_and_single_line(self):
        deps = read_manifest(self.write("go.mod", self.GO_MOD))
        self.assertEqual(sorted(deps), ["github.com/gin-gonic/gin",
                                        "github.com/stretchr/testify",
                                        "golang.org/x/net"])

    def test_indirect_is_still_a_dependency(self):
        """The advisory names it and go.mod is where the bump is written."""
        deps = read_manifest(self.write("go.mod", self.GO_MOD))
        self.assertEqual(deps["golang.org/x/net"].version,
                         "v0.0.0-20210119194325-5f4716e94777")

    def test_v_prefix_survives(self):
        deps = read_manifest(self.write("go.mod", self.GO_MOD))
        self.assertEqual(deps["github.com/gin-gonic/gin"].version, "v1.7.0")

    def test_module_and_go_lines_are_not_dependencies(self):
        deps = read_manifest(self.write("go.mod", self.GO_MOD))
        self.assertNotIn("module", deps)
        self.assertNotIn("go", deps)


class TestReadOtherManifests(_TreeCase):
    """Cargo, pyproject, pom and the Ruby pair."""

    @requires_tomllib
    def test_cargo_toml_string_and_table_forms(self):
        text = ('[dependencies]\n'
                'serde = "1.0.100"\n'
                'tokio = { version = "1.20.0", features = ["full"] }\n'
                '\n[dev-dependencies]\n'
                'criterion = "0.4.0"\n')
        deps = read_manifest(self.write("Cargo.toml", text))
        self.assertEqual(deps["serde"].version, "1.0.100")
        self.assertEqual(deps["tokio"].version, "1.20.0")
        self.assertEqual(deps["criterion"].version, "0.4.0")

    @requires_tomllib
    def test_pyproject_pep621_list(self):
        text = ('[project]\n'
                'name = "x"\n'
                'dependencies = ["pillow==8.3.1", "requests>=2.20.0"]\n')
        deps = read_manifest(self.write("pyproject.toml", text))
        self.assertEqual(deps["pillow"].version, "8.3.1")
        self.assertFalse(deps["requests"].exact)

    @requires_tomllib
    def test_pyproject_poetry_table(self):
        text = ('[tool.poetry.dependencies]\n'
                'python = "^3.10"\n'
                'pillow = "8.3.1"\n')
        deps = read_manifest(self.write("pyproject.toml", text))
        self.assertEqual(deps["pillow"].version, "8.3.1")

    def test_pom_uses_group_and_artifact(self):
        """OSV and deps.dev key Maven packages on groupId:artifactId."""
        text = ('<project xmlns="http://maven.apache.org/POM/4.0.0">'
                '<dependencies><dependency>'
                '<groupId>org.apache.logging.log4j</groupId>'
                '<artifactId>log4j-core</artifactId>'
                '<version>2.14.1</version>'
                '</dependency></dependencies></project>')
        deps = read_manifest(self.write("pom.xml", text))
        self.assertIn("org.apache.logging.log4j:log4j-core", deps)
        self.assertEqual(deps["org.apache.logging.log4j:log4j-core"].version,
                         "2.14.1")

    def test_gemfile_lock_gives_resolved_versions(self):
        text = ("GEM\n"
                "  remote: https://rubygems.org/\n"
                "  specs:\n"
                "    rack (2.2.3)\n"
                "    nokogiri (1.13.0)\n")
        deps = read_manifest(self.write("Gemfile.lock", text))
        self.assertEqual(deps["rack"].version, "2.2.3")
        self.assertEqual(deps["nokogiri"].version, "1.13.0")

    def test_gemfile_dsl(self):
        text = ('source "https://rubygems.org"\n'
                'gem "rack", "2.2.3"\n'
                'gem "rails"\n')
        deps = read_manifest(self.write("Gemfile", text))
        self.assertEqual(deps["rack"].version, "2.2.3")
        self.assertEqual(deps["rails"].version, "")

    def test_package_lock_v3(self):
        path = self.write("package-lock.json", {
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"name": "lodash",
                                                 "version": "4.17.11"}},
        })
        self.assertEqual(read_manifest(path)["lodash"].version, "4.17.11")

    def test_package_lock_v1_nested(self):
        path = self.write("package-lock.json", {
            "lockfileVersion": 1,
            "dependencies": {"lodash": {"version": "4.17.11"}},
        })
        self.assertEqual(read_manifest(path)["lodash"].version, "4.17.11")

    def test_unknown_filename_yields_nothing(self):
        self.assertEqual(read_manifest(self.write("server.js", "x")), {})

    def test_missing_file_yields_nothing(self):
        self.assertEqual(read_manifest(self.root / "nope.txt"), {})


class TestFindDependency(_TreeCase):
    """Lookup tolerates the spelling differences a scanner introduces."""

    def test_pypi_name_folding(self):
        deps = read_manifest(self.write("requirements.txt", "zope.event==4.5.0\n"))
        self.assertIsNotNone(find_dependency(deps, "zope-event", _PYPI))
        self.assertIsNotNone(find_dependency(deps, "Zope_Event", _PYPI))

    def test_case_insensitive(self):
        deps = read_manifest(self.write("requirements.txt", _REQUIREMENTS))
        self.assertIsNotNone(find_dependency(deps, "Pillow", _PYPI))

    def test_absent_returns_none(self):
        deps = read_manifest(self.write("requirements.txt", _REQUIREMENTS))
        self.assertIsNone(find_dependency(deps, "django", _PYPI))


# ---------------------------------------------------------------------------
# 4. CVE ids
# ---------------------------------------------------------------------------

class TestCveIds(unittest.TestCase):
    """Labels first, prose only as a fallback."""

    # (description, alert, expected)
    CASES = [
        ("from labels", {"labels": ["CVE-2023-4863", "other"]}, ["CVE-2023-4863"]),
        ("deduped and sorted",
         {"labels": ["CVE-2023-50447", "CVE-2023-4863", "CVE-2023-4863"]},
         ["CVE-2023-4863", "CVE-2023-50447"]),
        ("uppercased", {"labels": ["cve-2023-4863"]}, ["CVE-2023-4863"]),
        ("falls back to description",
         {"labels": [], "description": "fixes CVE-2021-23437 in pillow"},
         ["CVE-2021-23437"]),
        ("labels win over prose",
         {"labels": ["CVE-2023-4863"], "description": "also CVE-9999-1"},
         ["CVE-2023-4863"]),
        ("none anywhere", {"labels": [], "description": "no ids"}, []),
        ("missing keys", {}, []),
    ]

    def test_cases(self):
        for desc, alert, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(cve_ids_from_alert(alert), expected, desc)


# ---------------------------------------------------------------------------
# 5. identify_package
# ---------------------------------------------------------------------------

class TestIdentifyPackage(_TreeCase):
    """The deterministic path: manifest is the authority, alert is the hint."""

    def setUp(self):
        super().setUp()
        self.write("python-ml/requirements.txt", _REQUIREMENTS)

    def test_pillow_from_the_sandbox_alert(self):
        ref = identify_package(_PILLOW_ALERT, self.root, allow_llm=False)
        self.assertTrue(ref.ok, ref.error)
        self.assertEqual(ref.ecosystem.key, "pypi")
        self.assertEqual(ref.package, "pillow")
        self.assertEqual(ref.current_version, "8.3.1")
        self.assertTrue(ref.exact_pin)
        self.assertEqual(ref.resolved_by, "manifest")
        self.assertEqual(ref.cve_ids, ["CVE-2023-4863", "CVE-2023-50447"])

    def test_range_spec_resolved_from_lockfile(self):
        self.write("web/package.json", {"dependencies": {"lodash": "^4.17.4"}})
        self.write("web/package-lock.json", {
            "lockfileVersion": 3,
            "packages": {"node_modules/lodash": {"name": "lodash",
                                                 "version": "4.17.11"}}})
        ref = identify_package({"title": "lodash Package Vulnerabilities",
                                "file_path": "web/package.json", "labels": []},
                               self.root, allow_llm=False)
        self.assertEqual(ref.current_version, "4.17.11",
                         "the lockfile is authoritative over a range spec")
        self.assertTrue(ref.exact_pin)
        self.assertIn("lockfile", ref.resolved_by)

    def test_range_spec_without_lockfile_uses_base_and_flags_it(self):
        self.write("web/package.json", {"dependencies": {"lodash": "^4.17.4"}})
        ref = identify_package({"title": "lodash Package Vulnerabilities",
                                "file_path": "web/package.json", "labels": []},
                               self.root, allow_llm=False)
        self.assertEqual(ref.current_version, "4.17.4")
        self.assertFalse(ref.exact_pin, "callers must be able to see it was a range")

    def test_longest_match_wins(self):
        """"golang.org/x/net" must beat a stray shorter token."""
        self.write("svc/go.mod",
                   'module x\nrequire (\n\tgolang.org/x/net v0.17.0\n\tnet v1.0.0\n)\n')
        ref = identify_package({"title": "golang.org/x/net Package Vulnerabilities",
                                "file_path": "svc/go.mod", "labels": []},
                               self.root, allow_llm=False)
        self.assertEqual(ref.package, "golang.org/x/net")

    def test_title_wins_over_description_regardless_of_length(self):
        """Precedence must not be decided by which name happens to be longer."""
        ref = identify_package({
            "title": "flask Package Vulnerabilities",
            "file_path": "./python-ml/requirements.txt",
            "description": "unrelated note mentioning requests and pillow",
            "recommendation": "", "labels": [],
        }, self.root, allow_llm=False)
        self.assertEqual(ref.package, "flask")

    def test_description_used_only_when_title_matches_nothing(self):
        ref = identify_package({
            "title": "Imaging library flaw",
            "file_path": "./python-ml/requirements.txt",
            "description": "pillow 8.3.1 is affected",
            "recommendation": "", "labels": [],
        }, self.root, allow_llm=False)
        self.assertEqual(ref.package, "pillow")

    def test_source_used_when_file_path_absent(self):
        alert = dict(_PILLOW_ALERT)
        del alert["file_path"]
        ref = identify_package(alert, self.root, allow_llm=False)
        self.assertTrue(ref.ok, ref.error)
        self.assertEqual(ref.package, "pillow")

    # (description, alert overrides, expected error fragment)
    ERROR_CASES = [
        ("no manifest path", {"file_path": "", "source": ""},
         "no file_path or source"),
        ("unknown manifest type", {"file_path": "server.js"},
         "no known ecosystem"),
        ("manifest missing from repo", {"file_path": "nope/requirements.txt"},
         "no dependencies parsed"),
        # Every prose field has to be cleared, not just the title — the
        # description is searched too, by design.
        ("package absent from manifest",
         {"title": "django Package Vulnerabilities", "description": "",
          "recommendation": ""},
         "matches the alert"),
    ]

    def test_error_cases(self):
        for desc, overrides, fragment in self.ERROR_CASES:
            with self.subTest(desc):
                alert = {**_PILLOW_ALERT, **overrides}
                ref = identify_package(alert, self.root, allow_llm=False)
                self.assertFalse(ref.ok, desc)
                self.assertIn(fragment, ref.error or "", desc)

    def test_never_raises_on_a_hostile_alert(self):
        """The pipeline degrades on a bad ref; it must not blow up producing one."""
        for alert in ({}, {"file_path": None}, {"labels": None, "file_path": 1},
                      {"file_path": "../../etc/passwd"}):
            with self.subTest(str(alert)):
                ref = identify_package(alert, self.root, allow_llm=False)
                self.assertFalse(ref.ok)

    def test_to_dict_is_json_serializable(self):
        """The ref is rendered into a prompt, so it has to serialize."""
        ref = identify_package(_PILLOW_ALERT, self.root, allow_llm=False)
        payload = json.dumps(ref.to_dict())
        self.assertIn("pillow", payload)


class TestIdentifyPackageLlmFallback(_TreeCase):
    """The model may only pick from the manifest, and is checked afterwards."""

    def setUp(self):
        super().setUp()
        self.write("python-ml/requirements.txt", _REQUIREMENTS)
        # A title naming nothing in the manifest forces the fallback.
        self.alert = {"title": "Imaging library flaw",
                      "file_path": "./python-ml/requirements.txt",
                      "labels": ["CVE-2023-4863"], "description": "",
                      "recommendation": ""}

    def _claude(self, package):
        import subprocess as sp
        return sp.CompletedProcess(
            args=["claude"], returncode=0,
            stdout=json.dumps({"result": json.dumps({"package": package})}),
            stderr="")

    def test_not_called_when_the_manifest_already_matches(self):
        with patch("package_identity.subprocess.run") as run:
            ref = identify_package(_PILLOW_ALERT, self.root, allow_llm=True)
        run.assert_not_called()
        self.assertEqual(ref.resolved_by, "manifest")

    def test_not_called_when_disabled(self):
        with patch("package_identity.subprocess.run") as run:
            identify_package(self.alert, self.root, allow_llm=False)
        run.assert_not_called()

    def test_valid_answer_is_accepted(self):
        with patch("package_identity.subprocess.run",
                   return_value=self._claude("pillow")):
            ref = identify_package(self.alert, self.root, allow_llm=True)
        self.assertTrue(ref.ok, ref.error)
        self.assertEqual(ref.package, "pillow")
        self.assertEqual(ref.current_version, "8.3.1")
        self.assertIn("llm", ref.resolved_by)

    def test_hallucinated_package_is_rejected(self):
        """A name that is not in the manifest must resolve to nothing, not an edit."""
        with patch("package_identity.subprocess.run",
                   return_value=self._claude("definitely-not-installed")):
            ref = identify_package(self.alert, self.root, allow_llm=True)
        self.assertFalse(ref.ok)
        self.assertIn("matches the alert", ref.error)

    def test_empty_answer_is_rejected(self):
        with patch("package_identity.subprocess.run",
                   return_value=self._claude("")):
            ref = identify_package(self.alert, self.root, allow_llm=True)
        self.assertFalse(ref.ok)

    # (description, side_effect, return_value)
    FAILURE_CASES = [
        ("timeout",
         __import__("subprocess").TimeoutExpired(cmd=["claude"], timeout=60), None),
        ("non-zero exit", None,
         __import__("subprocess").CompletedProcess(
             args=["claude"], returncode=1,
             stdout='{"is_error": true, "subtype": "error_max_turns"}', stderr="")),
        ("unparseable output", None,
         __import__("subprocess").CompletedProcess(
             args=["claude"], returncode=0, stdout="no json here", stderr="")),
    ]

    def test_failures_degrade_quietly(self):
        for desc, side_effect, return_value in self.FAILURE_CASES:
            with self.subTest(desc):
                kwargs = ({"side_effect": side_effect} if side_effect
                          else {"return_value": return_value})
                with patch("package_identity.subprocess.run", **kwargs):
                    ref = identify_package(self.alert, self.root, allow_llm=True)
                self.assertFalse(ref.ok, desc)
                self.assertIsNotNone(ref.error, desc)

    def test_single_shot_flags_are_used(self):
        """Tools removed, not merely denied — see _SINGLE_SHOT_TOOL_FLAGS."""
        with patch("package_identity.subprocess.run",
                   return_value=self._claude("pillow")) as run:
            identify_package(self.alert, self.root, allow_llm=True)
        cmd = run.call_args[0][0]
        self.assertIn("--tools", cmd)
        self.assertEqual(cmd[cmd.index("--tools") + 1], "")
        self.assertNotIn("--allowedTools", cmd)

    def test_prompt_lists_only_manifest_entries(self):
        with patch("package_identity.subprocess.run",
                   return_value=self._claude("pillow")) as run:
            identify_package(self.alert, self.root, allow_llm=True)
        prompt = run.call_args[0][0][2]
        for name in ("pillow", "numpy", "flask"):
            self.assertIn(name, prompt)


# ---------------------------------------------------------------------------
# 6. Identification feeding the data layer
# ---------------------------------------------------------------------------

class TestIdentityFeedsResolveBump(_TreeCase):
    """The two halves have to fit: a PackageRef must be a usable query."""

    def test_ref_drives_a_decision(self):
        from version_data import resolve_bump

        class Fetcher:
            sources = ["fake"]

            def osv_advisories(self, package, ecosystem):
                assert package == "pillow", package
                assert ecosystem.osv == "PyPI", ecosystem.osv
                return [{
                    "id": "CVE-2023-4863", "aliases": [],
                    "affected": [{
                        "package": {"name": "pillow", "ecosystem": "PyPI"},
                        "ranges": [{"type": "ECOSYSTEM",
                                    "events": [{"introduced": "0"},
                                               {"fixed": "10.0.1"}]}],
                    }],
                }]

            def published_versions(self, package, ecosystem):
                return ["8.3.1", "9.0.0", "10.0.1"]

        self.write("python-ml/requirements.txt", _REQUIREMENTS)
        ref = identify_package(_PILLOW_ALERT, self.root, allow_llm=False)
        decision = resolve_bump(ref.ecosystem, ref.package, ref.current_version,
                                fetcher=Fetcher())
        self.assertEqual(decision.target_version, "10.0.1")
        self.assertEqual(decision.bump_class, "major")
        self.assertEqual(decision.advisories_cleared, ["CVE-2023-4863"])


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestNormalizeName,
        TestParseSpec,
        TestReadRequirements,
        TestReadPackageJson,
        TestReadGoMod,
        TestReadOtherManifests,
        TestFindDependency,
        TestCveIds,
        TestIdentifyPackage,
        TestIdentifyPackageLlmFallback,
        TestIdentityFeedsResolveBump,
    ]

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
