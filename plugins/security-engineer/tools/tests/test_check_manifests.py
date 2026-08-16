#!/usr/bin/env python3
"""Unit tests for tools/check_manifests.py.

Table-driven, and every case is data in / problems out — no filesystem, because
the checks were written as pure functions precisely so this file wouldn't need
one. `main()` is exercised once at the end against the real repo, which is the
only assertion here that touches disk.

Run: python3 tools/tests/test_check_manifests.py
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from check_manifests import (
    check_command_frontmatter,
    check_executable_bits,
    check_manifest_agreement,
    check_skill_frontmatter,
    main,
    parse_frontmatter,
)


class TestParseFrontmatter(unittest.TestCase):
    CASES = [
        ("flat keys",
         "---\nname: run\ndescription: does a thing\n---\n# Body\n",
         {"name": "run", "description": "does a thing"}),
        ("quotes stripped",
         '---\nargument-hint: "[--max N]"\n---\n',
         {"argument-hint": "[--max N]"}),
        ("value keeps inner colons",
         "---\ndescription: fix it: then ship it\n---\n",
         {"description": "fix it: then ship it"}),
        ("no frontmatter at all", "# Just a heading\n", {}),
        ("empty document", "", {}),
        ("fence not on line one", "\n---\nname: run\n---\n", {}),
        ("unterminated block still yields its keys",
         "---\nname: run\n", {"name": "run"}),
        ("blank lines and comments skipped",
         "---\n\n# a comment\nname: run\n---\n", {"name": "run"}),
        ("indented continuation ignored",
         "---\nname: run\n  nested: value\n---\n", {"name": "run"}),
        ("body after the closing fence ignored",
         "---\nname: run\n---\ndescription: not frontmatter\n",
         {"name": "run"}),
    ]

    def test_cases(self):
        for desc, text, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(parse_frontmatter(text), expected, desc)


class TestManifestAgreement(unittest.TestCase):
    """The version-drift check — the reason this module exists."""

    def _plugin(self, **over):
        base = {"name": "security-engineer", "version": "1.0.0",
                "description": "d"}
        return {**base, **over}

    def _market(self, **over):
        entry = {"name": "security-engineer", "version": "1.0.0",
                 "description": "d", **over}
        return {"plugins": [entry]}

    def test_agreeing_manifests_are_silent(self):
        self.assertEqual(
            check_manifest_agreement(self._plugin(), self._market()), [])

    CASES = [
        # (description, plugin overrides, marketplace overrides, needle)
        ("version drift", {}, {"version": "1.0.1"}, "version"),
        ("description drift", {}, {"description": "other"}, "description"),
    ]

    def test_drift_is_reported(self):
        for desc, plugin_over, market_over, needle in self.CASES:
            with self.subTest(desc):
                problems = check_manifest_agreement(
                    self._plugin(**plugin_over), self._market(**market_over))
                self.assertEqual(len(problems), 1, f"{desc}: {problems}")
                self.assertIn(needle, problems[0], desc)

    def test_missing_plugin_name_stops_early(self):
        problems = check_manifest_agreement({"version": "1.0.0"}, self._market())
        self.assertEqual(len(problems), 1)
        self.assertIn("'name'", problems[0])

    def test_missing_version_reported(self):
        problems = check_manifest_agreement(
            {"name": "security-engineer", "description": "d"},
            self._market(version=None))
        self.assertTrue(any("'version'" in p for p in problems), problems)

    def test_unlisted_plugin_names_what_was_found(self):
        problems = check_manifest_agreement(
            self._plugin(), {"plugins": [{"name": "something-else"}]})
        self.assertEqual(len(problems), 1)
        self.assertIn("something-else", problems[0])

    def test_empty_marketplace_says_none(self):
        problems = check_manifest_agreement(self._plugin(), {})
        self.assertIn("none", problems[0])


class TestSkillFrontmatter(unittest.TestCase):
    CASES = [
        ("complete", [("run", {"name": "run", "description": "d"})], 0),
        ("missing description", [("run", {"name": "run"})], 1),
        ("missing name", [("run", {"description": "d"})], 1),
        ("both missing", [("run", {"nope": "x"})], 2),
        ("no frontmatter", [("run", {})], 1),
        ("name disagrees with directory",
         [("run", {"name": "runner", "description": "d"})], 1),
        ("several skills, one broken",
         [("run", {"name": "run", "description": "d"}),
          ("scan", {"name": "scan"})], 1),
        ("nothing to check", [], 0),
    ]

    def test_cases(self):
        for desc, skills, expected in self.CASES:
            with self.subTest(desc):
                problems = check_skill_frontmatter(skills)
                self.assertEqual(len(problems), expected, f"{desc}: {problems}")

    def test_directory_mismatch_names_both(self):
        problems = check_skill_frontmatter(
            [("run", {"name": "runner", "description": "d"})])
        self.assertIn("runner", problems[0])
        self.assertIn("run", problems[0])


class TestCommandFrontmatter(unittest.TestCase):
    CASES = [
        ("has description", [("commands/script.md", {"description": "d"})], 0),
        ("empty description", [("commands/script.md", {"description": ""})], 1),
        ("no description key", [("commands/script.md", {"name": "x"})], 1),
        ("no frontmatter", [("commands/script.md", {})], 1),
        ("no commands", [], 0),
    ]

    def test_cases(self):
        for desc, commands, expected in self.CASES:
            with self.subTest(desc):
                problems = check_command_frontmatter(commands)
                self.assertEqual(len(problems), expected, f"{desc}: {problems}")


class TestExecutableBits(unittest.TestCase):
    CASES = [
        ("all executable", [("bin/security-engineer", True)], 0),
        ("one stripped", [("bin/security-engineer", False)], 1),
        ("mixed", [("install.sh", True), ("devloop/run.sh", False)], 1),
        ("nothing declared", [], 0),
    ]

    def test_cases(self):
        for desc, modes, expected in self.CASES:
            with self.subTest(desc):
                problems = check_executable_bits(modes)
                self.assertEqual(len(problems), expected, f"{desc}: {problems}")

    def test_message_gives_the_fix(self):
        problems = check_executable_bits([("install.sh", False)])
        self.assertIn("chmod +x install.sh", problems[0])


class TestAgainstThisRepo(unittest.TestCase):
    """The checker has to pass on the tree that ships it."""

    def test_main_exits_clean(self):
        self.assertEqual(main(), 0, "check_manifests.py reported problems")


if __name__ == "__main__":
    unittest.main(verbosity=2)
