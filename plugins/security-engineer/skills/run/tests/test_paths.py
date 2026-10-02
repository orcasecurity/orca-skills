#!/usr/bin/env python3
"""Tests for alert-derived path handling.

Every path here is built from a value someone else supplied — an alert_id from
the API, a `source` or `manifest_path` from a finding, a file list a model
reported — and one of them is an argument to shutil.rmtree.

Run with: python3 tests/test_paths.py
"""
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_DIR = Path(__file__).parent
sys.path.insert(0, str(_DIR.parent))
sys.path.insert(0, str(_DIR.parent.parent / "lib"))

import orchestrator
import package_identity
import validator
from orca_client import Repository
from orchestrator import AlertTask, FixAgentResult, _declared_paths, _worktree_path
from paths import WORKTREE_PREFIX, assert_disposable, resolve_within, safe_name


class TestSafeName(unittest.TestCase):
    """alert_id names a directory that gets deleted, so it is an allowlist."""

    CASES = [
        ("a slash becomes a dash, as alert_branch_name already did",
         "orca-ab/cd", "orca-ab-cd"),
        ("traversal cannot survive", "../../etc", "etc"),
        ("a bare parent directory cannot survive", "..", "unnamed"),
        ("the current directory cannot survive", ".", "unnamed"),
        ("empty is never returned", "", "unnamed"),
        ("shell metacharacters are dropped", "a;rm -rf /;b", "a-rm--rf---b"),
        ("newlines are dropped", "a\nb", "a-b"),
        ("ordinary ids are untouched", "orca-abc123", "orca-abc123"),
    ]

    def test_cases(self):
        for desc, raw, expected in self.CASES:
            with self.subTest(desc):
                self.assertEqual(safe_name(raw), expected, desc)

    def test_worktree_path_sanitizes_both_halves(self):
        repo = Repository(name="owner/repo", url="https://github.com/owner/repo")
        path = _worktree_path("../../../etc/passwd", repo)
        self.assertEqual(path.parent, Path("/tmp"))
        self.assertTrue(path.name.startswith(f"{WORKTREE_PREFIX}owner-repo-"))
        self.assertNotIn("..", str(path))


class TestResolveWithin(unittest.TestCase):
    """`Path.__truediv__` does not normalise, so the join has to be checked."""

    ROOT = "/tmp/orca-fix-owner-repo-1"

    def test_ordinary_relative_path_resolves(self):
        self.assertEqual(resolve_within(self.ROOT, "src/app.py"),
                         Path(self.ROOT) / "src/app.py")

    def test_traversal_is_refused(self):
        self.assertIsNone(resolve_within(self.ROOT, "../../etc/passwd"))

    def test_traversal_that_returns_inside_is_allowed(self):
        """`a/../b` never leaves, and refusing it would fail honest alerts."""
        self.assertEqual(resolve_within(self.ROOT, "a/../b.py"),
                         Path(self.ROOT) / "b.py")

    def test_absolute_path_is_refused(self):
        self.assertIsNone(resolve_within(self.ROOT, "/etc/passwd"))

    def test_symlink_out_of_the_tree_is_refused(self):
        """A cloned repository can contain a symlink; resolving catches it."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "worktree"
            (root / "sub").mkdir(parents=True)
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (root / "sub" / "link").symlink_to(outside)
            self.assertIsNone(resolve_within(root, "sub/link/secret.txt"))

    def test_empty_relative_is_the_root_itself(self):
        self.assertEqual(resolve_within(self.ROOT, ""), Path(self.ROOT))


class TestAssertDisposable(unittest.TestCase):
    """The rmtree in _create_worktree used to be justified by a naming
    convention. A convention is not a check on a value from the API."""

    def test_our_worktree_is_allowed(self):
        assert_disposable(f"/tmp/{WORKTREE_PREFIX}owner-repo-orca-1")

    def test_a_directory_outside_tmp_is_refused(self):
        with self.assertRaises(RuntimeError):
            assert_disposable("/home/someone/project")

    def test_tmp_itself_is_refused(self):
        with self.assertRaises(RuntimeError):
            assert_disposable("/tmp")

    def test_an_unrelated_tmp_directory_is_refused(self):
        with self.assertRaises(RuntimeError):
            assert_disposable("/tmp/someone-elses-build")

    def test_a_nested_path_is_refused(self):
        """Only the worktree itself is disposable, never something under it."""
        with self.assertRaises(RuntimeError):
            assert_disposable(f"/tmp/{WORKTREE_PREFIX}x/src")

    def test_create_worktree_checks_before_removing(self):
        src = __import__("inspect").getsource(orchestrator._create_worktree)
        self.assertIn("assert_disposable(path)", src)
        self.assertLess(src.index("assert_disposable(path)"),
                        src.index("shutil.rmtree"))


class TestDeclaredPaths(unittest.TestCase):
    """`git add -A` committed whatever the agent's Bash left behind."""

    def _task(self, files):
        return AlertTask(
            alert_id="orca-1", title="t", risk_level="high", feature_type="sast",
            source="app.py:1", alert_json={}, worktree_path=Path("/tmp/orca-fix-x"),
            fix_result=FixAgentResult(success=True, files_changed=files),
        )

    def test_reported_files_are_returned_relative_and_sorted(self):
        self.assertEqual(_declared_paths(self._task(["b.py", "a/c.py"])),
                         ["a/c.py", "b.py"])

    def test_line_suffix_is_stripped(self):
        self.assertEqual(_declared_paths(self._task(["app.py:40"])), ["app.py"])

    def test_duplicates_collapse(self):
        self.assertEqual(_declared_paths(self._task(["a.py", "a.py"])), ["a.py"])

    def test_a_path_outside_the_worktree_fails_the_alert(self):
        with self.assertRaises(RuntimeError):
            _declared_paths(self._task(["../../etc/passwd"]))

    def test_an_absolute_path_fails_the_alert(self):
        with self.assertRaises(RuntimeError):
            _declared_paths(self._task(["/etc/passwd"]))

    def test_nothing_reported_fails_rather_than_staging_everything(self):
        with self.assertRaises(RuntimeError):
            _declared_paths(self._task([]))

    def test_commit_stages_by_name_not_wholesale(self):
        import inspect
        src = inspect.getsource(orchestrator._commit_and_pr)
        self.assertIn("_declared_paths(task)", src)
        self.assertNotIn('"git", "add", "-A"', src)

    def test_retry_push_is_scoped_the_same_way(self):
        import inspect
        src = inspect.getsource(orchestrator._push_fix_update)
        self.assertIn("_declared_paths(task)", src)
        self.assertNotIn('"-A"', src)


class TestUnaccountedChangesBlockTheCommit(unittest.TestCase):
    """Staging by name is only half of it: a leftover is either an
    under-reported fix or a stray artefact, and we cannot tell which."""

    def test_leftover_untracked_file_raises(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = ("?? scratch.env", "", 0)
            with self.assertRaises(RuntimeError):
                run_agent._stage(["app.py"])

    def test_leftover_unstaged_modification_raises(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = (" M other.py", "", 0)
            with self.assertRaises(RuntimeError):
                run_agent._stage(["app.py"])

    def test_clean_tree_commits(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = ("M  app.py", "", 0)
            run_agent._stage(["app.py"])  # must not raise

    def test_no_paths_keeps_the_blanket_stage_for_manual_use(self):
        import run_agent
        with patch.object(run_agent, "run") as run:
            run.return_value = ("", "", 0)
            run_agent._stage([])
            self.assertEqual(run.call_args_list[0].args[0], ["git", "add", "-A"])


class TestClonedTreesCannotConfigureTheAgent(unittest.TestCase):
    """A repository configures Claude Code just by containing files. The fix
    agent runs with cwd inside a repo cloned from the tenant."""

    def test_fix_agent_pins_its_configuration(self):
        for flag in ("--safe-mode", "--setting-sources", "--settings",
                     "--strict-mcp-config"):
            self.assertIn(flag, orchestrator._PINNED_CONFIG_FLAGS, flag)

    def test_settings_file_is_plugin_owned_and_exists(self):
        settings = Path(orchestrator._AGENT_SETTINGS)
        self.assertTrue(settings.is_file(), settings)
        self.assertIn("agent-settings.json", str(settings))

    def test_settings_file_is_valid_json(self):
        import json
        json.loads(Path(orchestrator._AGENT_SETTINGS).read_text())

    def test_setting_sources_excludes_the_clones_own(self):
        flags = orchestrator._PINNED_CONFIG_FLAGS
        sources = flags[flags.index("--setting-sources") + 1]
        self.assertNotIn("project", sources)
        self.assertNotIn("local", sources)

    def test_the_flags_reach_the_subprocess(self):
        import inspect
        src = inspect.getsource(orchestrator._invoke_fix_agent)
        self.assertIn("*_PINNED_CONFIG_FLAGS", src)


class TestAlertPathsCannotEscapeTheWorktree(unittest.TestCase):
    """The same join, at the three other places an alert field reaches one."""

    def test_project_root_ignores_a_traversing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(
                validator._find_project_root(["../../etc/passwd"], root, "go.mod"),
                root)

    def test_terraform_root_ignores_a_traversing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(
                validator._find_terraform_root(["../../etc/x.tf"], root), root)

    def test_package_identity_refuses_a_traversing_manifest(self):
        src = __import__("inspect").getsource(package_identity.identify_package)
        self.assertIn("resolve_within(worktree_path, manifest_rel)", src)

    def test_cve_verify_refuses_a_traversing_manifest(self):
        from pipelines import cve
        src = __import__("inspect").getsource(cve.CvePipeline.verify)
        self.assertIn("resolve_within(worktree_path, manifest_rel)", src)


if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    test_classes = [
        TestSafeName,
        TestResolveWithin,
        TestAssertDisposable,
        TestDeclaredPaths,
        TestUnaccountedChangesBlockTheCommit,
        TestClonedTreesCannotConfigureTheAgent,
        TestAlertPathsCannotEscapeTheWorktree,
    ]

    _registered = {cls.__name__ for cls in test_classes}
    _defined = {name for name, obj in list(globals().items())
                if isinstance(obj, type) and issubclass(obj, unittest.TestCase)
                and obj is not unittest.TestCase}
    _missing = sorted(_defined - _registered)
    if _missing:
        sys.exit(f"Test classes defined but never run — add them to "
                 f"test_classes: {', '.join(_missing)}")

    for cls in test_classes:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    sys.exit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
