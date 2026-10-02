#!/usr/bin/env python3
"""Path handling for values that came from an alert.

Almost every path this plugin builds is derived from something it was handed:
an `alert_id` that names a worktree directory, a `source` or `manifest_path`
joined onto a worktree root, a file list a model reported. None of it is ours,
and `Path.__truediv__` does not normalise — `worktree / "../../etc/passwd"` is
a path outside the worktree that reads like one inside it.

Two rules follow, and this module is where they live so no call site has to
remember them:

  * anything used as a filename is collapsed to a known alphabet (`safe_name`)
  * anything joined onto a root is resolved and checked to still be under that
    root (`resolve_within`), which also catches a symlink pointing out of a
    cloned tree

`assert_disposable` is the belt for the one destructive operation here.
`_create_worktree` clears a leftover directory with `shutil.rmtree`, and the
comment justifying it used to read "ours by naming convention" — which is work
a sanitiser should be doing, on a value that arrives from the API.
"""
import re
from pathlib import Path

# Worktrees live at /tmp/orca-fix-<repo>-<alert id>. Both halves are checked
# before anything is deleted: the parent directory and the prefix.
WORKTREE_ROOT = Path("/tmp")
WORKTREE_PREFIX = "orca-fix-"

# Deliberately an allowlist. A denylist of "/" and ".." would still pass through
# NUL bytes, newlines, shell metacharacters and unicode path separators.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


def safe_name(value) -> str:
    """Collapse an alert-derived value into something usable as one path segment.

    Never returns "", "." or ".." — each of those names a directory that is not
    the one the caller meant, and the last two are how a traversal starts.
    """
    cleaned = _UNSAFE.sub("-", str(value or ""))
    cleaned = cleaned.strip("-.")
    return cleaned or "unnamed"


def resolve_within(root, relative) -> Path | None:
    """Join `relative` onto `root`, or return None if the result escapes it.

    Resolves both sides, so a `../` in the alert's `source` and a symlink planted
    in a cloned repository are the same case and both fail closed. Callers treat
    None as "this alert does not name a path in this worktree" — which is what it
    is — rather than falling back to the root, since operating on the wrong file
    is worse than not operating at all.
    """
    root_path = Path(root).resolve()
    candidate = (root_path / str(relative or "")).resolve()
    if candidate == root_path or root_path in candidate.parents:
        return candidate
    return None


def assert_disposable(path) -> None:
    """Raise unless `path` is one of our own worktrees, directly under /tmp.

    Called before every rmtree. The check is on the resolved path, so a symlink
    at the worktree location cannot redirect the delete somewhere else.
    """
    resolved = Path(path).resolve()
    if resolved.parent != WORKTREE_ROOT.resolve():
        raise RuntimeError(
            f"refusing to delete {resolved}: not directly under {WORKTREE_ROOT}")
    if not resolved.name.startswith(WORKTREE_PREFIX):
        raise RuntimeError(
            f"refusing to delete {resolved}: not a {WORKTREE_PREFIX}* worktree")
