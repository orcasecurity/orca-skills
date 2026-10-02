#!/usr/bin/env python3
"""
Redaction of detected credentials on every path that leaves this process.

A secret fix is the one finding type where the alert hands us the thing we must
not repeat. Removing a hardcoded credential produces a diff whose *removed* line
is the credential, and that diff is then read by two model subprocesses, summarised
into a pull request body, written to the run log and POSTed to a webhook. The
credential is already in the repository — that is the finding — so the PR diff
itself adds no audience the repo did not already have. What the run adds is every
path that leaves the repository's access boundary: Slack, the log file on disk,
two third-party model calls, and the watch notifications a PR body generates.

Those are the paths this module closes. The PR diff is deliberately not one of
them: a commit that removes a line renders that line, and no amount of scrubbing
changes what `git show` prints. Redacting egress is what is achievable; the PR
carrying an explicit "this does not remediate, rotate the credential" warning is
what makes the residue honest (see orchestrator._secret_warning).

What counts as a candidate
--------------------------
Orca gives us no field holding the bare secret value — `_normalize_alert` promotes
`code_snippet`, which is whole source lines, and nothing finer. So candidates are
derived, most specific first:

  1. the assignment value — the quoted literal on the right of `=` or `:`, which
     is the credential itself and the form a model is most likely to quote back
  2. any other quoted literal on the line, for snippets that are not assignments
  3. the whole stripped line, which is what a unified diff actually contains

Keys are never candidates. `API_KEY = "sk-live-…"` yields `sk-live-…`, never
`API_KEY`, because the environment variable name is exactly what the PR has to
tell an operator to set — redacting it would make the remediation instructions
useless.

Only secret findings build a live redactor. For a SAST or CVE alert `code_snippet`
is ordinary vulnerable code with no credential in it, and scrubbing it from a diff
would blind the LLM validation gate to the very lines it has to judge.
"""
import re

from orca_client import _resolve_feature_type

PLACEHOLDER = "[REDACTED-SECRET]"

# Below these lengths a candidate stops identifying the credential and starts
# matching ordinary prose. A 3-character "value" scrubbed everywhere would eat
# words out of the impact description without protecting anything.
_MIN_VALUE_LEN = 6
_MIN_LINE_LEN = 8

# The right-hand side of an assignment: `API_KEY = "sk-live-abc"`, `password: 'hunter2'`.
# Only group 2 (the value) is ever taken — see the module docstring on keys.
_ASSIGNMENT = re.compile(r"""([A-Za-z_][\w.\-]*)\s*[=:]\s*["']([^"']+)["']""")

# Bare quoted literals, for snippets that are not shaped like an assignment
# (a call argument, a YAML scalar, a JSON value).
_QUOTED = re.compile(r"""["']([^"']+)["']""")

# Unquoted `KEY=value`, the .env and Dockerfile `ENV` form, where there are no
# quotes to anchor on. Stops at whitespace so a trailing comment is not absorbed.
_BARE_ASSIGNMENT = re.compile(r"""([A-Za-z_][\w.\-]*)\s*=\s*([^\s"'#]{12,})""")


def _snippet_lines(alert: dict) -> list[str]:
    """The alert's code_snippet as a list of lines, however Orca shaped it."""
    raw = alert.get("code_snippet") or []
    lines = [str(item) for item in raw] if isinstance(raw, list) else str(raw).splitlines()
    return [ln.strip() for ln in lines if ln and ln.strip()]


def _candidates(alert: dict) -> list[str]:
    """Strings that must not appear in anything this run emits.

    Ordered longest first so that replacement cannot leave a fragment behind: if
    the whole line and the value inside it are both candidates, scrubbing the
    line first means the value's own pass finds nothing left to do, whereas the
    reverse order would leave the line's surrounding text intact and correct.
    """
    found: set[str] = set()

    for line in _snippet_lines(alert):
        for _key, value in _ASSIGNMENT.findall(line):
            if len(value) >= _MIN_VALUE_LEN:
                found.add(value)
        for _key, value in _BARE_ASSIGNMENT.findall(line):
            found.add(value)
        for value in _QUOTED.findall(line):
            if len(value) >= _MIN_VALUE_LEN:
                found.add(value)
        if len(line) >= _MIN_LINE_LEN:
            found.add(line)

    return sorted(found, key=len, reverse=True)


class Redactor:
    """Callable that replaces every known credential fragment with PLACEHOLDER.

    An instance with no candidates is falsy and returns its input untouched, so
    callers can build one unconditionally and skip the `if feature_type ==`
    dance at each call site.
    """

    def __init__(self, candidates: list[str] | None = None):
        self.candidates = candidates or []

    def __bool__(self) -> bool:
        return bool(self.candidates)

    def __call__(self, text):
        """Scrub a string. Non-strings pass through, so this is safe on Optionals."""
        if not self.candidates or not text or not isinstance(text, str):
            return text
        for candidate in self.candidates:
            if candidate in text:
                text = text.replace(candidate, PLACEHOLDER)
        return text

    def scrub(self, value):
        """Scrub recursively through lists, tuples and dicts of strings.

        Notification payloads carry `manual_steps` and `concerns` as lists, and
        the impact agent's parsed JSON arrives as a dict, so a string-only
        redactor would quietly miss both.
        """
        if isinstance(value, str):
            return self(value)
        if isinstance(value, list):
            return [self.scrub(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self.scrub(item) for item in value)
        if isinstance(value, dict):
            return {k: self.scrub(v) for k, v in value.items()}
        return value


_NULL_REDACTOR = Redactor()


def build_redactor(alert: dict | None) -> Redactor:
    """The redactor for one alert. Always returns an instance, never None.

    Non-secret findings get the no-op redactor: there is no known credential to
    scrub, and blanking their code_snippet out of a diff would break the gates
    that have to read it.
    """
    if not alert or not isinstance(alert, dict):
        return _NULL_REDACTOR
    if _resolve_feature_type(alert) != "secret":
        return _NULL_REDACTOR
    candidates = _candidates(alert)
    return Redactor(candidates) if candidates else _NULL_REDACTOR
