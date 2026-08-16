#!/usr/bin/env python3
"""
Notification system for the Security Engineer orchestrator.
Pluggable backends: console (always), log file (always), webhook (opt-in).

Add new backends by implementing NotifierBackend and registering in build_notifiers().
"""
import json
import os
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

@dataclass
class NotificationPayload:
    event: str
    alert_id: str
    feature_type: str
    risk_level: str
    repo: str
    pr_url: str | None = None
    reason: str | None = None
    impact_level: str | None = None
    manual_steps: list[str] = field(default_factory=list)
    concerns: list[str] = field(default_factory=list)
    detail: str = ""
    error_detail: str | None = None
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Backend protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class NotifierBackend(Protocol):
    def send(self, payload: NotificationPayload) -> None: ...


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------

_CONSOLE_PREFIX = {
    "clone_started":     "[CLONE]",
    "clone_succeeded":   "[CLONE]",
    "clone_failed":      "[CLONE]",
    "alerts_fetched":    "[LIST] ",
    "fix_started":       "[START]",
    "fix_planned":       "[PLAN] ",
    "committed":         "[GIT]  ",
    "pr_opened":         "[PR]   ",
    "fix_succeeded":     "[OK]   ",
    "fix_failed":        "[FAIL] ",
    "timeout":           "[TOUT] ",
    "validation_failed": "[INVL] ",
    "ci_failed":         "[CI]   ",
    "run_complete":      "[DONE] ",
}

_CONSOLE_MSG = {
    "clone_started":     "Cloning {repo}",
    "clone_succeeded":   "Cloned {repo} → {detail}",
    "clone_failed":      "Clone failed for {repo}: {reason}",
    "alerts_fetched":    "{repo}: {detail}",
    "fix_started":       "Fix started for {alert_id} ({feature_type}, {risk_level})",
    "fix_planned":       "{alert_id} dry-run plan ready",
    "committed":         "{alert_id} committed ({detail})",
    "pr_opened":         "{alert_id} PR opened: {pr_url}",
    "fix_succeeded":     "{alert_id} fixed — PR: {pr_url}",
    "fix_failed":        "{alert_id} failed: {reason}",
    "timeout":           "{alert_id} timed out",
    "validation_failed": "{alert_id} validation failed: {reason}",
    "ci_failed":         "{alert_id} CI failed on {pr_url}",
    "run_complete":      "{succeeded} fixed, {failed} failed, {skipped} skipped",
}


class ConsoleNotifier:
    def send(self, payload: NotificationPayload) -> None:
        prefix = _CONSOLE_PREFIX.get(payload.event, "[INFO] ")
        tmpl = _CONSOLE_MSG.get(payload.event, payload.event)
        msg = tmpl.format(**vars(payload))
        print(f"{prefix} {msg}", flush=True)


class LogFileNotifier:
    """Always active. Appends newline-delimited JSON to security-engineer-run.json."""

    def __init__(self, log_path: Path):
        self.log_path = log_path

    def send(self, payload: NotificationPayload) -> None:
        entry = {k: v for k, v in vars(payload).items() if v is not None and v != [] and v != 0 and v != ""}
        with open(self.log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")


class WebhookNotifier:
    """Active when NOTIFY_WEBHOOK_URL is set. Generic HTTP POST — works with Slack, Teams, etc."""

    def __init__(self, url: str):
        self.url = url

    def send(self, payload: NotificationPayload) -> None:
        body = json.dumps({
            "event": payload.event,
            "alert_id": payload.alert_id,
            "repo": payload.repo,
            "impact_level": payload.impact_level,
            "pr_url": payload.pr_url,
            "reason": payload.reason,
            "manual_steps": payload.manual_steps,
            "timestamp": payload.timestamp,
        }).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception as e:
            print(f"[WARN] webhook failed: {e}")


# ---------------------------------------------------------------------------
# Composite notifier
# ---------------------------------------------------------------------------

class Notifier:
    def __init__(self, backends: list[NotifierBackend]):
        self.backends = backends

    def notify(self, event: str, payload: NotificationPayload) -> None:
        payload.event = event
        for backend in self.backends:
            try:
                backend.send(payload)
            except Exception as e:
                print(f"[WARN] notifier {type(backend).__name__} failed: {e}")


def build_notifiers(repo: str, log_dir: Path) -> Notifier:
    """Build active backends from environment. Extend here to add new channels."""
    backends: list[NotifierBackend] = [
        ConsoleNotifier(),
        LogFileNotifier(log_dir / "security-engineer-run.json"),
        # No PR-comment backend on purpose. The impact assessment already goes
        # into the PR body at creation time (_commit_and_pr in orchestrator.py),
        # and impact is computed *before* the PR is opened — so a comment posted
        # on fix_succeeded could only ever repeat it. It did: every PR carried
        # the same manual_steps and concerns twice, once in the description and
        # once below the diff. The body is the better home — visible from the
        # start, editable, and it does not generate a notification.
        # impact.error still reaches security-engineer-run.json via LogFileNotifier.
    ]
    webhook_url = os.environ.get("NOTIFY_WEBHOOK_URL")
    if webhook_url:
        backends.append(WebhookNotifier(webhook_url))
    return Notifier(backends)
