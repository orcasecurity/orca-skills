#!/usr/bin/env python3
"""
The CVE specialist: decide the version before the agent runs, then check it did.

Two things happen here that did not happen before.

`prepare()` resolves the target version from OSV and deps.dev and hands the agent
a directive. The agent used to be asked to find the patched version itself, from
Orca's free-text `recommendation` or failing that from memory, which produced the
same bump behind three different explanations across three runs.

`verify()` checks the manifest. Phase 3 was a silent no-op for every CVE fix:
`local_build_check` dispatches on the dominant file extension, and a CVE fix
touches requirements.txt (.txt), go.mod (.mod) or package.json (.json) — all of
which fell through to `else: pass`. `go build ./...` had never once run on a CVE
fix. So the gate that was supposed to catch a broken bump could not see one.
"""
import sys
from pathlib import Path

from package_identity import find_dependency, identify_package, read_manifest
from validator import ValidationResult, _find_project_root, _run_check

from pipelines.base import FixPipeline, FixPlan

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "lib"))
from version_data import VersionDataFetcher, advisory_scopes, parse_version, resolve_bump

# Where the per-ecosystem agent instructions live, appended to fix-agents/cve.md.
_FRAGMENT_DIR = Path(__file__).parent.parent / "fix-agents" / "cve"

# Resolve checks that are cheap and do not mutate the tree or need the network.
# pypi/npm/maven install-resolution is deliberately absent: `pip install` and
# `npm install` are slow, online, and rewrite lockfiles, which is the fix agent's
# job rather than the gate's. CI covers what is left.
_RESOLVE_CHECKS = {
    "go": (["go", "build", "./..."], "go.mod"),
    "cargo": (["cargo", "metadata", "--locked", "--format-version", "1"],
              "Cargo.toml"),
}


def build_fetcher(cfg=None) -> VersionDataFetcher | None:
    """Fetcher configured from `version_data:`, or None when disabled.

    A None fetcher makes CvePipeline.prepare fall through to the agent's own
    judgement, which is the pre-existing behaviour — so `enabled: false` is a
    real off switch rather than a broken pipeline.
    """
    if cfg is None:
        return VersionDataFetcher()
    if not getattr(cfg, "enabled", True):
        return None
    kwargs = {"cache_ttl_sec": cfg.cache_ttl_sec,
              "timeout_sec": cfg.timeout_sec,
              "offline": cfg.offline}
    if cfg.cache_dir:
        kwargs["cache_dir"] = Path(cfg.cache_dir)
    if cfg.osv_url:
        kwargs["osv_url"] = cfg.osv_url
    if cfg.deps_dev_url:
        kwargs["deps_dev_url"] = cfg.deps_dev_url
    return VersionDataFetcher(**kwargs)


class CvePipeline(FixPipeline):
    """Package-dependency CVEs: manifest bumps with a derived target version."""

    feature_type = "cve"

    def __init__(self, timeout_sec: int = 240, diff_limit: int = 200,
                 fetcher: VersionDataFetcher | None = None,
                 allow_llm_identify: bool = True):
        super().__init__("cve", timeout_sec, diff_limit)
        self.fetcher = fetcher
        self.allow_llm_identify = allow_llm_identify

    # -- before the agent runs ----------------------------------------------

    def prepare(self, task, worktree_path: Path) -> FixPlan:
        """Identify the package and decide the version, then say so plainly.

        Any failure comes back as a FixPlan with `error` set and no directive.
        The caller is expected to fall through to the agent's own judgement and
        flag the alert for review — a data-layer outage should cost us
        determinism, not the fix.
        """
        ref = identify_package(task.alert_json or {}, worktree_path,
                               allow_llm=self.allow_llm_identify)
        if not ref.ok:
            return FixPlan(error=f"package identification failed: {ref.error}",
                           needs_review=True)

        decision = resolve_bump(ref.ecosystem, ref.package, ref.current_version,
                               fetcher=self.fetcher)
        if not decision.resolved:
            return FixPlan(error=f"version resolution failed: {decision.error}",
                           needs_review=True,
                           metadata={"package_ref": ref.to_dict(),
                                     "version_decision": decision.to_dict()})

        requested = list(getattr(task, "requested_cves", None) or [])
        metadata = {"package_ref": ref.to_dict(),
                    "version_decision": decision.to_dict(),
                    "requested_cves": requested}
        plan = FixPlan(
            summary=decision.rationale,
            prompt_extra=self._directive(ref, decision, requested),
            metadata=metadata,
            # A bump we could not classify, or one that leaves advisories behind,
            # is not something to merge unread.
            needs_review=(decision.bump_class == "unknown"
                          or bool(decision.advisories_remaining)
                          or bool(decision.advisories_unknown_scope)
                          or not ref.exact_pin),
        )
        return plan

    def _directive(self, ref, decision, requested_cves=None) -> str:
        """The instruction the agent gets instead of a research task."""
        lines = [
            "## Target Version (already decided — do not choose another)",
            "",
            (f"Set **{ref.package}** to exactly **{decision.target_version}** "
             f"in `{ref.manifest_path}`."),
            "",]
        if requested_cves:
            # Without this the agent only sees a package alert and may reason
            # its way to the *smallest* bump that fixes the headline CVE. The
            # target below already clears the requested one along with the rest.
            lines += [
                (f"This alert was selected because it carries "
                 f"{', '.join(requested_cves)}. The target version below clears "
                 "it along with the package's other advisories — do not narrow "
                 "the bump to that one advisory."),
                "",
            ]
        lines += [
            f"- Ecosystem: {ref.ecosystem.key}",
            f"- Currently declared: {ref.current_version}"
            + ("" if ref.exact_pin else " (a range, not an exact pin)"),
            f"- Bump: {decision.bump_class}"
            + (f", crossing {decision.majors_crossed} major versions"
               if decision.majors_crossed > 1 else ""),
            f"- Why this version: {decision.rationale}",
        ]
        if decision.advisories_remaining:
            lines.append("- Still affected after this bump: "
                         + ", ".join(decision.advisories_remaining))
        if len(decision.candidates) > 1:
            others = ", ".join(c["version"] for c in decision.candidates[1:])
            lines.append(f"- Safe alternatives, if and only if the target cannot "
                         f"be applied: {others}")
        lines += [
            "",
            ("This version was resolved from OSV advisory ranges and the "
             "published version list. It is the lowest release that clears the "
             "advisories affecting the installed version. Do **not** substitute a "
             "different version, and do not 'upgrade to latest' — if "
             f"{decision.target_version} cannot be applied, report failure with "
             "the reason instead."),
        ]
        fragment = self._ecosystem_fragment(ref.ecosystem.key)
        if fragment:
            lines += ["", fragment]
        return "\n".join(lines)

    def _ecosystem_fragment(self, ecosystem_key: str) -> str:
        """Per-ecosystem instructions, if we have written them for this one."""
        path = _FRAGMENT_DIR / f"{ecosystem_key}.md"
        try:
            return path.read_text()
        except OSError:
            return ""

    # -- after the agent runs ----------------------------------------------

    def verify(self, task, worktree_path: Path,
               plan: FixPlan | None = None) -> ValidationResult:
        """Did the manifest actually end up pinning a safe version?

        Without a plan we cannot say what "correct" was, so fall back to the
        generic build check rather than inventing a verdict.
        """
        decision = (plan.metadata.get("version_decision") if plan else None) or {}
        ref = (plan.metadata.get("package_ref") if plan else None) or {}
        target = decision.get("target_version")
        package = ref.get("package")
        manifest_rel = ref.get("manifest_path")
        if not (target and package and manifest_rel):
            return super().verify(task, worktree_path, plan)

        failures = []
        manifest_abs = Path(worktree_path) / manifest_rel
        applied = self._applied_version(manifest_abs, package, ref)

        started_at = ref.get("current_version")

        if applied is None:
            failures.append(
                f"{package} is no longer declared in {manifest_rel} — the fix "
                "removed the dependency instead of bumping it")
        elif started_at and self._same_version(applied, started_at) \
                and not self._same_version(applied, target):
            # Still on the version we set out to replace. This needs no advisory
            # lookup to judge — the bump simply did not happen — which matters
            # because the advisory check below fails open, so an outage would
            # otherwise let an untouched manifest through.
            failures.append(
                f"{package} is still pinned to {applied} in {manifest_rel} — the "
                f"version the alert was raised against. No bump was applied "
                f"(target was {target})")
        elif not self._same_version(applied, target):
            # The agent went its own way. That is only a failure if where it went
            # is unsafe; a different-but-clean version is worth flagging, not
            # rejecting outright.
            if self._is_vulnerable(ref, applied):
                failures.append(
                    f"{package} is pinned to {applied} in {manifest_rel}, not the "
                    f"resolved target {target}, and {applied} is still covered by "
                    "a known advisory")
            else:
                print(f"[WARN] {task.alert_id} {package} pinned to {applied}, not "
                      f"the resolved target {target}; {applied} has no known "
                      "advisory so allowing it", flush=True)

        lock_failure = self._lockfile_disagrees(manifest_abs, package, ref, applied)
        if lock_failure:
            failures.append(lock_failure)

        requested = (plan.metadata.get("requested_cves") if plan else None) or []
        if applied and requested:
            still_open = self._requested_still_open(ref, applied, requested)
            if still_open:
                failures.append(
                    f"{package} was bumped to {applied}, but "
                    f"{', '.join(still_open)} — the advisory this run was asked "
                    "to fix — still covers that version")

        if failures:
            return ValidationResult(passed=False, phase="local_build",
                                    failures=failures)

        return self._resolve_check(ref, manifest_rel, worktree_path)

    def _applied_version(self, manifest_abs: Path, package: str, ref: dict):
        """The version the manifest declares now, or None if it is gone."""
        eco = self._ecosystem(ref)
        deps = read_manifest(manifest_abs)
        if not deps:
            return None
        dep = find_dependency(deps, package, eco)
        return dep.version if dep and dep.version else None

    def _lockfile_disagrees(self, manifest_abs: Path, package: str, ref: dict,
                            applied) -> str:
        """Catch a manifest edited without regenerating the lockfile."""
        from package_identity import _LOCKFILES

        eco = self._ecosystem(ref)
        for lockname in _LOCKFILES.get(manifest_abs.name.lower(), ()):
            lock_path = manifest_abs.parent / lockname
            if not lock_path.exists():
                continue
            locked = read_manifest(lock_path)
            dep = find_dependency(locked, package, eco)
            if not dep or not dep.version:
                continue
            if applied and not self._same_version(dep.version, applied):
                return (f"{lockname} still resolves {package} to {dep.version} "
                        f"while the manifest says {applied} — the lockfile was "
                        "not regenerated")
        return ""

    def _resolve_check(self, ref: dict, manifest_rel: str,
                       worktree_path: Path) -> ValidationResult:
        """Run the ecosystem's own check, where one is cheap and offline."""
        eco_key = ref.get("ecosystem")
        entry = _RESOLVE_CHECKS.get(eco_key)
        if entry is None:
            return ValidationResult(passed=True, phase="local_build")
        cmd, marker = entry
        root = _find_project_root([manifest_rel], Path(worktree_path), marker)
        return _run_check(cmd, root)

    # -- helpers -----------------------------------------------------------

    def _ecosystem(self, ref: dict):
        from version_data import resolve_ecosystem
        return resolve_ecosystem(ref.get("ecosystem") or "")

    @staticmethod
    def _same_version(a: str, b: str) -> bool:
        """Compare through the parser so v1.2.3, 1.2.3 and 1.2.3.0 agree."""
        pa, pb = parse_version(a), parse_version(b)
        if pa is None or pb is None:
            return str(a).strip() == str(b).strip()
        return pa.sort_key() == pb.sort_key()

    def _requested_still_open(self, ref: dict, version: str,
                              requested: list) -> list:
        """Which of the requested advisories still cover the applied version.

        Matched against each scope's aliases as well as its id: OSV groups the
        CVE and GHSA records describing one flaw, and `_preferred_id` collapses
        the group to a single id — so a requested CVE routinely survives only as
        an alias. Comparing ids alone would miss it and report a clean bump as a
        failure.

        Fails *open*, like `_is_vulnerable`: an unreachable OSV must cost us the
        check, not the fix.
        """
        eco = self._ecosystem(ref)
        parsed = parse_version(version)
        if eco is None or parsed is None or not requested:
            return []
        try:
            fetcher = self.fetcher or VersionDataFetcher()
            vulns = fetcher.osv_advisories(ref.get("package", ""), eco)
        except Exception:
            return []

        wanted = {str(c).upper() for c in requested}
        still_open = []
        for scope in advisory_scopes(vulns, ref.get("package", ""), eco):
            if not scope.scoped or not scope.covers(parsed):
                continue
            ids = {str(scope.advisory_id).upper()}
            ids.update(str(a).upper() for a in (scope.aliases or []))
            still_open.extend(sorted(wanted & ids))
        return sorted(set(still_open))

    def _is_vulnerable(self, ref: dict, version: str) -> bool:
        """Is this version covered by a known advisory? Cache-backed.

        Fails *open* — if we cannot reach the data, we do not claim a version is
        vulnerable, because that would turn an outage into a rejected fix.
        """
        eco = self._ecosystem(ref)
        parsed = parse_version(version)
        if eco is None or parsed is None:
            return False
        try:
            fetcher = self.fetcher or VersionDataFetcher()
            vulns = fetcher.osv_advisories(ref.get("package", ""), eco)
        except Exception:
            return False
        scopes = [s for s in advisory_scopes(vulns, ref.get("package", ""), eco)
                  if s.scoped]
        return any(s.covers(parsed) for s in scopes)
