"""
Version-decision data layer: given a vulnerable package, which version fixes it?

Answers that question from data rather than judgement. Two public sources, both
free and unauthenticated:

  OSV.dev       which version ranges each advisory affects
  deps.dev v3   which versions were actually published

The result is deliberately auditable — target version, how far the bump reaches,
which advisories it clears, and which candidates were passed over — because the
version choice is the part of a CVE fix a reviewer most needs to be able to
check. Three consecutive runs on the same pillow alert previously produced the
same diff behind three different explanations; a decision you can re-derive is
the point of this module.

Stdlib only, and never raises: every failure path returns a VersionDecision with
`error` set, so a data-layer outage degrades the pipeline instead of stopping it.
"""
import contextlib
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

OSV_URL = "https://api.osv.dev/v1/query"
DEPS_DEV_URL = "https://api.deps.dev/v3"

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "security-engineer" / "version-data"
DEFAULT_CACHE_TTL_SEC = 6 * 3600
DEFAULT_TIMEOUT_SEC = 20

# How many safe versions beyond the target to carry forward. They feed the impact
# prompt ("what else could we have picked") and the Orca-check retry loop, which
# needs a next candidate to advance to rather than a free-form second guess.
_MAX_CANDIDATES = 5


# ---------------------------------------------------------------------------
# Ecosystems
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Ecosystem:
    """Naming for one package ecosystem across the three vocabularies we touch.

    Every source spells these differently: we say "cargo", OSV says "crates.io",
    deps.dev says "cargo". Keeping the mapping in one table is what stops that
    from turning into scattered string literals.

    manifests: filenames that imply this ecosystem, used by package_identity to
               resolve an ecosystem from an Orca alert's file path.
    """
    key: str
    osv: str
    deps_dev: str
    manifests: tuple


ECOSYSTEMS = {
    e.key: e for e in [
        Ecosystem("pypi", "PyPI", "pypi",
                  ("requirements.txt", "pyproject.toml", "setup.py",
                   "setup.cfg", "Pipfile", "poetry.lock", "requirements.in")),
        Ecosystem("npm", "npm", "npm",
                  ("package.json", "package-lock.json", "yarn.lock",
                   "pnpm-lock.yaml")),
        Ecosystem("go", "Go", "go", ("go.mod", "go.sum")),
        Ecosystem("maven", "Maven", "maven",
                  ("pom.xml", "build.gradle", "build.gradle.kts")),
        Ecosystem("cargo", "crates.io", "cargo", ("Cargo.toml", "Cargo.lock")),
        Ecosystem("rubygems", "RubyGems", "rubygems", ("Gemfile", "Gemfile.lock",
                                                       "gems.rb")),
        Ecosystem("nuget", "NuGet", "nuget", ("packages.config",)),
    ]
}

# Accept the spellings callers are likely to already have: our own keys, OSV's
# names, and a few common aliases.
_ECOSYSTEM_ALIASES = {
    "pip": "pypi", "python": "pypi", "pypi": "pypi",
    "node": "npm", "nodejs": "npm", "npm": "npm",
    "golang": "go", "go": "go",
    "java": "maven", "maven": "maven", "gradle": "maven",
    "rust": "cargo", "cargo": "cargo", "crates.io": "cargo", "crates": "cargo",
    "ruby": "rubygems", "rubygems": "rubygems", "gem": "rubygems",
    "dotnet": "nuget", "nuget": "nuget",
}


def resolve_ecosystem(name: str) -> Ecosystem | None:
    """Map any spelling of an ecosystem onto our canonical Ecosystem, or None."""
    if not name:
        return None
    key = _ECOSYSTEM_ALIASES.get(str(name).strip().lower())
    return ECOSYSTEMS.get(key) if key else None


def ecosystem_for_manifest(filename: str) -> Ecosystem | None:
    """Infer the ecosystem from a manifest or lockfile name (basename match)."""
    if not filename:
        return None
    base = Path(str(filename)).name.lower()
    for eco in ECOSYSTEMS.values():
        if any(base == m.lower() for m in eco.manifests):
            return eco
    return None


# ---------------------------------------------------------------------------
# Version parsing and ordering
# ---------------------------------------------------------------------------

# Stage ranks. A prerelease sorts before its release and a post-release after,
# which is the one ordering rule PEP 440 and SemVer agree on.
_STAGE_DEV = 0
_STAGE_PRE = 1
_STAGE_RELEASE = 2
_STAGE_POST = 3

_PRE_LABELS = {
    "a": 1, "alpha": 1,
    "b": 2, "beta": 2,
    "c": 3, "rc": 3, "pre": 3, "preview": 3,
    "snapshot": 0,          # Maven: sorts below any qualifier of the same release
    "m": 0, "milestone": 0,
}

# Qualifiers that mean "this *is* the release" rather than something before it.
# Java-world versions like 2.7.18.RELEASE or 1.0.Final would otherwise be read
# as prereleases and excluded from candidates.
_RELEASE_QUALIFIERS = {"final", "release", "ga", "stable"}

_POST_LABELS = {"post", "rev", "r"}

_VERSION_RE = re.compile(
    r"""^\s*
        v?                              # leading v: Go modules, git tags
        (?:(?P<epoch>\d+)!)?            # PEP 440 epoch
        (?P<release>\d+(?:\.\d+)*)      # dotted numeric release
        (?P<rest>.*?)\s*$               # pre/post/dev/qualifier remainder
    """,
    re.VERBOSE,
)

_SUFFIX_RE = re.compile(r"^(?P<label>[a-z]+)\.?(?P<num>\d+)?")


@dataclass(frozen=True)
class Version:
    """A parsed version with a total order.

    Deliberately not a full PEP 440 / SemVer implementation — the repo has no
    third-party dependencies, so this is hand-rolled and stops short of the
    corners neither standard agrees on. What it does guarantee is what the
    caller relies on: release versions order correctly, and anything it cannot
    read confidently is reported as a prerelease so it is never chosen as a
    bump target. Wrong-but-confident is the failure mode worth avoiding here.
    """
    raw: str
    epoch: int
    release: tuple          # normalized: trailing zeros stripped, so 1.0.0 == 1
    stage: int
    stage_label: int        # rank within the stage (alpha < beta < rc)
    stage_num: int
    understood: bool        # False when the suffix was unrecognized

    @property
    def is_prerelease(self) -> bool:
        return self.stage < _STAGE_RELEASE

    @property
    def major(self) -> int:
        return self.release[0] if self.release else 0

    @property
    def minor(self) -> int:
        return self.release[1] if len(self.release) > 1 else 0

    def sort_key(self) -> tuple:
        return (self.epoch, self.release, self.stage, self.stage_label,
                self.stage_num)

    def __lt__(self, other) -> bool:
        return self.sort_key() < other.sort_key()

    def __le__(self, other) -> bool:
        return self.sort_key() <= other.sort_key()

    def __str__(self) -> str:
        return self.raw


def parse_version(raw) -> Version | None:
    """Parse a version string, or None if it has no numeric release at all.

    Build metadata is discarded before parsing, which is what makes Go's
    `+incompatible` and SemVer's `+build.5` harmless. Go pseudo-versions
    (v0.0.0-20210119194325-5f4716e94777) fall out as a prerelease of 0.0.0,
    which is the correct place for them.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    text = text.split("+", 1)[0]          # drop build metadata
    m = _VERSION_RE.match(text)
    if not m:
        return None

    epoch = int(m.group("epoch") or 0)
    parts = tuple(int(p) for p in m.group("release").split("."))
    # Strip trailing zeros so 1.0.0, 1.0 and 1 compare equal, as both PEP 440
    # and SemVer-with-implicit-zeros expect.
    release = parts
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]

    rest = m.group("rest").lower().lstrip(".-_")
    stage, label, num, understood = _parse_suffix(rest)
    return Version(raw=str(raw).strip(), epoch=epoch, release=release,
                   stage=stage, stage_label=label, stage_num=num,
                   understood=understood)


def _parse_suffix(rest: str) -> tuple:
    """Classify a version's trailing qualifier -> (stage, label_rank, num, ok)."""
    if not rest:
        return _STAGE_RELEASE, 0, 0, True

    m = _SUFFIX_RE.match(rest)
    if not m:
        # A numeric tail is ambiguous: SemVer reads "1.0.0-1" as a prerelease,
        # PEP 440 reads "1.0-1" as a *post*-release. We take the SemVer reading
        # because the two mistakes are not symmetrical. Go pseudo-versions land
        # here (v0.0.0-20210119194325-5f4716e94777), and calling one a
        # post-release of v0.0.0 would let it be picked as a bump target —
        # recommending a commit snapshot as the fix for a CVE. Reading a real
        # post-release as a prerelease merely passes it over.
        digits = re.match(r"^(\d+)", rest)
        if digits:
            return _STAGE_PRE, 0, int(digits.group(1)), True
        return _STAGE_PRE, 0, 0, False

    label = m.group("label")
    num = int(m.group("num") or 0)

    if label in _RELEASE_QUALIFIERS:
        return _STAGE_RELEASE, 0, num, True
    if label in _POST_LABELS:
        return _STAGE_POST, 0, num, True
    if label == "dev":
        return _STAGE_DEV, 0, num, True
    if label in _PRE_LABELS:
        return _STAGE_PRE, _PRE_LABELS[label], num, True

    # Unrecognized. Sort it below the plain release and mark it not understood,
    # so candidate selection skips it instead of bumping somewhere unreadable.
    return _STAGE_PRE, 0, num, False


def bump_class(current: Version | None, target: Version | None) -> str:
    """Classify the distance of a bump: patch | minor | major | unknown."""
    if current is None or target is None:
        return "unknown"
    if target.major != current.major:
        return "major"
    if target.minor != current.minor:
        return "minor"
    return "patch"


# ---------------------------------------------------------------------------
# OSV advisory ranges -> "is this version vulnerable?"
# ---------------------------------------------------------------------------

@dataclass
class AdvisoryScope:
    """The version ranges one advisory says are vulnerable, for one package."""
    advisory_id: str
    aliases: list = field(default_factory=list)
    severity: str = ""
    exact_versions: set = field(default_factory=set)
    # (introduced, fixed, last_affected) — fixed is exclusive, last_affected
    # inclusive, and None means the interval is open at that end.
    intervals: list = field(default_factory=list)
    scoped: bool = True     # False when OSV gave us neither ranges nor versions

    def covers(self, version: Version) -> bool:
        if version.raw in self.exact_versions:
            return True
        for introduced, fixed, last_affected in self.intervals:
            if introduced is not None and version < introduced:
                continue
            if fixed is not None and not version < fixed:
                continue
            if last_affected is not None and not version <= last_affected:
                continue
            return True
        return False


def _advisory_severity(vuln: dict) -> str:
    """Best-effort severity label from an OSV record."""
    for entry in vuln.get("affected") or []:
        sev = (entry.get("ecosystem_specific") or {}).get("severity")
        if sev:
            return str(sev)
    for sev in vuln.get("severity") or []:
        if sev.get("score"):
            return str(sev["score"])
    return ""


# Which id to show a reviewer when several records describe the same flaw.
# Reviewers think in CVEs; GHSA is the next most recognizable.
_ID_PREFERENCE = ("CVE-", "GHSA-", "PYSEC-")


def _preferred_id(ids) -> str:
    """Pick the most recognizable id from an alias group."""
    for prefix in _ID_PREFERENCE:
        matches = sorted(i for i in ids if i.upper().startswith(prefix))
        if matches:
            return matches[0]
    return min(ids) if ids else ""


def advisory_scopes(vulns: list, package: str, ecosystem: Ecosystem) -> list:
    """Turn raw OSV records into per-vulnerability version scopes for a package.

    Records are merged across aliases before being returned. OSV routinely
    carries the same flaw several times over — a pillow query comes back with 76
    GHSA and 75 PYSEC records that collapse to 79 distinct vulnerabilities — and
    counting those twice would make the PR body claim roughly double the
    advisories a bump actually clears. The merge does not change which versions
    are vulnerable, only what we report.

    GIT ranges are skipped: they are commit hashes, and a version comparator has
    nothing useful to say about them.
    """
    want = (package or "").strip().lower()
    parsed = []          # (id_set, scope) before alias merging

    for vuln in vulns or []:
        vuln_id = vuln.get("id") or ""
        if not vuln_id:
            continue
        aliases = [str(a) for a in (vuln.get("aliases") or []) if a]
        scope = AdvisoryScope(advisory_id=vuln_id, aliases=aliases,
                              severity=_advisory_severity(vuln))
        saw_any_scope = False
        for entry in vuln.get("affected") or []:
            pkg = entry.get("package") or {}
            if (pkg.get("name") or "").strip().lower() != want:
                continue
            eco = (pkg.get("ecosystem") or "")
            # OSV suffixes some ecosystems (e.g. "Alpine:v3.16"); prefix-match.
            if eco and not eco.lower().startswith(ecosystem.osv.lower()):
                continue

            for v in entry.get("versions") or []:
                scope.exact_versions.add(str(v))
                saw_any_scope = True

            for rng in entry.get("ranges") or []:
                if (rng.get("type") or "").upper() == "GIT":
                    continue
                for interval in _events_to_intervals(rng.get("events") or []):
                    scope.intervals.append(interval)
                    saw_any_scope = True

        if not saw_any_scope:
            # The record matched the package but gave us nothing to compare.
            # Recorded rather than silently dropped — quietly ignoring an
            # advisory is exactly the kind of invisible gap this module exists
            # to remove.
            scope.scoped = False
        parsed.append(({vuln_id, *aliases}, scope))

    return _merge_by_alias(parsed)


def _merge_by_alias(parsed: list) -> list:
    """Union records that share any id, and merge each group into one scope.

    A group is `scoped` if *any* of its records gave us a version range: one
    database having filled in the ranges is enough to reason about the flaw.
    """
    groups = []                      # list of [id_set, [scopes]]
    for ids, scope in parsed:
        merged_into = None
        for group in list(groups):
            if group[0] & ids:
                if merged_into is None:
                    group[0] |= ids
                    group[1].append(scope)
                    merged_into = group
                else:
                    # This record bridges two groups that were separate until now.
                    merged_into[0] |= group[0]
                    merged_into[1].extend(group[1])
                    groups.remove(group)
        if merged_into is None:
            groups.append([set(ids), [scope]])

    out = []
    for ids, scopes in groups:
        merged = AdvisoryScope(
            advisory_id=_preferred_id(ids),
            aliases=sorted(ids),
            severity=next((s.severity for s in scopes if s.severity), ""),
            scoped=any(s.scoped for s in scopes),
        )
        for s in scopes:
            merged.exact_versions |= s.exact_versions
            merged.intervals.extend(s.intervals)
        # Databases describing the same flaw usually describe the same range, so
        # dedupe: identical intervals change nothing about coverage and only make
        # the diagnostic output hard to read.
        merged.intervals = list(dict.fromkeys(merged.intervals))
        out.append(merged)
    return out


def _events_to_intervals(events: list) -> list:
    """Fold an OSV range's events into (introduced, fixed, last_affected).

    `introduced: "0"` is OSV's sentinel for "from the beginning" and becomes an
    open lower bound. Events are processed in order: an `introduced` opens an
    interval and the next `fixed`/`last_affected` closes it.
    """
    intervals = []
    open_from = None
    have_open = False
    for event in events:
        if not isinstance(event, dict):
            continue
        if "introduced" in event:
            if have_open:
                intervals.append((open_from, None, None))
            raw = event["introduced"]
            open_from = None if str(raw) == "0" else parse_version(raw)
            have_open = True
        elif "fixed" in event:
            intervals.append((open_from, parse_version(event["fixed"]), None))
            open_from, have_open = None, False
        elif "last_affected" in event:
            intervals.append((open_from, None, parse_version(event["last_affected"])))
            open_from, have_open = None, False
    if have_open:
        intervals.append((open_from, None, None))
    return intervals


# ---------------------------------------------------------------------------
# Fetching, with an on-disk cache
# ---------------------------------------------------------------------------

_CACHE_FORMAT = 1


class VersionDataFetcher:
    """Fetches OSV advisories and published versions, cached on disk.

    Cached because a `--remote all` run puts up to 12 fixes in flight at once
    against two public APIs, and because it makes the unit tests hermetic:
    tests inject a fetcher backed by recorded fixtures rather than the network.
    deps.dev's terms explicitly permit caching.
    """

    def __init__(self, cache_dir=DEFAULT_CACHE_DIR, cache_ttl_sec=DEFAULT_CACHE_TTL_SEC,
                 timeout_sec=DEFAULT_TIMEOUT_SEC, offline=False,
                 osv_url=OSV_URL, deps_dev_url=DEPS_DEV_URL):
        self.cache_dir = Path(cache_dir)
        self.cache_ttl_sec = cache_ttl_sec
        self.timeout_sec = timeout_sec
        self.offline = offline
        self.osv_url = osv_url
        self.deps_dev_url = deps_dev_url
        self.sources = []          # human-readable trail: what we hit, cache or net

    # -- public -------------------------------------------------------------

    def osv_advisories(self, package: str, ecosystem: Ecosystem) -> list:
        """Every OSV advisory for the package, regardless of version.

        Queried package-wide on purpose. Asking only about the alert's own CVE
        is how you bump straight into a different one — the failure mode
        fix-agents/cve.md currently tries to handle with prose after the fact.
        """
        payload = self._cached("osv", ecosystem, package, lambda: self._post_json(
            self.osv_url,
            {"package": {"name": package, "ecosystem": ecosystem.osv}},
        ))
        return (payload or {}).get("vulns") or []

    def published_versions(self, package: str, ecosystem: Ecosystem) -> list:
        """Version strings deps.dev has seen published for the package."""
        quoted = urllib.parse.quote(package, safe="")
        url = f"{self.deps_dev_url}/systems/{ecosystem.deps_dev}/packages/{quoted}"
        payload = self._cached("versions", ecosystem, package,
                               lambda: self._get_json(url))
        out = []
        for entry in (payload or {}).get("versions") or []:
            v = (entry.get("versionKey") or {}).get("version")
            if v:
                out.append(str(v))
        return out

    # -- cache --------------------------------------------------------------

    def _cache_path(self, kind: str, ecosystem: Ecosystem, package: str) -> Path:
        # quote() keeps scoped npm names (@babel/core) and Go module paths from
        # turning into directory traversal.
        safe = urllib.parse.quote(package, safe="")
        return self.cache_dir / ecosystem.key / f"{safe}.{kind}.json"

    def _cached(self, kind: str, ecosystem: Ecosystem, package: str, fetch):
        path = self._cache_path(kind, ecosystem, package)
        hit = self._read_cache(path)
        if hit is not None:
            self.sources.append(f"{kind}:{ecosystem.key}/{package} (cache)")
            return hit
        if self.offline:
            self.sources.append(f"{kind}:{ecosystem.key}/{package} (offline, no cache)")
            return None
        payload = fetch()
        self.sources.append(f"{kind}:{ecosystem.key}/{package} (fetched)")
        self._write_cache(path, payload)
        return payload

    def _read_cache(self, path: Path):
        try:
            with open(path) as f:
                blob = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        if blob.get("cache_format") != _CACHE_FORMAT:
            return None
        fetched_at = blob.get("fetched_at") or 0
        # offline mode ignores the TTL: stale data beats no data when the whole
        # point of the mode is that we cannot refresh it.
        if not self.offline and (time.time() - fetched_at) > self.cache_ttl_sec:
            return None
        return blob.get("payload")

    def _write_cache(self, path: Path, payload) -> None:
        blob = {"cache_format": _CACHE_FORMAT, "fetched_at": time.time(),
                "payload": payload}
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Write-then-rename so a concurrent reader never sees a half file.
            # 12 fixes can be in flight against the same cache directory.
            fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(blob, f)
                os.replace(tmp, path)
            except BaseException:
                with contextlib.suppress(OSError):
                    os.unlink(tmp)
                raise
        except OSError as e:
            # A cache we cannot write is a slow cache, not a broken run.
            print(f"[WARN] version-data cache write failed for {path}: {e}", flush=True)

    # -- http ---------------------------------------------------------------

    def _get_json(self, url: str):
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        return self._read_json(req, url)

    def _post_json(self, url: str, body: dict):
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"},
            method="POST")
        return self._read_json(req, url)

    def _read_json(self, req, url: str):
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")[:200]
            raise RuntimeError(f"HTTP {e.code} from {url}: {body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"cannot reach {url}: {e.reason}") from e


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------

@dataclass
class VersionDecision:
    """Why we are bumping to this version, in a form a reviewer can re-derive."""
    ecosystem: str
    package: str
    current_version: str
    target_version: str | None = None
    bump_class: str = "unknown"
    majors_crossed: int = 0
    advisories_cleared: list = field(default_factory=list)
    advisories_remaining: list = field(default_factory=list)
    advisories_unknown_scope: list = field(default_factory=list)
    candidates: list = field(default_factory=list)
    rationale: str = ""
    data_sources: list = field(default_factory=list)
    error: str | None = None

    @property
    def resolved(self) -> bool:
        return bool(self.target_version) and self.error is None

    def to_dict(self) -> dict:
        return dict(vars(self))


def resolve_bump(ecosystem, package: str, current_version: str,
                 fetcher: VersionDataFetcher | None = None,
                 **fetcher_kwargs) -> VersionDecision:
    """Pick the lowest published version that clears every advisory on a package.

    Policy is minimum-safe at any distance: we do not refuse to cross a major
    boundary, because for some packages there is no safe release inside the
    current major. What we do instead is classify the distance and hand that to
    impact analysis, so a four-major jump is labelled rather than stumbled into.

    Never raises. On any failure the decision comes back with `error` set and no
    target, and the caller is expected to fall back to its previous behaviour.
    """
    eco = ecosystem if isinstance(ecosystem, Ecosystem) else resolve_ecosystem(ecosystem)
    eco_key = eco.key if eco else str(ecosystem)
    decision = VersionDecision(ecosystem=eco_key, package=package,
                               current_version=current_version)
    if eco is None:
        decision.error = f"unknown ecosystem: {ecosystem!r}"
        return decision

    current = parse_version(current_version)
    if current is None:
        decision.error = f"cannot parse current version: {current_version!r}"
        return decision

    fetcher = fetcher or VersionDataFetcher(**fetcher_kwargs)
    try:
        vulns = fetcher.osv_advisories(package, eco)
        published = fetcher.published_versions(package, eco)
    except Exception as e:
        decision.data_sources = list(fetcher.sources)
        decision.error = f"{type(e).__name__}: {e}"
        return decision
    decision.data_sources = list(fetcher.sources)

    scopes = advisory_scopes(vulns, package, eco)
    decision.advisories_unknown_scope = sorted(
        s.advisory_id for s in scopes if not s.scoped)
    usable = [s for s in scopes if s.scoped]

    affecting_current = [s for s in usable if s.covers(current)]
    if not published:
        decision.error = "no published versions found"
        return decision

    safe = _safe_upgrades(published, current, usable)
    if safe:
        target, target_ver = safe[0]
        decision.target_version = target
        decision.bump_class = bump_class(current, target_ver)
        decision.majors_crossed = max(0, target_ver.major - current.major)
        decision.advisories_cleared = sorted(
            s.advisory_id for s in affecting_current if not s.covers(target_ver))
        decision.advisories_remaining = sorted(
            s.advisory_id for s in affecting_current if s.covers(target_ver))
        decision.candidates = [
            {"version": v, "bump_class": bump_class(current, pv)}
            for v, pv in safe[:_MAX_CANDIDATES]
        ]
        decision.rationale = _rationale(decision, affecting_current)
        return decision

    # Nothing is fully clean. Take the version that clears the most advisories
    # affecting us — a partial fix that says so beats no fix that pretends.
    best = _best_effort_upgrade(published, current, affecting_current)
    if best is None:
        decision.advisories_remaining = sorted(s.advisory_id for s in affecting_current)
        decision.error = ("no published version above "
                          f"{current_version} clears any advisory")
        decision.rationale = (
            f"No release of {package} above {current_version} clears the "
            f"{len(affecting_current)} advisory(ies) affecting it. Needs a "
            "human decision: replace the dependency, or accept the risk.")
        return decision

    target, target_ver, cleared, remaining = best
    decision.target_version = target
    decision.bump_class = bump_class(current, target_ver)
    decision.majors_crossed = max(0, target_ver.major - current.major)
    decision.advisories_cleared = sorted(cleared)
    decision.advisories_remaining = sorted(remaining)
    decision.candidates = [{"version": target,
                            "bump_class": decision.bump_class}]
    decision.rationale = _rationale(decision, affecting_current)
    return decision


def _safe_upgrades(published: list, current: Version, scopes: list) -> list:
    """Published versions above `current` that no advisory covers, lowest first.

    Prereleases are excluded, with one exception: a prerelease of the *same*
    release the caller is already on, so someone pinned to 2.0.0-rc1 can still
    be moved to 2.0.0-rc2. Merely being on a prerelease is not enough — a Go
    module pinned to a pseudo-version of v0.0.0 would otherwise make every
    later pseudo-version a candidate, and offering a commit snapshot as the fix
    for a CVE is not an upgrade anyone wants suggested on retry.

    Versions whose suffix we could not read are excluded for the same reason.
    """
    out = []
    for raw in published:
        v = parse_version(raw)
        if v is None or not v.understood:
            continue
        if v.is_prerelease and v.release != current.release:
            continue
        if not current < v:
            continue
        if any(s.covers(v) for s in scopes):
            continue
        out.append((raw, v))
    out.sort(key=lambda pair: pair[1].sort_key())
    return out


def _best_effort_upgrade(published: list, current: Version, affecting: list):
    """Highest-value partial upgrade: clears the most advisories, then lowest."""
    graded = []
    for raw in published:
        v = parse_version(raw)
        if v is None or not v.understood:
            continue
        if v.is_prerelease and not current.is_prerelease:
            continue
        if not current < v:
            continue
        cleared = [s.advisory_id for s in affecting if not s.covers(v)]
        remaining = [s.advisory_id for s in affecting if s.covers(v)]
        if not cleared:
            continue
        graded.append((-len(cleared), v.sort_key(), raw, v, cleared, remaining))
    if not graded:
        return None
    graded.sort(key=lambda g: (g[0], g[1]))
    _, _, raw, v, cleared, remaining = graded[0]
    return raw, v, cleared, remaining


def _rationale(decision: VersionDecision, affecting: list) -> str:
    """One reviewable sentence: what we picked, why, and what it leaves behind."""
    cleared = decision.advisories_cleared
    bits = [(f"{decision.package} {decision.current_version} → "
             f"{decision.target_version}")]
    if decision.bump_class != "unknown":
        span = f"{decision.bump_class} bump"
        if decision.majors_crossed > 1:
            span += f", {decision.majors_crossed} major versions"
        bits.append(span)
    if cleared:
        shown = ", ".join(cleared[:4])
        more = f" (+{len(cleared) - 4} more)" if len(cleared) > 4 else ""
        bits.append(f"lowest published release clearing {shown}{more}")
    elif not affecting:
        bits.append("no advisory in OSV covers the installed version")
    if decision.advisories_remaining:
        bits.append("still affected by " + ", ".join(decision.advisories_remaining[:4]))
    if decision.advisories_unknown_scope:
        bits.append(f"{len(decision.advisories_unknown_scope)} advisory(ies) "
                    "had no version range and could not be assessed")
    return "; ".join(bits) + "."
