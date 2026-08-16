#!/usr/bin/env python3
"""
Work out which package, at which version, an Orca CVE alert is actually about.

Orca does not tell us directly. `_normalize_alert` keeps no package name, no
installed version and no ecosystem — a package CVE arrives as a title like
"pillow Package Vulnerabilities", a manifest path in `source`, and CVE ids in
`labels`. Everything else has to be recovered from the repository.

The manifest is the authority and the alert is the hint. That direction matters:
a title naming a package that is not in the manifest means we have the wrong
file or the wrong repo, and inventing a package name from prose is how you end
up editing something nobody asked you to touch.
"""
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "lib"))
from _json_util import find_last_json_with_key
from validator import _SINGLE_SHOT_MAX_TURNS, _SINGLE_SHOT_TOOL_FLAGS, _subprocess_error_detail
from version_data import Ecosystem, ecosystem_for_manifest

try:                                    # stdlib from 3.11
    import tomllib
except ImportError:                     # pragma: no cover - older interpreters
    tomllib = None


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class Dependency:
    """One declared dependency, as the manifest actually writes it."""
    name: str               # as written in the file
    spec: str               # raw version spec, e.g. "^4.17.4" or "==8.3.1"
    version: str = ""       # concrete version extracted from spec, if any
    exact: bool = False     # True when the spec pins exactly one version


@dataclass
class PackageRef:
    """Everything the CVE pipeline needs to ask "which version fixes this?"."""
    ecosystem: Ecosystem
    package: str
    current_version: str
    manifest_path: str                       # repo-relative, as Orca reported it
    cve_ids: list = field(default_factory=list)
    exact_pin: bool = True                   # False when the spec was a range
    resolved_by: str = ""                    # audit trail: how we got here
    error: str | None = None

    @property
    def ok(self) -> bool:
        return bool(self.package and self.current_version and self.error is None)

    def to_dict(self) -> dict:
        d = dict(vars(self))
        d["ecosystem"] = self.ecosystem.key if self.ecosystem else None
        return d


# ---------------------------------------------------------------------------
# Name normalization
# ---------------------------------------------------------------------------

def normalize_name(name: str, ecosystem: Ecosystem | None = None) -> str:
    """Fold a package name to a comparable form.

    PyPI treats runs of `-`, `_` and `.` as equivalent and is case-insensitive
    (PEP 503), so `Pillow`, `pillow` and `PIL-low` collide. Other ecosystems are
    case-sensitive in principle but we compare case-insensitively anyway,
    because we are matching against prose written by a scanner.
    """
    text = (name or "").strip().lower()
    if ecosystem is not None and ecosystem.key == "pypi":
        text = re.sub(r"[-_.]+", "-", text)
    return text


# ---------------------------------------------------------------------------
# Version specs
# ---------------------------------------------------------------------------

# Range operators we strip to recover a base version. `==` and `===` are exact;
# everything else describes a set, and the base is only a starting point.
_EXACT_PREFIXES = ("===", "==")
_RANGE_CHARS = "^~>=<!*"

# The leading `v` is captured, not stripped. Go modules require it in go.mod and
# in OSV queries, and this version string is what gets written back into the
# manifest — reporting golang.org/x/net at "0.0.0-2021…" would be wrong twice.
_VERSION_IN_SPEC = re.compile(r"v?\d+(?:\.\d+)*(?:[-+.][0-9A-Za-z.-]+)?")


def parse_spec(spec: str) -> tuple:
    """Read a version spec -> (concrete_version, is_exact).

    A range like `^4.17.4` yields its base version and `is_exact=False`. The
    base is a defensible stand-in for "installed": npm would resolve `^4.17.4`
    to at least 4.17.4, so advisories that stop below it do not apply. The
    lockfile is the real authority and is consulted first where we can read one.
    """
    text = (spec or "").strip()
    if not text:
        return "", False

    exact = False
    for prefix in _EXACT_PREFIXES:
        if text.startswith(prefix):
            exact = True
            text = text[len(prefix):].strip()
            break
    else:
        # A bare "4.17.4" with no operator is an exact pin in requirements.txt,
        # go.mod and Cargo.lock; in package.json it means the same thing. A range
        # character *anywhere* disqualifies it, not just in first position —
        # "4.*" starts with a digit but pins nothing.
        exact = (bool(text)
                 and not any(c in text for c in _RANGE_CHARS)
                 and "," not in text and " " not in text)

    match = _VERSION_IN_SPEC.search(text)
    if not match:
        return "", False
    version = match.group(0)
    # A comma or space means several clauses, so nothing is pinned.
    if "," in (spec or "") or len((spec or "").split()) > 1:
        exact = False
    return version, exact


# ---------------------------------------------------------------------------
# Manifest readers
# ---------------------------------------------------------------------------

def _read_requirements(text: str) -> dict:
    """requirements.txt / requirements.in — one requirement per line."""
    out = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):        # -r other.txt, -e ., --flags
            continue
        line = line.split(";", 1)[0].strip()        # drop env markers
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(\[[^\]]*\])?\s*(.*)$", line)
        if not m:
            continue
        name, spec = m.group(1), (m.group(3) or "").strip()
        version, exact = parse_spec(spec)
        out[name] = Dependency(name=name, spec=spec, version=version, exact=exact)
    return out


def _read_package_json(text: str) -> dict:
    """package.json — every dependency section, since a CVE can sit in any."""
    out = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version, exact = parse_spec(str(spec))
            out[name] = Dependency(name=name, spec=str(spec), version=version,
                                   exact=exact)
    return out


def _read_go_mod(text: str) -> dict:
    """go.mod — both `require (...)` blocks and single-line requires.

    `// indirect` markers are kept: a transitive module is still the thing the
    advisory names, and go.mod is where the bump has to be written.
    """
    out = {}
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if re.match(r"^require\s*\($", line):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if not in_block:
            m = re.match(r"^require\s+(\S+)\s+(\S+)$", line)
        else:
            m = re.match(r"^(\S+)\s+(\S+)$", line)
        if not m:
            continue
        name, spec = m.group(1), m.group(2)
        # go.mod versions are already canonical and always exact, so the spec is
        # the version — no need to re-derive it.
        out[name] = Dependency(name=name, spec=spec, version=spec, exact=True)
    return out


def _read_toml_deps(text: str, tables: tuple) -> dict:
    """Cargo.toml / pyproject.toml — dependency tables, string or table form."""
    out = {}
    if tomllib is None:
        return out
    try:
        data = tomllib.loads(text)
    except Exception:
        return out

    def walk(node, path):
        for key in path:
            node = (node or {}).get(key)
            if node is None:
                return None
        return node

    for table in tables:
        section = walk(data, table)
        if isinstance(section, dict):
            for name, spec in section.items():
                # Cargo allows `serde = { version = "1.0", features = [...] }`
                raw = spec.get("version", "") if isinstance(spec, dict) else spec
                version, exact = parse_spec(str(raw))
                out[name] = Dependency(name=name, spec=str(raw), version=version,
                                       exact=exact)
        elif isinstance(section, list):
            # PEP 621 project.dependencies is a list of requirement strings.
            out.update(_read_requirements("\n".join(str(s) for s in section)))
    return out


def _read_pom(text: str) -> dict:
    """pom.xml — groupId:artifactId, the coordinate OSV and deps.dev expect."""
    out = {}
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    # Maven POMs are namespaced; match on the local tag name instead of
    # hardcoding a namespace URI that varies by schema version.
    def local(tag):
        return tag.rsplit("}", 1)[-1]

    for dep in root.iter():
        if local(dep.tag) != "dependency":
            continue
        fields = {local(c.tag): (c.text or "").strip() for c in dep}
        group, artifact = fields.get("groupId"), fields.get("artifactId")
        if not group or not artifact:
            continue
        spec = fields.get("version", "")
        version, exact = parse_spec(spec)
        name = f"{group}:{artifact}"
        out[name] = Dependency(name=name, spec=spec, version=version, exact=exact)
    return out


def _read_gemfile_lock(text: str) -> dict:
    """Gemfile.lock — resolved versions, which beats parsing the Ruby DSL."""
    out = {}
    for raw in text.splitlines():
        m = re.match(r"^\s{4,}([A-Za-z0-9._-]+)\s+\(([^)]+)\)\s*$", raw)
        if not m:
            continue
        name, spec = m.group(1), m.group(2)
        version, _ = parse_spec(spec)
        if version:
            out[name] = Dependency(name=name, spec=spec, version=version,
                                   exact=True)
    return out


def _read_gemfile(text: str) -> dict:
    """Gemfile — `gem "name", "1.2.3"`. A version is often absent by design."""
    out = {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        m = re.match(r"""^gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?""", line)
        if not m:
            continue
        name, spec = m.group(1), (m.group(2) or "")
        version, exact = parse_spec(spec)
        out[name] = Dependency(name=name, spec=spec, version=version, exact=exact)
    return out


def _read_package_lock(text: str) -> dict:
    """package-lock.json — resolved versions, authoritative over a range spec."""
    out = {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return out
    # lockfileVersion 2/3 keep entries under "packages" keyed by install path.
    for path, entry in (data.get("packages") or {}).items():
        if not path or not isinstance(entry, dict):
            continue
        name = entry.get("name") or path.split("node_modules/")[-1]
        version = entry.get("version")
        if name and version:
            out[name] = Dependency(name=name, spec=str(version),
                                   version=str(version), exact=True)
    # lockfileVersion 1 uses a nested "dependencies" tree.
    def walk(node):
        for name, entry in (node or {}).items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if version and name not in out:
                out[name] = Dependency(name=name, spec=str(version),
                                       version=str(version), exact=True)
            walk(entry.get("dependencies"))

    walk(data.get("dependencies"))
    return out


# Manifests keyed by filename. Lockfiles are listed separately because they are
# consulted only to resolve a range spec, never to decide what to edit.
_MANIFEST_READERS = {
    "requirements.txt": _read_requirements,
    "requirements.in": _read_requirements,
    "package.json": _read_package_json,
    "go.mod": _read_go_mod,
    "pom.xml": _read_pom,
    "gemfile": _read_gemfile,
    "gemfile.lock": _read_gemfile_lock,
    "package-lock.json": _read_package_lock,
    "cargo.toml": lambda t: _read_toml_deps(
        t, (("dependencies",), ("dev-dependencies",), ("build-dependencies",))),
    "pyproject.toml": lambda t: _read_toml_deps(
        t, (("project", "dependencies"),
            ("tool", "poetry", "dependencies"),
            ("tool", "poetry", "dev-dependencies"))),
}

# Where to look for a resolved version when the manifest only gives a range.
_LOCKFILES = {
    "package.json": ("package-lock.json",),
    "gemfile": ("Gemfile.lock",),
}


def read_manifest(path) -> dict:
    """Parse a manifest into {name: Dependency}. Unreadable files give {}."""
    p = Path(path)
    reader = _MANIFEST_READERS.get(p.name.lower())
    if reader is None:
        return {}
    try:
        text = p.read_text(errors="replace")
    except OSError:
        return {}
    return reader(text)


def find_dependency(deps: dict, name: str,
                    ecosystem: Ecosystem | None = None) -> Dependency | None:
    """Look a package up in a parsed manifest, tolerant of name spelling."""
    want = normalize_name(name, ecosystem)
    for key, dep in deps.items():
        if normalize_name(key, ecosystem) == want:
            return dep
    return None


# ---------------------------------------------------------------------------
# Identification
# ---------------------------------------------------------------------------

# Words that appear in Orca's generated titles and are never package names.
_TITLE_NOISE = {
    "package", "packages", "vulnerability", "vulnerabilities", "vulnerable",
    "cve", "in", "the", "a", "an", "and", "or", "of", "for", "with", "high",
    "critical", "medium", "low", "severity", "risk", "outdated", "dependency",
    "dependencies", "library", "libraries", "version", "versions", "found",
    "detected", "known", "security", "issue", "issues", "advisory",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def cve_ids_from_alert(alert: dict) -> list:
    """CVE ids from `labels`, falling back to the alert's prose."""
    found = []
    for label in alert.get("labels") or []:
        for m in _CVE_RE.finditer(str(label)):
            found.append(m.group(0).upper())
    if not found:
        for key in ("title", "description", "recommendation"):
            for m in _CVE_RE.finditer(str(alert.get(key) or "")):
                found.append(m.group(0).upper())
    return sorted(set(found))


# Alert fields that might name the package, most trustworthy first. Orca puts the
# subject in the title; description and recommendation are prose that may mention
# other packages in passing.
_NAME_SOURCES = ("title", "description", "recommendation")


def _candidate_names(alert: dict) -> list:
    """Candidate package names grouped by source, most trustworthy group first.

    Grouped rather than flattened because precedence has to beat match length: a
    title naming `pillow` must win over a description that happens to mention
    `flask`, and with one flat list the longer string would win by accident.
    """
    groups = []
    for key in _NAME_SOURCES:
        text = str(alert.get(key) or "")
        tokens = []
        for token in re.findall(r"[A-Za-z0-9][A-Za-z0-9._/:-]*", text):
            if token.lower() in _TITLE_NOISE or _CVE_RE.match(token):
                continue
            tokens.append(token)
        groups.append(tokens)
    return groups


def identify_package(alert: dict, worktree_path,
                     allow_llm: bool = True,
                     timeout_sec: int = 60) -> PackageRef:
    """Resolve an Orca CVE alert to (ecosystem, package, installed version).

    Deterministic first: the ecosystem comes from the manifest filename, and the
    package name is whichever manifest entry the alert's prose mentions. Only if
    no manifest entry matches do we ask a model, and even then its answer is
    checked against the manifest before it is trusted.
    """
    # Coerced to str: these fields come from an external API, and a bad ref must
    # degrade the pipeline rather than raise inside it.
    manifest_rel = str(alert.get("file_path") or alert.get("source") or "").strip()
    ref = PackageRef(ecosystem=None, package="", current_version="",
                     manifest_path=manifest_rel,
                     cve_ids=cve_ids_from_alert(alert))

    if not manifest_rel:
        ref.error = "alert has no file_path or source to locate a manifest"
        return ref

    eco = ecosystem_for_manifest(manifest_rel)
    if eco is None:
        ref.error = f"no known ecosystem for manifest {manifest_rel!r}"
        return ref
    ref.ecosystem = eco

    manifest_abs = Path(worktree_path) / manifest_rel
    deps = read_manifest(manifest_abs)
    if not deps:
        ref.error = f"no dependencies parsed from {manifest_rel}"
        return ref

    dep = _match_from_alert(alert, deps, eco)
    resolved_by = "manifest"
    if dep is None and allow_llm:
        dep = _match_from_llm(alert, deps, eco, manifest_rel, timeout_sec)
        resolved_by = "llm+manifest"
    if dep is None:
        ref.error = (f"no dependency in {manifest_rel} matches the alert "
                     f"(parsed {len(deps)})")
        return ref

    version, exact = dep.version, dep.exact
    if not exact or not version:
        locked = _version_from_lockfile(manifest_abs, dep.name, eco)
        if locked:
            version, exact = locked, True
            resolved_by += "+lockfile"

    if not version:
        ref.error = (f"{dep.name} is declared in {manifest_rel} as "
                     f"{dep.spec!r} with no resolvable version")
        ref.package = dep.name
        return ref

    ref.package = dep.name
    ref.current_version = version
    ref.exact_pin = exact
    ref.resolved_by = resolved_by
    return ref


def _match_from_alert(alert: dict, deps: dict,
                      ecosystem: Ecosystem) -> Dependency | None:
    """Find the manifest entry the alert names.

    The title is consulted before the description, and only within one source
    does the longest match win — so "golang.org/x/net" beats a stray "net", but a
    package merely mentioned in the description can never displace the one named
    in the title. The manifest is what is being searched, never the other way
    round: a name the repository does not declare is not a match at all.
    """
    by_norm = {normalize_name(k, ecosystem): v for k, v in deps.items()}
    for tokens in _candidate_names(alert):
        matches = []
        for token in tokens:
            norm = normalize_name(token, ecosystem)
            if norm in by_norm:
                matches.append((len(norm), by_norm[norm]))
        if matches:
            matches.sort(key=lambda pair: -pair[0])
            return matches[0][1]
    return None


def _version_from_lockfile(manifest_abs: Path, name: str,
                           ecosystem: Ecosystem) -> str:
    """Resolved version for a range spec, if a lockfile sits beside the manifest."""
    for lockname in _LOCKFILES.get(manifest_abs.name.lower(), ()):
        locked = read_manifest(manifest_abs.parent / lockname)
        dep = find_dependency(locked, name, ecosystem)
        if dep and dep.version:
            return dep.version
    return ""


_LLM_PROMPT = """\
An automated security pipeline needs to know which dependency an alert is about.

## Alert
Title: {title}
Description: {description}
Recommendation: {recommendation}
CVE ids: {cve_ids}

## Dependencies declared in {manifest}
{dep_list}

Choose the ONE entry from the list above that the alert is about. You must copy
the name exactly as it appears in the list. If none of them is the subject of the
alert, say so rather than guessing.

Return ONLY this JSON as your final output (nothing after this block):
{{"package": "<exact name from the list, or empty string if none match>"}}
"""


def _match_from_llm(alert: dict, deps: dict, ecosystem: Ecosystem,
                    manifest_rel: str, timeout_sec: int) -> Dependency | None:
    """Last resort when no manifest entry matches the alert's prose.

    Constrained to picking from the manifest, and the answer is looked up in the
    manifest afterwards, so a hallucinated package name resolves to nothing
    rather than to an edit. Single-shot with tools removed, matching the other
    read-only agents.
    """
    listing = "\n".join(f"- {d.name} ({d.spec or 'no version'})"
                        for d in deps.values())
    prompt = _LLM_PROMPT.format(
        title=alert.get("title", ""),
        description=(alert.get("description") or "")[:1500],
        recommendation=(alert.get("recommendation") or "")[:1500],
        cve_ids=", ".join(cve_ids_from_alert(alert)) or "(none)",
        manifest=manifest_rel,
        dep_list=listing[:4000],
    )
    cmd = ["claude", "-p", prompt, *_SINGLE_SHOT_TOOL_FLAGS,
           "--output-format", "json", "--max-turns", str(_SINGLE_SHOT_MAX_TURNS)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout_sec)
    except subprocess.TimeoutExpired:
        print(f"[WARN] package identification timed out after {timeout_sec}s",
              flush=True)
        return None
    if result.returncode != 0:
        print("[WARN] package identification failed "
              f"(exit={result.returncode}): {_subprocess_error_detail(result)}",
              flush=True)
        return None

    try:
        envelope = json.loads(result.stdout)
        text = envelope.get("result", "") or result.stdout
    except json.JSONDecodeError:
        text = result.stdout
    data = find_last_json_with_key(text, "package")
    if not data or not data.get("package"):
        return None
    return find_dependency(deps, str(data["package"]), ecosystem)
