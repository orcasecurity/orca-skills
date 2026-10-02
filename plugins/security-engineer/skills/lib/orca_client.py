"""
Shared Orca Security API client.
Used by orca_alerts.py, orca_get_alert.py, and run_agent.py.

Token: ORCA_API_TOKEN env var (base64 token string from Orca config)
       or ORCA_AUTH_TOKEN env var (same format)
"""
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Repository:
    """A code repository with Orca metadata and an optional local clone path.

    clone_path = None  → single-repo mode: all git ops use cwd (existing behaviour)
    clone_path = Path  → multi-repo mode: all git ops run inside the cloned directory
    """
    name: str                           # "owner/repo" (derived from URL)
    url: str                            # "https://github.com/owner/repo" (for cloning)
    clone_path: Path | None = None   # set by _clone_repo() in multi-repo mode
    orca_score: float = 0.0
    risk_level: str = ""

ORCA_API = "https://api.orcasecurity.io/api/serving-layer/query"
RISK_ORDER = ["critical", "high", "medium", "low", "informational"]

ALL_CATEGORIES = [
    "Neglected assets", "Vendor services misconfigurations",
    "Workload misconfigurations", "Best practices",
    "Data protection", "Data at risk", "IAM misconfigurations",
    "Network misconfigurations", "Logging and monitoring",
    "Authentication", "Lateral movement", "Vulnerabilities",
    "Malware", "Malicious activity", "System integrity",
    "Suspicious activity", "Source code vulnerabilities"
]


def get_token():
    """Read ORCA_API_TOKEN or ORCA_AUTH_TOKEN from environment."""
    token = os.environ.get("ORCA_API_TOKEN") or os.environ.get("ORCA_AUTH_TOKEN")
    if not token:
        sys.exit("Error: set ORCA_API_TOKEN env var (base64 token from your Orca config)")
    return token


def val(item, key, default=None):
    """Extract from item['data'][key]['value'], item[key], or default."""
    data = item.get("data", item)
    v = data.get(key, default)
    if isinstance(v, dict):
        return v.get("value", default)
    return v if v is not None else default


def _post(payload, token):
    """POST to ORCA_API. Raises RuntimeError on HTTP error."""
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        ORCA_API,
        data=data,
        headers={
            "Authorization": f"TOKEN {token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code}: {body}") from e


def _extract_file_path(source: str) -> str:
    """Extract a clean relative file path from the Orca Source field.

    Handles three formats:
    - GitHub blob URL: https://github.com/owner/repo/blob/<sha>/path/to/file.js
    - Path with line suffix: path/to/file.js:40
    - Plain path: path/to/file.js
    """
    if not source:
        return ""
    if "github.com" in source and "/blob/" in source:
        parts = source.split("/blob/")
        if len(parts) > 1:
            # Drop the sha/branch component (first segment after /blob/)
            path = "/".join(parts[1].split("/")[1:])
            return path.split("#")[0].strip("/")  # strip GitHub line anchor (#L40)
    return source.split(":")[0].strip()


def _normalize_code_snippet(raw_snippet):
    """Normalize code_snippet to a list of code lines.

    Orca returns different formats depending on alert type:
    - Secret/SAST: list of dicts [{"line": "code...", "position": 3}, ...]
    - Other:       list of strings ["code line 1", "code line 2"]
    """
    if not raw_snippet:
        return [], None, None
    lines = []
    first_line = None
    last_line = None
    for entry in raw_snippet:
        if isinstance(entry, dict):
            lines.append(entry.get("line", "").rstrip("\n"))
            pos = entry.get("position")
            if pos is not None:
                if first_line is None or pos < first_line:
                    first_line = pos
                if last_line is None or pos > last_line:
                    last_line = pos
        else:
            lines.append(str(entry))
    return lines, first_line, last_line


def _normalize_alert(item):
    """Convert a raw API item into a clean dict."""
    findings = val(item, "RiskFindings", {}) or {}
    position = findings.get("position", {}) or {}
    ai_triage = findings.get("ai_triage", {}) or {}
    source = val(item, "Source", "") or ""

    # Normalize code_snippet and extract line numbers from it
    raw_snippet = findings.get("code_snippet", [])
    snippet_lines, snippet_start, snippet_end = _normalize_code_snippet(raw_snippet)

    # Position: prefer explicit position dict, fall back to code_snippet positions
    start_line = position.get("start_line") or snippet_start
    end_line = position.get("end_line") or snippet_end

    return {
        "alert_id":       val(item, "AlertId") or item.get("name", ""),
        "title":          val(item, "AlertType", ""),
        "risk_level":     (val(item, "RiskLevel", "") or "").lower(),
        "score":          val(item, "OrcaScore"),
        "category":       val(item, "Category", ""),
        "status":         val(item, "Status", ""),
        "source":         source,
        "file_path":      _extract_file_path(source),
        "labels":         val(item, "Labels", []) or [],
        # Every advisory this alert covers. A package alert is one *package*,
        # not one CVE — Orca's django alert carries 41 ids — so this is also the
        # only complete list available: RiskFindings.cves.top_cves holds just
        # the highest-scoring one.
        "cve_ids":        val(item, "CveIds", []) or [],
        "description":    val(item, "Description", ""),
        "recommendation": val(item, "Recommendation", ""),
        "feature_type":   findings.get("feature_type", ""),
        "code_snippet":   snippet_lines,            # always list[str] now
        "position": {
            "start_line": start_line,
            "end_line":   end_line,
        },
        "ai_triage": {
            "explanation": ai_triage.get("explanation", ""),
            "verdict":     ai_triage.get("verdict", ""),
            "confidence":  ai_triage.get("confidence"),
        },
        # Rich context from RiskFindings (available for fix agents)
        "origin_url":     findings.get("origin_url", ""),
        "verification":   findings.get("active_verification_status", ""),
        "first_commit":   findings.get("first_commit", {}),
        "is_test_file":   findings.get("is_test_file", False),
        # Whatever else the two rich payloads carried. fetch_alert_by_id has
        # always requested AssetData and this function has always dropped it, so
        # nobody knows whether Orca already supplies a structured package name,
        # installed version or fixed version for a package CVE — which is exactly
        # what the CVE pipeline has to recover from the repository instead.
        # Preserved rather than parsed: guessing at key names we have never seen
        # would be speculative, and keeping them makes it a `get-alert` away.
        "asset_data":     _bounded(val(item, "AssetData", {})),
        "extra_findings": _bounded(_unknown_finding_keys(findings)),
    }


# Everything _normalize_alert already promotes to a top-level key. Anything else
# in RiskFindings is passed through under "extra_findings".
_KNOWN_FINDING_KEYS = {
    "position", "ai_triage", "code_snippet", "feature_type", "origin_url",
    "active_verification_status", "first_commit", "is_test_file",
}

# The normalized alert is pretty-printed into the fix agent's prompt, so an
# unbounded passthrough would push the actual instructions out of the way.
_PASSTHROUGH_LIMIT = 4000


def _unknown_finding_keys(findings):
    """RiskFindings entries that do not already have a home."""
    if not isinstance(findings, dict):
        return {}
    return {k: v for k, v in findings.items() if k not in _KNOWN_FINDING_KEYS}


def _bounded(value, limit=_PASSTHROUGH_LIMIT):
    """Drop a passthrough payload that cannot safely go into a prompt.

    Serialized strictly, with no `default=` fallback, because the caller that
    ultimately renders this dict — `_invoke_fix_agent` building the fix prompt —
    calls json.dumps without one. Anything that would raise there has to be
    dropped here instead, or an unexpected payload takes the whole fix down.
    """
    if not value:
        return {} if isinstance(value, dict) else value
    try:
        size = len(json.dumps(value))
    except (TypeError, ValueError):
        return {"_dropped": "not JSON-serializable"}
    if size > limit:
        return {"_dropped": f"{size} bytes exceeds the {limit}-byte prompt budget"}
    return value


_ALERT_ID_PREFIXES = ("orca-", "alert-", "alert_", "alert ", "#")


def normalize_alert_id(alert_id):
    """Coerce however a human wrote an alert ID into Orca's canonical form.

    Orca mints IDs as `orca-<digits>`, but a request arriving in plain English
    says "remediate alert-192901290", "fix #192901290", or just the number. Only
    a purely numeric remainder is re-prefixed: anything else is passed through
    untouched, so a genuinely different ID scheme still reaches the API and
    fails there with its own name in the error rather than a mangled one.

    Idempotent — canonical IDs coming back out of Orca survive a second pass.
    """
    if not alert_id:
        return alert_id
    candidate = str(alert_id).strip()
    lowered = candidate.lower()
    for prefix in _ALERT_ID_PREFIXES:
        if lowered.startswith(prefix):
            candidate = candidate[len(prefix):].strip()
            break
    return f"orca-{candidate}" if candidate.isdigit() else str(alert_id).strip()


# Advisory id schemes that appear in Orca's CveIds field. Only the scheme prefix
# is case-normalized: a CVE id's body is digits, but a GHSA id's is lowercase by
# construction (GHSA-2p49-hgcm-8545), so uppercasing the whole string would
# invent an id nobody issued.
_ADVISORY_SCHEMES = ("CVE", "GHSA", "PYSEC", "GO", "RUSTSEC", "OSV")


def normalize_cve_id(cve_id):
    """Coerce however a human wrote an advisory id into its canonical form.

    Canonical here means what the id's issuer prints: `cve-2020-7471` becomes
    `CVE-2020-7471`, `ghsa-2p49-hgcm-8545` becomes `GHSA-2p49-hgcm-8545`. The
    Orca API matches case-insensitively either way, but the value also reaches
    the plan table, the fix directive and the PR body, so it is normalized at
    the boundary for the same reason `normalize_alert_id` is.

    An id in no scheme we recognize is returned trimmed but otherwise untouched,
    so it still reaches the API under the name the user typed.

    Idempotent — a canonical id survives a second pass.
    """
    if not cve_id:
        return cve_id
    candidate = str(cve_id).strip()
    scheme, sep, rest = candidate.partition("-")
    if sep and scheme.upper() in _ADVISORY_SCHEMES:
        return f"{scheme.upper()}-{rest}"
    return candidate


def _cve_filter_clause(cve_ids):
    """The serving-layer clause matching alerts carrying any of these ids.

    CveIds is a list field, so it needs `any_match` wrapping an inner `in`
    rather than the flat `str`/`in` shape the scalar keys use — a flat clause is
    rejected with "Unknown field 'CveIds'". This is the same clause Orca's own
    Discovery UI builds for "code repository alerts for CVE-...".
    """
    values = [normalize_cve_id(c) for c in cve_ids]
    return {
        "type": "list",
        "key": "CveIds",
        "operator": "any_match",
        "values": [{"type": "str", "key": "CveIds",
                    "operator": "in", "values": values}],
    }


# Restricts a query to alerts on code repositories. Needed whenever alerts are
# selected by something other than a repo name: a bare CveIds query also returns
# cloud-workload alerts (a "Vulnerable Software" finding on a VM running the same
# vulnerable package), which this pipeline has no way to fix.
CODE_REPOSITORY_INVENTORY = {
    "keys": ["Inventories"],
    "models": ["Inventory"],
    "type": "object_set",
    "operator": "has",
    "with": {
        "type": "operation",
        "operator": "and",
        "values": [
            {"type": "str", "key": "NewCategory",
             "operator": "eq", "values": ["CI Source"]},
            {"type": "str", "key": "NewSubCategory",
             "operator": "eq", "values": ["Code Repository"]},
        ],
    },
}

# Every Alert field the two rich fetches request. One list, because a field
# added for one caller and forgotten in the other is how `cve_ids` would end up
# populated in bulk mode and empty for --alert.
_ALERT_SELECT = [
    "AlertId", "AlertType", "OrcaScore", "RiskLevel", "Category",
    "Source", "Status", "Description", "Recommendation",
    "RiskFindings", "Labels", "AssetData", "CveIds",
]


def fetch_alert_by_id(alert_id, token):
    """Fetch a single alert by ID. Returns normalized dict or None."""
    alert_id = normalize_alert_id(alert_id)
    payload = {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "key": "AlertId",
                "values": [alert_id],
                "type": "str",
                "operator": "in"
            }
        },
        "limit": 1,
        "select": _ALERT_SELECT,
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2
    }
    result = _post(payload, token)
    items = result.get("data", [])
    if not items:
        return None
    return _normalize_alert(items[0])


def alerts_payload(repo, statuses=None, cve_ids=None, limit=100):
    """The serving-layer request `fetch_alerts` sends.

    Split out from the fetch so the query can be asserted in a unit test without
    a token or a network call — the CVE clause in particular is a shape the API
    rejects outright when it is wrong, which is a poor thing to discover live.
    """
    clauses = [
        {
            "key": "Category",
            "values": ALL_CATEGORIES,
            "type": "str",
            "operator": "in"
        },
        {
            "key": "Status",
            "values": statuses or ["open", "in_progress"],
            "type": "str",
            "operator": "in"
        },
    ]
    if repo:
        clauses.append({
            "keys": ["Inventories"],
            "models": ["Inventory"],
            "type": "object_set",
            "operator": "has",
            "with": {
                "key": "Name",
                "values": [repo],
                "type": "str",
                "operator": "in"
            }
        })
    else:
        # No repo to scope by, so scope by asset kind instead — see
        # CODE_REPOSITORY_INVENTORY.
        clauses.append(CODE_REPOSITORY_INVENTORY)
    if cve_ids:
        clauses.append(_cve_filter_clause(cve_ids))

    return {
        "query": {
            "models": ["Alert"],
            "type": "object_set",
            "with": {
                "operator": "and",
                "type": "operation",
                "values": clauses
            }
        },
        "limit": limit,
        "start_at_index": 0,
        "order_by[]": ["-OrcaScore"],
        "select": _ALERT_SELECT,
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2
    }


def fetch_alerts(repo, token, min_level=None, feature_types=None, statuses=None,
                 cve_ids=None):
    """
    Fetch open alerts for a repo.

    repo          - "owner/repo" string
    min_level     - minimum risk level (inclusive); None means all
    feature_types - list of feature_type strings to include; None means all
    statuses      - list of statuses; defaults to ["open", "in_progress"]
    cve_ids       - advisory ids; an alert matches if it carries any of them.
                    Filtered server-side, so --max still caps real matches.
    """
    payload = alerts_payload(repo, statuses=statuses, cve_ids=cve_ids)

    result = _post(payload, token)
    items = result.get("data", [])
    alerts = [_normalize_alert(item) for item in items]

    # Filter by min_level
    if min_level and min_level in RISK_ORDER:
        cutoff = RISK_ORDER.index(min_level)
        alerts = [a for a in alerts if a["risk_level"] in RISK_ORDER and RISK_ORDER.index(a["risk_level"]) <= cutoff]

    # Filter by feature_types
    if feature_types:
        ft_set = {ft.lower() for ft in feature_types}
        alerts = [a for a in alerts if _resolve_feature_type(a) in ft_set]

    return alerts


def list_repositories(token: str) -> list:
    """Fetch all code repositories that have open/in-progress alerts in Orca.

    Returns a list of Repository objects ordered by OrcaScore descending.
    """
    payload = {
        "query": {
            "models": ["CodeRepository"],
            "type": "object_set",
            "with": {
                "keys": ["Alerts"],
                "models": ["Alert"],
                "type": "object_set",
                "operator": "has",
                "with": {
                    "key": "Status",
                    "values": ["open", "in_progress"],
                    "type": "str",
                    "operator": "in"
                }
            }
        },
        "limit": 100,
        "start_at_index": 0,
        "order_by[]": ["-OrcaScore"],
        "select": [
            "CiSource", "Name", "OrcaScore", "RiskLevel", "group_unique_id",
            "Exposure", "State", "Observations", "Tags",
            "ShiftleftProject.Name", "CodeLanguages", "Url"
        ],
        "get_results_and_count": False,
        "full_graph_fetch": {"enabled": True},
        "debug_enable_bu_tags": True,
        "max_tier": 2,
    }
    result = _post(payload, token)
    repos = []
    seen_urls: set = set()
    for item in result.get("data", []):
        url = (val(item, "Url", "") or "").strip()
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        # Derive owner/repo from the clone URL
        name = None
        for sep in ("github.com/", "github.com:"):
            if sep in url:
                name = url.split(sep)[-1].removesuffix(".git").strip("/")
                break
        if not name:
            # Fall back to the Orca Name field
            name = (val(item, "Name", "") or url)
        repos.append(Repository(
            name=name,
            url=url,
            orca_score=float(val(item, "OrcaScore") or 0),
            risk_level=(val(item, "RiskLevel", "") or "").lower(),
        ))
    return repos


def repos_with_cve(cve_ids, token, statuses=None):
    """Which code repositories have an open alert carrying these advisory ids.

    One query, no cloning, no per-repo iteration — the CveIds filter is
    server-side and the repo name comes back on each alert. Answers "where is
    this CVE open?", which is the first question anyone asks and should not
    require a fix run.

    Returns [(repo_name, alert_count)] ordered by count descending.
    """
    payload = alerts_payload(None, statuses=statuses, cve_ids=cve_ids)
    result = _post(payload, token)
    counts: dict = {}
    for item in result.get("data", []):
        asset = val(item, "AssetData", {}) or {}
        name = (asset.get("asset_name") or "").strip()
        if name:
            counts[name] = counts.get(name, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _resolve_feature_type(alert):
    """Normalize feature_type.
    Package CVEs have empty feature_type but category 'Vulnerabilities'.
    SAST CVEs have feature_type 'sast' and a CVE-* label.
    """
    ft = (alert.get("feature_type") or "").lower()
    category = (alert.get("category") or "").lower()
    labels = alert.get("labels") or []
    has_cve_label = any(re.match(r"CVE-\d{4}-\d+", str(label)) for label in labels)

    # Package vulnerabilities: category "Vulnerabilities" with no feature_type
    if "vulnerabilit" in category and not ft:
        return "cve"
    # SAST alerts with explicit CVE labels
    if has_cve_label and ft == "sast":
        return "cve"
    return ft or "unknown"


def is_fixable(alert):
    """True for sast/iac/secret/cve. False for scm_posture and unknown."""
    return _resolve_feature_type(alert) in {"sast", "iac", "secret", "cve"}


def alert_branch_name(alert_id):
    return f"fix/orca-{alert_id.replace('/', '-')}"


def branch_exists_remote(branch_name, cwd=None):
    """Check if branch exists on remote origin.

    cwd: working directory for the git command (None = inherit from caller).
         Pass repo.clone_path in multi-repo mode.
    """
    try:
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "origin", branch_name],
            capture_output=True, text=True, timeout=10, cwd=cwd
        )
        return bool(result.stdout.strip())
    except Exception:
        return False
