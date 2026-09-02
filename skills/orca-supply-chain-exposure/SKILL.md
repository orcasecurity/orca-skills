---
name: orca-supply-chain-exposure
description: Supply chain exposure check — given a list of suspect packages (e.g. an MDR advisory like the @antv/* npm campaign), find which versions are deployed across the environment, which match the vulnerable range, and which assets carry them. Use when user asks about supply chain risk, package exposure, IOC package check, malicious package, or "are we running X" (e.g., "are we exposed to the @antv attack", "any assets with left-pad", "check these npm packages", "supply chain check").
trigger: When user provides a list of packages (with or without suspected versions) and wants to know whether any are running in the environment, or references a published supply-chain campaign / IOC list / dependency advisory and asks "are we exposed".
---

# Orca Supply Chain Exposure Skill

Answers the question: **"From this list of suspect packages, which are we actually running, where, and at what version?"**

Replaces a manual sweep of inventory + SBOM queries with a single parallel check. Optimized for the moment after an MDR / vendor / news advisory lands and the team needs an exposure answer in minutes.

## Usage

```
/orca-supply-chain-exposure @antv/util @antv/g2 @antv/g6
/orca-supply-chain-exposure log4j-core 2.14.1
/orca-supply-chain-exposure xz-utils 5.6.0,5.6.1
```

Or natural language:
- "are we exposed to the @antv npm attack?"
- "check these packages: react-devtools 4.28.0, axios 0.21.0"
- "any assets with xz-utils 5.6.x?"
- "supply chain check on this IOC list"

The user may paste a bullet list, a comma-separated list, or a table. Parse it.

## Processing Logic

### Step 1: Parse the package list

Build a normalized list of `(package_name, suspected_versions[])`. If the user only gave package names with no versions, treat **any version found in the environment as a positive hit** and rely on Orca's CVE data to confirm vulnerability.

### Step 2: Run parallel exposure queries

For each package, run two queries in parallel:

**Query A: Direct inventory lookup**
```
discovery_search:
  search_phrase: "assets with package <name>"
  limit: 50
```

**Query B: CVE-driven lookup** (catches assets where Orca already flags the package as vulnerable)
```
discovery_search:
  search_phrase: "assets with vulnerable <name> package"
  limit: 50
```

**Batching rule:** Run all packages' Query A and Query B in parallel — one tool-call batch per package isn't enough, batch *across* packages. For 20 packages, that's 40 parallel `discovery_search` calls in one message.

### Step 3: Match version ranges

For each asset returned, extract the installed version from the discovery_search response and compare against the user's suspected version list:

- **Vulnerable Match**: installed version is in the suspected range.
- **Below Range**: installed version is older than the vulnerable range (not affected).
- **Above Range**: installed version is newer (patched or unrelated).
- **Unknown Version**: discovery_search didn't return a version — flag and recommend a manual SBOM check in Orca UI.

### Step 4: Enrich confirmed exposures

For assets with **Vulnerable Match** only (top 5 by environment importance), run in parallel:

```
get_asset_by_id:
  asset_id: <UUID>
```
```
get_asset_related_alerts_summary:
  asset_id: <UUID>
```
```
get_asset_crown_jewel_info:
  group_unique_id: <group_unique_id>
```

This adds prod/non-prod tag, exposure status, related CVEs Orca already raised, and crown-jewel status.

### Step 5: Build the exposure table

Output is the table the on-call team needs to paste into a ticket or status update.

## Proactive Remediation Behavior

**CRITICAL: Never leave the user with just data.** After the exposure table:

1. **Suggest the next action** — "Patch `<package>` on `<asset>` first because it's prod + internet-facing."
2. **Offer remediation format selection** — "I can generate the upgrade or removal manifest. Choose format: terraform | helm | ansible | cli | instructions | dockerfile-patch."
3. **For confirmed exposure on prod assets**, auto-suggest snoozing alerts and opening an incident ticket.

When the user picks a format:
- Generate the upgrade / pin / removal config
- Write to `supplychain-fix-<package>.<ext>`
- Include the verification command (`npm ls <package>`, `pip show <package>`, etc.)
- Suggest the next package to fix

## Output Format

### Layer 1: Exposure Table

```
═══════════════════════════════════════════════════════════════════
SUPPLY CHAIN EXPOSURE CHECK
<date> | <N> packages checked
═══════════════════════════════════════════════════════════════════

VERDICT: <one-liner — "1 confirmed exposure" / "no matches" / "3 vulnerable">

┌─────────────────────────────────────────────────────────────────┐
│  PACKAGES CHECKED       <N>                                     │
│  CONFIRMED VULNERABLE   <N>                                     │
│  BELOW RANGE            <N>                                     │
│  NOT FOUND              <N>                                     │
│  ASSETS AFFECTED        <N> (<M> prod, <K> non-prod)            │
│  CROWN JEWELS AFFECTED  <N>                                     │
└─────────────────────────────────────────────────────────────────┘

EXPOSURE TABLE:

  Package              Version in Env   Vulnerable Range   Status         Assets
  ───────────────────────────────────────────────────────────────────────────────
  <name>               <ver>            <range>            VULNERABLE     <count>
  <name>               <ver>            <range>            Below Range    <count>
  <name>               —                <range>            Not Found      0
  ...

CONFIRMED EXPOSURES (act on these now):
  [!] <package>@<version> on <asset> (<type>, <prod/non-prod>)
      Crown jewel: YES/NO | Internet-facing: YES/NO | Related alerts: <N>
      Fix: upgrade to <safe version> OR remove if unused

RECOMMENDED ACTION:
  Top priority: patch <package> on <asset> — <reason>.
  I can generate the fix right now.

  What format? terraform | helm | ansible | cli | dockerfile-patch |
  instructions | pulumi

═══════════════════════════════════════════════════════════════════
Or drill down: confirmed | unknown-version | not-found | by-asset | full
═══════════════════════════════════════════════════════════════════
```

### Layer 2: Drill-Downs

#### "confirmed" — Confirmed vulnerable assets

```
───────────────────────────────────────────────────────────────────
CONFIRMED EXPOSURES
───────────────────────────────────────────────────────────────────

  [!] <asset> (<type>) in <account>
      Package: <name>@<version>
      Vulnerable range: <range>
      Environment: <prod/staging/dev tag>
      Internet-facing: YES/NO
      Crown jewel: YES/NO
      Related Orca alerts: <N> (top: <alert title>)
      Upgrade path: <name>@<safe-version>

  [!] <asset> — ...

───────────────────────────────────────────────────────────────────
```

#### "unknown-version" — Assets where the version couldn't be determined

```
───────────────────────────────────────────────────────────────────
UNKNOWN VERSIONS — Manual SBOM Check Required
───────────────────────────────────────────────────────────────────

These assets have the package installed, but Orca's response didn't
include a parseable version. Verify in Orca UI → Asset → SBOM:

  <asset> — <package>
  <asset> — <package>
  ...

───────────────────────────────────────────────────────────────────
```

#### "not-found" — Packages not present in the environment

```
───────────────────────────────────────────────────────────────────
NOT FOUND IN ENVIRONMENT
───────────────────────────────────────────────────────────────────

The following packages were not found on any monitored asset:
  • <package> (suspected versions: <range>)
  • <package>
  ...

Caveat: a "not found" result means Orca's inventory has no match.
Verify scanner coverage with /orca-account-health if accounts may
be missing.

───────────────────────────────────────────────────────────────────
```

#### "by-asset" — Grouped by asset (useful for ticket assignment)

```
───────────────────────────────────────────────────────────────────
EXPOSURE BY ASSET
───────────────────────────────────────────────────────────────────

  <asset> (<account>)
    • <package>@<version> — VULNERABLE
    • <package>@<version> — VULNERABLE
    • <package>@<version> — Below Range

  <asset> (<account>)
    • ...

───────────────────────────────────────────────────────────────────
```

#### "full" — Everything expanded

## Edge Cases

### No packages provided
```
⚠ No packages to check. Provide a package list:

  /orca-supply-chain-exposure <name1> <name2> ...
  /orca-supply-chain-exposure <name>@<version>

Or paste a bullet list from your advisory.
```

### All packages not found
```
✅ None of the <N> packages are present in the monitored environment.

Caveats:
  • Verify Orca scanner coverage with /orca-account-health
  • Newly deployed assets may not have been scanned yet
  • Package may be installed under a different name (alias check recommended)
```

### Discovery returned > 50 hits for a single package
```
⚠ <package> is on more than 50 assets — discovery_search is capped at 50.

Showing top 50 by severity. For the full list:
  Open the app_url in the discovery_search response.
```

### User provided versions but Orca returns no version data
```
Asset returned a hit for <package> but no version data.
Manual verification needed in Orca UI → Asset → SBOM.
```

## MCP Tools Used

### Primary Tools

| Tool | Purpose | Parameter |
|------|---------|-----------|
| `discovery_search` | Find assets running a given package | `search_phrase` (NL), `limit` |
| `get_asset_by_id` | Asset prod/non-prod tag and metadata | `asset_id` (UUID) |
| `get_asset_related_alerts_summary` | Existing alerts on the affected asset | `asset_id` (UUID) |
| `get_asset_crown_jewel_info` | Crown jewel status | `group_unique_id` |

### Secondary Tools

| Tool | Purpose | When |
|------|---------|------|
| `get_alert` | Pull related CVE alert details | Drill-down into an existing Orca CVE alert for the package |
| `search_cdr_events` | Recent activity from/to the affected asset | If user asks for activity context |

### Parameter Notes

- `discovery_search` natural-language phrasing matters: both `"assets with package <name>"` and `"assets with vulnerable <name>"` should run — each surfaces different data (inventory vs CVE-tagged).
- `discovery_search` is **capped at 50 results** per call — the response includes `app_url` for the full set; surface this when truncated.
- The package-name string must match exactly what Orca indexes; common aliases (e.g. `log4j-core` vs `log4j`) may need two queries.

## Implementation Notes

1. **Parallelize across packages, not just across queries.** For a 10-package advisory, the first batch should be ~20 `discovery_search` calls in one message.
2. **Version match is the differentiator** — without version comparison this is just a "package found anywhere" check. Always show the installed version and the suspected range side by side.
3. **"Below Range" is a real status, not a non-finding** — call it out explicitly so the user sees that the check ran and the asset is verified safe.
4. **Crown jewel + internet-facing flag** turns a generic "vulnerable" hit into a priority-1 incident. Always enrich confirmed exposures with these two fields.
5. **Link to other skills**: suggest `/orca-impact-analysis` for fix consequences, `/orca-alert-triage` for any related CVE alert, `/orca-account-health` if "not found" results need a coverage sanity-check.
