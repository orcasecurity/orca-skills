---
name: orca-impact-analysis
description: Analyzes the full impact of fixing an Orca alert — what closes, what breaks, and what the environment looks like after the fix. Use when user asks about impact, consequences, or blast radius of fixing an alert (e.g., "what's the impact of fixing orca-3380725", "if I fix this what breaks", "what else closes").
trigger: When user asks about impact of fixing an alert, what else closes, what breaks, remediation impact, fix simulation, blast radius of fix, or "what if I fix" (e.g., "impact orca-3380725", "what does fixing orca-3511464 close?", "if I fix this what breaks?")
---

# Orca Impact Analysis Skill

Answers two questions:
1. **"If I fix this, what else closes?"** — alerts, attack paths, compliance controls resolved
2. **"If I fix this, what might break?"** — production workflows, automation, and services that depend on the current (insecure) state

Given a single Orca alert, this skill analyzes BOTH sides of remediation impact — the security improvements AND the operational risk of applying the fix.

## Usage

```
/orca-impact-analysis <alert-id>
/orca-impact-analysis orca-3380725
```

Or natural language:
- "what's the impact of fixing orca-3380725?"
- "if I fix orca-3511464, what else closes?"
- "impact analysis for orca-3213766"
- "what does remediation of orca-3380725 resolve?"

## What This Skill Does

1. **Fetches the alert** and identifies the root cause and fix action
2. **Queries same-asset alerts** to find co-located findings that share the same root cause
3. **Queries attack paths** to find kill chains that break when this alert is fixed
4. **Queries similar alert type** across the environment to find the same issue on other assets
5. **Checks compliance impact** to find frameworks/controls that would pass after the fix
6. **Simulates breakage risk** using CloudTrail/CDR events, effective permissions, and usage patterns to identify production workflows that depend on the current state
7. **Synthesizes a full impact report** with security gains AND operational risks

## Processing Logic

### Step 1: Understand the Fix

Fetch the alert with `get_alert` and determine:
- **What is the root cause?** (e.g., missing MFA, exposed service, overprivileged role)
- **What is the fix action?** (e.g., enable MFA, add authentication, remove role assignment)
- **What asset is affected?** (asset type, ID, account, cloud provider)

Categorize the fix type:
```
Fix Type              Examples                          Cascade Pattern
─────────────────────────────────────────────────────────────────────
Configuration fix     Enable MFA, restrict access        Closes same-asset alerts that depend on this config
Permission fix        Remove role, tighten policy        Breaks attack paths, closes privilege escalation chains
Exposure fix          Add auth, block port, restrict IP  Closes exposure alerts, breaks external attack paths
Patch/update          Apply CVE patch, upgrade version   Closes all CVE alerts for that package version
Removal               Delete unused resource             Closes ALL alerts on that asset
```

### Step 2: Same-Asset Impact

Use `get_asset_related_alerts_summary` (with the asset UUID from the alert's `Inventory.id`) to find all alerts on the same asset.

For each related alert, determine if fixing the original alert would also resolve it:

**Direct resolution** — the related alert shares the same root cause:
- Original: "Root account without MFA" → Also resolves: "API access from root account" (MFA would add protection)
- Original: "Exposed Kibana" → Also resolves: "Sensitive data exposure on web tool" (same fix: add auth)

**Indirect improvement** — the fix reduces risk but doesn't fully close the related alert:
- Original: "Root without MFA" → Improves: "Root access keys exist" (MFA helps but keys still exist)

**No impact** — unrelated finding on the same asset:
- Original: "Missing MFA" → No impact on: "Outdated OS version" (different root cause)

Classification logic:
```
IF related_alert.alert_type == original_alert.alert_type THEN
  "Direct close" — same finding, duplicate
ELSE IF related_alert.remediation overlaps original_alert.remediation THEN
  "Direct close" — same fix resolves both
ELSE IF related_alert.risk_findings references same config/permission/exposure THEN
  "Risk reduction" — fix reduces exploitability or impact
ELSE IF related_alert is in attack path that includes original alert THEN
  "Attack path broken" — fix breaks the chain
ELSE
  "No impact" — independent finding
```

### Step 3: Attack Path Impact

Use `get_alert_attack_path_data` (with the alert_id) to find attack paths that include this alert.

For each attack path:
- Is this alert a **critical node** (removing it breaks the path)?
- Or is it a **contributing factor** (removing it weakens but doesn't break the path)?
- What is the attack path's risk score and story?

Also use `get_asset_related_attack_paths_summary` for the asset to get the full picture.

### Step 4: Environment-Wide Impact

Use `get_alerts_with_similar_alert_type` (with the alert_id and alert_type) to find the same issue across other assets.

This answers: "If I fix this pattern everywhere (not just this one asset), how many alerts close?"

Group results by:
- Account/subscription
- Asset type
- Risk level

### Step 5: Compliance Impact

From the original alert's `RelatedCompliances` and `RuleId`:
- Use `get_control_test_alerts` with the `RuleId` to find all alerts triggered by the same compliance control
- This shows how many compliance violations would be resolved

#### Compliance Score Calculation

Use these tools to get **actual compliance scores** before and after the fix:

1. **`get_enabled_compliance_frameworks`** — returns all enabled frameworks with their current `avg_score_percent` and `test_results` (PASS/FAIL counts). This gives the org-wide baseline.

2. **`get_compliance_framework_stats_for_asset`** — returns per-asset compliance stats for a specific framework. Parameters: `framework_id` (e.g., `"pci_dss_v4.0.1"`) and `group_unique_id` (from the alert's `GroupUniqueId`). Returns:
   - `score.test_results.PASS` / `FAIL` counts for this asset
   - `score.avg_score_percent` — current score for this asset in this framework
   - `alerts.total_count` — number of alerts from this asset in this framework

3. **Calculate the delta**: For each framework where this asset has FAIL > 0:
   ```
   current_score = avg_score_percent
   total = PASS + FAIL
   after_fix_score = round(((PASS + 1) / total) * 100)
   delta = after_fix_score - current_score
   ```

4. **Present the score change table** — ALWAYS show this when data is available:
   ```
   Framework              Current    After Fix    Change
   ─────────────────────────────────────────────────────
   PCI DSS 4.0.1          99%   →   100%         +1%
   DSPM Best Practices    98%   →   100%         +2%
   SOC 2                  94%   →    95%         +1%
   ```

**Execution**: In Phase 2, call `get_enabled_compliance_frameworks` to get framework IDs. Then for the top 5-8 most relevant frameworks (from the alert's `RelatedCompliances` that overlap with enabled frameworks), call `get_compliance_framework_stats_for_asset` in parallel.

If the compliance tools return no data, fall back to qualitative:
- Count the number of distinct frameworks affected (from `RelatedCompliances`)
- Count the environment-wide alerts for this rule (from `get_control_test_alerts`)
- Show: "Fixing this resolves violations in X frameworks, closing Y alerts across Z accounts"

Always show the **number of frameworks affected** and the **number of alerts that would close** for the same rule across the environment — these are always available from the alert data.

### Step 6: Breakage Risk Simulation

**This is the critical differentiator.** Before the user applies a fix, show them what production workflows, automation, or services might break.

#### Data Sources for Breakage Analysis

Use these MCP tools to understand what actively depends on the current (insecure) state:

1. **`search_cdr_events`** — Search CloudTrail/audit log events filtered by the affected identity or resource. This shows what the asset is actively DOING in production.
   - For IAM changes: filter by `actors` (the identity being modified)
   - For network/exposure changes: filter by `targets` (the resource being locked down)
   - For permission changes: filter by `services` to see which AWS/Azure/GCP services are in use

2. **`get_cdr_events_grouped_by_event_name`** — Aggregate events by action name. This reveals usage patterns:
   - High-frequency actions = likely automation or production workflows
   - Low-frequency actions = likely human/manual operations
   - Unusual hours = likely CI/CD or cron jobs

3. **`get_aws_effective_permissions_policy_on_asset`** — For IAM assets, compare current permissions vs. recommended least-privilege policy. The DELTA between current and recommended is exactly what would be removed — and any of those permissions actively used in CloudTrail are what would break.

4. **Linked CloudTrail events** — From `get_asset_related_alerts_summary`, related alerts often embed CloudTrail events with user-agents, source IPs, and action details that reveal who/what is using the asset.

5. **`get_linked_entities_data`** — Get detailed linked entities (e.g., roles assumed by this identity, instances accessed, buckets touched).

#### Breakage Classification by Fix Type

```
Fix Type               What Breaks                          How to Detect
──────────────────────────────────────────────────────────────────────────────
Enable MFA             Automated processes using the         CDR events with service user-agents
                       identity (can't respond to MFA        (boto3, aws-cli, terraform, sdk),
                       prompt). API key access is NOT        API key usage in CloudTrail
                       affected by MFA.

Remove role/permission Anything relying on the removed       Compare effective permissions vs.
                       permissions. Services, Lambda         CDR events — any action in CDR that
                       functions, CI/CD pipelines.           uses a removed permission will fail.

Block port / add auth  Clients connecting without auth.      CDR network events, access logs,
                       Health checks, monitoring agents,     linked entities showing connections.
                       partner integrations.

Patch / upgrade        API breaking changes, dependency      Check release notes for breaking
                       incompatibilities, config format      changes. Look at linked services
                       changes.                              and their version requirements.

Delete resource        Everything that references this       Linked entities count, CloudTrail
                       resource. DNS, load balancers,        events targeting this resource,
                       application configs.                  dependent services.
```

#### Simulation Logic

For each fix type, run the appropriate analysis:

**For MFA enablement (identity alerts):**
```
1. Query CDR events for the identity over last 30 days
2. Group by user-agent:
   - "boto3", "aws-sdk", "terraform", "jenkins", "github-actions" → AUTOMATION (will break)
   - "console.amazonaws.com", "Mozilla", "Chrome" → HUMAN (will get MFA prompt)
   - "kali", unknown agents → SUSPICIOUS (should break — that's the point)
3. Group by source IP:
   - Known CIDR ranges → internal/VPN (expected)
   - Unknown IPs → external (investigate)
4. Group by time pattern:
   - Regular intervals (hourly, daily) → CRON/AUTOMATION
   - Business hours only → HUMAN
   - 24/7 consistent → SERVICE
5. For each automation pattern found:
   - Identify the service/workflow
   - Assess if it uses access keys (NOT affected by MFA) or console (affected)
   - Flag as "WILL BREAK" or "NOT AFFECTED"
```

**For permission removal (IAM alerts):**
```
1. Get effective permissions policy (current vs recommended)
2. Compute the delta: permissions that would be REMOVED
3. Query CDR events for the identity
4. For each event action, check if it falls within the removed permissions
5. If action is in removed permissions AND has been used recently → "WILL BREAK"
6. If action is in removed permissions but NOT used → "SAFE TO REMOVE"
7. Present the breakdown: which specific permissions are actively used
```

**For exposure fixes (network/auth alerts):**
```
1. Query CDR events targeting the resource
2. Identify all clients/IPs that connect
3. Classify: internal monitoring, health checks, user traffic, API consumers
4. For each client type:
   - Can it authenticate after the fix? → "NEEDS UPDATE"
   - Is it a health check that expects 200? → "WILL FAIL"
   - Is it legitimate user traffic? → "WILL GET AUTH PROMPT"
```

#### Breakage Risk Output Format

Present findings in a dedicated section:

```
───────────────────────────────────────────────────────────────────
BREAKAGE RISK — What might stop working
───────────────────────────────────────────────────────────────────

RISK LEVEL: <LOW / MEDIUM / HIGH / CRITICAL>

ACTIVE USAGE DETECTED (last 30 days):
  Total events: X
  Unique actions: Y
  Unique user-agents: Z

AUTOMATION / SERVICES THAT MAY BREAK:
  [!] <service/workflow> — <why it breaks>
      Evidence: <X events>, user-agent: <agent>, pattern: <hourly/daily>
      Mitigation: <how to update the service to work with the fix>

  [!] <service/workflow> — <why it breaks>
      ...

HUMAN WORKFLOWS AFFECTED:
  [~] <workflow> — <what changes for humans>
      Impact: <MFA prompt / new auth flow / permission denied>
      Mitigation: <communicate change, update runbooks>

NOT AFFECTED:
  [ok] <service> — <why it's safe>
      Reason: <uses access keys (MFA doesn't apply) / doesn't use removed permissions>

SUSPICIOUS ACTIVITY (SHOULD break — that's the goal):
  [x] <activity> — <why this is the threat we're fixing>
      This is the malicious/risky activity. Breaking it is the POINT.

SAFE DEPLOYMENT CHECKLIST:
  [ ] Notify <teams/owners> before applying fix
  [ ] Update <automation/service> to handle new auth flow
  [ ] Schedule change window: <recommended timing>
  [ ] Prepare rollback: <how to revert if critical service fails>
  [ ] Monitor after deployment: <what to watch for>
```

#### Breakage Risk Level Calculation

```
IF automation_events > 100 AND fix_affects_api_access THEN
  "CRITICAL" — high-volume automation will break
ELSE IF automation_events > 0 AND fix_affects_api_access THEN
  "HIGH" — some automation may break
ELSE IF human_events > 0 AND fix_changes_auth_flow THEN
  "MEDIUM" — humans will need to adapt (MFA, new login)
ELSE IF only_suspicious_events THEN
  "LOW" — only malicious activity breaks (ideal outcome)
ELSE IF no_events_found THEN
  "LOW" — no active usage detected, safe to apply
```

### Step 7: Synthesize the Report

Compile all findings into a single report. The report MUST start with the executive verdict and end with a clear fix/don't-fix recommendation.

## Output Format

```
═══════════════════════════════════════════════════════════════════
IMPACT ANALYSIS — <alert-id>
<Alert Title from alert data>
"If I <fix action>, what closes — and what breaks?"
═══════════════════════════════════════════════════════════════════

FIX ACTION: <what needs to be done>
ASSET: <asset name> (<asset type>) in <account>

┌─────────────────────────────────────────────────────────────────┐
│  VERDICT: <FIX NOW / FIX WITH CAUTION / PLAN FIX / DEFER>      │
│                                                                 │
│  Security gain:   <HIGH / MEDIUM / LOW>                         │
│  Breakage risk:   <LOW / MEDIUM / HIGH / CRITICAL>              │
│  Blast radius:    <X alerts, Y attack paths, Z frameworks>      │
│  Confidence:      <X%> — <basis for confidence>                 │
│                                                                 │
│  <1-2 sentence executive summary — why fix or why defer>        │
└─────────────────────────────────────────────────────────────────┘

───────────────────────────────────────────────────────────────────
REMEDIATION IMPACT SUMMARY
───────────────────────────────────────────────────────────────────

  Alerts directly closed:    X (including this one)
  Risk reduction:            X additional alerts improved
  Attack paths broken:       X
  Compliance frameworks:     X frameworks improved
  Same issue elsewhere:      X alerts across Y accounts

  Total risk reduction:      X critical, Y high, Z medium alerts
  Breakage risk:             LOW / MEDIUM / HIGH / CRITICAL

───────────────────────────────────────────────────────────────────
ALERTS THAT CLOSE WITH THIS FIX
───────────────────────────────────────────────────────────────────

  DIRECT CLOSE (same root cause):
    [x] <alert-id> — <title> (score: X.X)
    [x] <alert-id> — <title> (score: X.X)
    ... reason: <why this closes>

  RISK REDUCTION (partial improvement):
    [~] <alert-id> — <title> (score: X.X)
    ... reason: <what improves and what remains>

───────────────────────────────────────────────────────────────────
ATTACK PATHS BROKEN
───────────────────────────────────────────────────────────────────

  [x] Attack Path #1 (score: X.X)
      Story: <attack path narrative>
      Role of this alert: <critical node / contributing factor>

  [x] Attack Path #2 (score: X.X)
      ...

───────────────────────────────────────────────────────────────────
COMPLIANCE IMPACT
───────────────────────────────────────────────────────────────────

  Frameworks affected: X (list top 5-8 by name)
  Rule: <rule-id> — <X alerts> across <Y accounts> would close

  COMPLIANCE SCORE CHANGE (if data available):
    Framework              Current    After Fix    Change
    ─────────────────────────────────────────────────────
    PCI DSS 4.0.1          87%   →    89%         +2%
    NIST 800-53            91%   →    93%         +2%
    SOC 2                  94%   →    95%         +1%

  (If exact scores unavailable, show qualitative impact:)
  Resolves violations in X frameworks across Y environment-wide alerts.

───────────────────────────────────────────────────────────────────
SAME ISSUE ACROSS ENVIRONMENT
───────────────────────────────────────────────────────────────────

  <alert-type> found on X other assets:
    • <account-1>: Y assets (Z critical)
    • <account-2>: Y assets (Z critical)

  If fixed everywhere: X total alerts closed

───────────────────────────────────────────────────────────────────
BREAKAGE RISK — What might stop working
───────────────────────────────────────────────────────────────────

RISK LEVEL: <LOW / MEDIUM / HIGH / CRITICAL>

ACTIVE USAGE (last 30 days):
  Total events: X | Unique actions: Y | User-agents: Z

AUTOMATION THAT MAY BREAK:
  [!] <service> — <why> (X events, user-agent: <agent>, pattern: <freq>)
      Mitigation: <how to fix>

HUMAN WORKFLOWS AFFECTED:
  [~] <workflow> — <impact> | Mitigation: <action>

SUSPICIOUS ACTIVITY (SHOULD break):
  [x] <activity> — this is what we're fixing

SAFE DEPLOYMENT CHECKLIST:
  [ ] Notify affected teams
  [ ] Update automation to handle new auth
  [ ] Schedule change window
  [ ] Prepare rollback procedure
  [ ] Monitor post-deployment

═══════════════════════════════════════════════════════════════════
BOTTOM LINE
═══════════════════════════════════════════════════════════════════

  <VERDICT repeated>: <FIX NOW / FIX WITH CAUTION / PLAN FIX / DEFER>

  Security gain:  <summary of what closes and what improves>
  Breakage risk:  <summary of what could break>
  Net assessment: <clear 1-2 sentence recommendation>

  <If FIX NOW>:    This is a high-leverage, low-risk fix. Apply immediately.
  <If CAUTION>:    High security value but some production risk. Follow the
                   safe deployment checklist above.
  <If PLAN FIX>:   Worth fixing but needs coordination. Schedule with the
                   affected teams.
  <If DEFER>:      Low security gain or high breakage risk. Other fixes
                   have better ROI. Revisit in <timeframe>.

═══════════════════════════════════════════════════════════════════
```

## MCP Tools Used

### Primary Tools (always called)

| Tool | Purpose | Parameter |
|------|---------|-----------|
| `get_alert` | Understand the alert and fix action | `alert_id` |
| `get_asset_related_alerts_summary` | All alerts on same asset | `asset_id` (UUID from Inventory.id) |
| `get_alert_attack_path_data` | Attack paths through this alert | `alert_id` |
| `get_alerts_with_similar_alert_type` | Same issue across environment | `alert_id`, `alert_type` |

### Breakage Simulation Tools (called in Phase 2)

| Tool | Purpose | Parameter |
|------|---------|-----------|
| `search_cdr_events` | CloudTrail/audit events for the identity or resource | See CDR parameter reference below |
| `get_cdr_events_grouped_by_event_name` | Aggregate usage patterns by action | See CDR parameter reference below |
| `get_aws_effective_permissions_policy_on_asset` | Current vs. recommended permissions | `asset_arn` (ARN string) |

### Secondary Tools (called when relevant data exists)

| Tool | Purpose | Parameter |
|------|---------|-----------|
| `get_asset_related_attack_paths_summary` | All attack paths on the asset | `asset_id` (UUID) |
| `get_control_test_alerts` | Compliance control violations | `rule_id` (from alert's RuleId) |
| `get_linked_entities_mapping` | Connected entities count | `asset_id`, `model_name` |
| `get_linked_entities_data` | Detailed linked entity data | `asset_id`, `linked_entity` (object) |
| `get_asset_crown_jewel_info` | Crown jewel status | `group_unique_id` |
| `discovery_search` | Flexible search for related patterns | `search_phrase` |
| `get_enabled_compliance_frameworks` | All enabled frameworks with current scores | (no params) |
| `get_compliance_framework_stats_for_asset` | Per-asset compliance stats for a framework | `framework_id` (e.g., `"pci_dss_v4.0.1"`), `group_unique_id` |

### CDR Tool Parameter Reference (Verified)

Both `search_cdr_events` and `get_cdr_events_grouped_by_event_name` share these parameters:

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `time_range` | enum string | Yes | `"last_1_hour"`, `"last_24_hours"`, `"last_3_days"`, `"last_7_days"`, `"last_30_days"` |
| `actors` | string array | No | Filter by actor ARNs (e.g., `["arn:aws:iam::123:root"]`) |
| `targets` | string array | No | Filter by target resources (e.g., `["arn:aws:s3:::bucket"]`) |
| `services` | string array | No | Filter by service (e.g., `["iam.amazonaws.com"]`) |
| `accounts` | string array | No | Filter by cloud account IDs (e.g., `["506464807365"]`) |
| `actions` | string array | No | Filter by event name (e.g., `["CreateUser", "ConsoleLogin"]`) |
| `source_ip_addresses` | string array | No | Filter by source IPs |
| `countries` | string array | No | Filter by country names |
| `log_types` | string array | No | Filter by log type (`["CloudTrail", "AzureActivityLog", "GCPAuditLog"]`) |
| `cloud_providers` | string array | No | Filter by cloud provider (`["aws", "azure", "gcp"]`) |
| `end_time` | ISO 8601 string | No | End of time window (time_range counts backwards from this) |
| `limit` | integer (1-100) | No | Max events to return (default: 20, `search_cdr_events` only) |

**CDR event response structure** (each event):
```json
{
  "eventid": "...",
  "eventname": "PutObject",
  "eventtimestamp": "2026-04-17T11:39:53",
  "eventtype": "AwsApiCall",
  "account": "506464807365",
  "actor": "s3.amazonaws.com",
  "target": "arn:aws:s3:::mybucket",
  "sourceipaddress": "10.0.0.1",
  "cloud_provider": "aws",
  "service": "s3.amazonaws.com",
  "log_type": "CloudTrail",
  "action_type": "put",
  "country_short": "US",
  "assumed_role_user": "n/a"
}
```

**Grouped response structure** (each group):
```json
{ "eventname": "PutObject", "cou": 4762000 }
```

**Known CDR gotchas:**
- `time_range` does NOT accept freeform strings like `"30d"` — must use the exact enum values
- All filter arrays must be arrays, not strings (e.g., `["root"]` not `"root"`)
- The `actors` filter matches the `actor` field in events — for root accounts this is the full ARN
- If `actors` returns 0 results, try `accounts` filter instead (some events don't have actor-level granularity)
- CloudTrail events embedded in related alerts (from `get_asset_related_alerts_summary`) are often richer than CDR module events — check both sources
- Grouped results return approximate counts (rounded to thousands for large numbers)

### General Parameter Notes

- `asset_id` for asset tools requires **UUID format** (e.g., `c46cb523-3c5d-...`), found in the alert's `Inventory.id` field
- `asset_unique_id` format (e.g., `AwsUser_506464807365_...`) does NOT work with most asset tools
- `group_unique_id` for crown jewel check uses the `GroupUniqueId` field from alert data
- `get_alerts_with_similar_alert_type` requires both `alert_id` and `alert_type` as the alert type string

### MCP Connection

If Orca MCP servers from `.mcp.json` are not loaded in the session, fall back to direct HTTP calls:
- Endpoint: `https://api.orcasecurity.io/mcp`
- Protocol: SSE (`Accept: application/json, text/event-stream`)
- Auth: from `.mcp.json` headers
- Parse the `data:` line from the SSE response

## Execution Flow

Call tools in parallel where possible to minimize latency:

```
Phase 1 (parallel):
  get_alert(alert_id)

Phase 2 (parallel, after Phase 1 — need asset UUID, alert_type, ARN):
  # Security improvement queries
  get_asset_related_alerts_summary(asset_uuid)
  get_alert_attack_path_data(alert_id)
  get_alerts_with_similar_alert_type(alert_id, alert_type)
  get_asset_related_attack_paths_summary(asset_uuid)
  get_control_test_alerts(rule_id)            — if RuleId exists
  get_asset_crown_jewel_info(group_unique_id) — if GroupUniqueId exists

  # Breakage simulation queries (use correct enum values for time_range!)
  search_cdr_events(actors=[asset_arn], accounts=[account_id], time_range="last_30_days", limit=100)
  get_cdr_events_grouped_by_event_name(actors=[asset_arn], accounts=[account_id], time_range="last_30_days")
  search_cdr_events(services=["iam.amazonaws.com"], accounts=[account_id], time_range="last_30_days", limit=50)  — for IAM assets
  get_aws_effective_permissions_policy_on_asset(asset_arn)  — if AWS IAM asset
  get_linked_entities_mapping(asset_id, model_name)

  # NOTE: If actors filter returns 0 results, fall back to accounts filter.
  # Some identities (especially root) may not appear as actors in CDR.
  # Also check CloudTrail events embedded in related alerts from Phase 2.

Phase 3 (synthesis):
  Classify each related alert (direct close / risk reduction / no impact)
  Count attack paths broken
  Summarize compliance impact
  Analyze CDR events for automation vs human vs suspicious patterns
  Compare effective permissions delta with actual usage
  Calculate breakage risk level
  Generate priority recommendation (balancing security gain vs breakage risk)
```

## Classification Heuristics

### Same Root Cause Detection

Two alerts share the same root cause if ANY of these match:
1. **Same RuleType** — identical detection rule
2. **Same remediation action** — the RemediationConsole steps are the same or overlap
3. **Same risk finding config** — e.g., both reference the same IAM policy, same port, same missing config
4. **Parent-child relationship** — one alert is a consequence of the other (e.g., "no MFA" enables "unauthorized API access")

### Attack Path Criticality

An alert is a **critical node** in an attack path if:
- It's the entry point (first step)
- It's the privilege escalation step
- Removing it disconnects the path (no alternative route)

An alert is a **contributing factor** if:
- It increases the attack path score but the path still exists without it
- It provides an alternative route (redundant path)

### Verdict Logic

The verdict is the single most important output — it tells the user what to do. Calculate it from the intersection of security gain and breakage risk.

#### Security Gain Score (0-10)

```
Start: 0
+ Alert severity (critical=3, high=2, medium=1, low=0.5)
+ Alerts directly closed beyond this one (+1 per alert, max +3)
+ Attack paths broken (+1.5 per path, max +3)
+ Compliance frameworks affected (1-5 → +0.5, 6-20 → +1, 21+ → +2)
+ Environment-wide alerts for same rule (1-5 → +0.5, 6+ → +1)
+ Crown jewel asset (+1)
Cap at: 10
```

#### Breakage Risk Score (0-10)

```
Start: 0
+ Automation events that would break (+3 if >100, +2 if >10, +1 if >0)
+ Human workflows disrupted (+1 per distinct workflow, max +3)
+ Fix affects API/programmatic access (+2)
+ Fix requires coordinated change across teams (+2)
+ No rollback path available (+2)
- Only suspicious activity breaks (-2, ideal outcome)
- No active usage detected (-1)
Floor at: 0, Cap at: 10
```

#### Verdict Matrix

```
                    Breakage Risk
                    LOW (0-3)       MEDIUM (4-6)     HIGH (7-10)
Security   HIGH    FIX NOW         FIX WITH          FIX WITH
Gain       (7-10)                  CAUTION           CAUTION
           MED     FIX NOW         PLAN FIX          PLAN FIX
           (4-6)
           LOW     FIX NOW         DEFER             DEFER
           (0-3)   (easy win)
```

**Verdict descriptions:**
- **FIX NOW**: High security gain and/or low breakage risk. Apply immediately. No coordination needed.
- **FIX WITH CAUTION**: High security value but some production risk. Follow the safe deployment checklist. Worth doing but needs care.
- **PLAN FIX**: Worth fixing but needs coordination with affected teams. Schedule a change window.
- **DEFER**: Low security gain relative to breakage risk. Other fixes have better ROI. Revisit later.

**Confidence level** (shown in verdict box):
```
90-100%: All data sources returned results, clear classification
70-89%:  Most data available, minor ambiguity in breakage assessment
50-69%:  CDR data sparse or effective permissions unavailable
30-49%:  Limited data, verdict is best-effort
```

#### Priority Recommendation (in BOTTOM LINE section)

```
IF verdict == "FIX NOW" AND security_gain >= 7 THEN
  "HIGH-LEVERAGE FIX — this is the type of fix security teams dream about"
ELSE IF verdict == "FIX NOW" AND security_gain < 4 THEN
  "EASY WIN — low effort, low risk, just do it"
ELSE IF verdict == "FIX WITH CAUTION" THEN
  "WORTH IT — follow the deployment checklist and monitor after"
ELSE IF verdict == "PLAN FIX" AND same_issue_count >= 10 THEN
  "SYSTEMIC ISSUE — fix the pattern, not just this instance"
ELSE IF verdict == "DEFER" THEN
  "DEPRIORITIZE — better ROI elsewhere. Revisit in <timeframe>"

IF crown_jewel THEN
  Append: "Crown jewel asset — elevate priority regardless of cascade count"
```

## Best Practices

### DO:
- Call all MCP queries in parallel (Phase 2) for speed
- Show concrete numbers (X alerts, Y attack paths) not vague descriptions
- Distinguish between "direct close" and "risk reduction"
- Highlight high-leverage fixes prominently
- Include the environment-wide perspective (same fix applied everywhere)
- Show the priority recommendation based on total impact

### DON'T:
- Claim an alert will close without evidence from Orca data
- Count the original alert separately from the cascade (include it in the count)
- Ignore attack paths — they're often the most compelling argument for prioritization
- Skip compliance impact — it matters for reporting and audits
- Over-promise on indirect improvements — be honest about partial vs. full resolution

## Error Handling

If an alert has no related alerts, attack paths, or compliance data:
```
═══════════════════════════════════════════════════════════════════
IMPACT ANALYSIS — <alert-id>
═══════════════════════════════════════════════════════════════════

FIX ACTION: <what needs to be done>

REMEDIATION IMPACT: TARGETED FIX
  This alert is an isolated finding — fixing it closes this single alert.
  No related alerts, attack paths, or compliance controls are directly impacted.

  Still worth fixing: <severity> alert with Orca Score <score>
═══════════════════════════════════════════════════════════════════
```

## Integration with orca-alert-triage

This skill complements the `orca-alert-triage` skill:
- **orca-alert-triage**: "What is this alert and should I care?"
- **orca-impact-analysis**: "If I fix it, what's the total payoff?"

Users can chain them: triage first to understand the alert, then impact analysis to justify prioritization.
