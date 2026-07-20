---
name: orca-overprivileged-identities-rightsizing
description: Over-privileged identity right-sizing - finds identities holding more permissions than they use, according to Orca's pre-computed PoLP (Principle of Least Privilege) recommendations, across an account, business unit, or tag in AWS, Azure, and GCP; ranks them by identity risk score (highest risk first); and drives right-sizing through a non-destructive path (stage the change as ready-to-run artifacts) or a destructive path (apply the change) that always requires an evidence-based safety check plus explicit confirmation. Use when the user wants to reduce excess permissions, right-size roles or users, act on least-privilege recommendations, or shrink standing privilege (e.g. "right-size over-privileged identities", "apply PoLP recommendations", "trim unused permissions").
trigger: When the user asks to "right-size over-privileged identities", "reduce excess permissions", "apply least-privilege / PoLP recommendations", "which identities have permissions they don't use", "trim this role's permissions", "act on Orca's IAM recommendations", or passes an account / business unit / tag for an over-privilege sweep.
---

# Orca Over-Privileged Identity Right-Sizing Skill

Answers the question: **"Which of our identities hold far more permission than they use, and how do we safely cut them down?"**

Every unused permission is standing attack surface: if the identity is phished or its key leaks, the blast radius is everything it *may* do, not what it *does* do. This skill sweeps an account or business unit for identities whose granted permissions exceed their observed usage, ranks them by identity risk score, and walks the user through right-sizing with a **non-destructive path (stage: generate the change, apply nothing)** and a **destructive path (apply)** that is always gated behind an evidence-based safety check plus explicit confirmation.

**The core signal (verified in the Orca data model):** Orca's recommendation engine pre-computes a PoLP verdict per identity/grant from ~90 days of observed usage, stored as `RecommendationType` with exactly three values: **"Reduce Permissions"** (over-privileged — this skill's target), **"Inactive"** (dead weight — hand off to `/orca-inactive-identities-cleanup`), and **"PoLP Aligned"** (nothing to do). Where the verdict lives differs per provider:

- **AWS (identity-level):** an `AwsEffectivePermissionsPolicy` per user/role carries the verdict plus a **generated least-privilege policy** (`Recommendation.recommended_policy` + `policy_diff`), `UsedServices` vs `EntityAuthorizedServices`, and the identity's `PermissionUsage` ratio (share of authorized services actually used). Exposed directly via `get_aws_effective_permissions_policy_on_asset`. The engine skips IAM **groups**.
- **Azure (grant-level):** each `AzureIamRoleAssignment` carries **both** the normalized `RecommendationType` verdict and an inline `Recommendation` payload: a typed action (`detach_role`, `read_only`, `just_in_time`, `scope_reduction`, `no_action_needed`), an `action_needed` boolean, and read/write action usage with `LastUsageTime`. The typed actions roll up to the three verdicts (`detach_role` → "Inactive"; `read_only` / `just_in_time` / `scope_reduction` → "Reduce Permissions"; `no_action_needed` → "PoLP Aligned"). Computed only where cloud logs are enabled for the subscription.
- **GCP (grant-level):** a `GcpIamPolicyBindingRecommendation` per policy binding, same normalized-verdict-plus-typed-payload shape, linked to the user or service account. Feature-flag gated in some tenants.

**Provider coverage is a product fact:** Alibaba Cloud, OCI, and Tencent Cloud have **no PoLP recommendation layer** in Orca. This is a three-cloud skill (AWS, Azure, GCP); say so instead of improvising verdicts for other providers.

## Usage

```
/orca-overprivileged-identities-rightsizing 123456789012          # one cloud account
/orca-overprivileged-identities-rightsizing "Production"          # a business unit
/orca-overprivileged-identities-rightsizing --tag env=prod        # scope by tag (instead of account / BU)
/orca-overprivileged-identities-rightsizing 123456789012 --only nhis    # bucket: users | nhis
/orca-overprivileged-identities-rightsizing 123456789012 --action stage # pre-select the non-destructive path
/orca-overprivileged-identities-rightsizing 123456789012 --cloud aws    # one provider
```

Or natural language:
- "right-size the over-privileged identities in acme-production"
- "which roles have permissions they never use?"
- "apply Orca's least-privilege recommendations to the Production BU"
- "trim the unused permissions from our service accounts"
- "who has admin but only ever reads?"

## Processing Logic

### Step 1: Resolve scope

1. **Resolve scope first (ask if not given).** Accept any one of three:
   - **Account id**, used directly.
   - **Business unit**: `get_business_units_data` returns the BU's saved filter (accounts, providers, tags), not a ready-made account list — derive the member accounts from that filter before sweeping.
   - **Tag** (`--tag key=value`, repeatable, or "identities tagged env=prod" in words): sweep every identity carrying the tag(s), across accounts. Express the tag in the Step 2 `discovery_search` query; if the query can't honor it, post-filter retrieved results on the identity's tag fields.

   **If the user gave none of the three, ask which account, business unit, or tag to sweep** (offer to list the visible BUs) and wait. Never sweep a whole org by default. A tag may be combined with an account/BU to narrow further.
2. **No time-frame question.** Unlike the inactive-identities sweep, the usage window is baked into Orca's recommendation engine (~90 days of observed activity at scan time); there is nothing to ask. State the window in the output instead. If the user asks for a different window, explain that the pre-computed verdict is fixed and offer CDR corroboration (30-day cap on this MCP) as the only adjustable lens.

### Step 2: Enumerate over-privileged identities

**Primary path: `discovery_search` (if enabled).** Query identities per provider and decide over-privilege from each asset's own fields — **never from the query wording** (a natural-language "over-privileged X" query is unreliable both ways; query broadly by identity type and filter yourself):

| Provider | Where the verdict lives | Target population |
|----------|-------------------------|-------------------|
| AWS | `EffectivePermissionsPolicy.RecommendationType == "Reduce Permissions"` on `AwsUser` / `AwsIamRole`; payload via `get_aws_effective_permissions_policy_on_asset` | Users and roles with recent activity but unused permissions. IAM groups are not covered by the engine (surface the group alert instead, see fallback) |
| Azure | `RecommendationType == "Reduce Permissions"` on the identity's `AzureIamRoleAssignment`s (the payload's `action_needed == true` corroborates; both fields live on the same asset, see the core-signal note above) | Users, service principals, managed identities — aggregated per principal across their assignments |
| GCP | `Recommendation` on `GcpIamPolicyBindingRecommendation` (linked to `GcpUser` / `GcpIamServiceAccount` via the binding) | Users and service accounts — aggregated per identity across their bindings |

> **Don't assume one query returns every identity.** `discovery_search` returns a bounded, risk-ordered result set (read `total_items` for the true count and the result's `app_url` for the full list). On large accounts retrieve the highest-risk slice, act on that top slice, and report `total_items` as the real total — best-effort ordering of the highest-risk slice, not a global sort of all N.

**Fallbacks**, in order (`discovery_search` may return `Feature is not enabled` or fail transiently with 5xx):

1. **Alert-anchored enumeration (AWS only).** Verified machine alert types keyed on the recommendation engine (pass these exact strings to `get_alerts_with_similar_alert_type`): `aws_user_with_unused_services`, `aws_role_with_unused_services` — every such alert marks an over-privileged identity and embeds the asset. `aws_group_with_unused_services` covers IAM groups (granted >5 services never authenticated) — surface these as "review with owner", the engine generates no group policy. **Azure and GCP have no recommendation-driven alert rules** (verified against the rule catalog); their fallback is path 2 only. The admin-privilege alert family (`aws_iam_user_with_admin_privileges`, `aws_iam_role_with_admin_privileges`, `gcp_service_account_with_admin_privileges`, `azure_principal_with_global_administrator_permission`, and provider variants) corroborates and finds the highest-value targets, but an admin alert alone doesn't prove the permissions are *unused* — always re-check the recommendation fields.
2. **Per-asset reads.** `get_asset_by_name` / `get_asset_by_id` per identity, reading the recommendation fields off each asset (works whenever the serving layer is up).

> **Model-type caveat:** `get_asset_by_name` / `get_asset_by_id` reject unknown `model_type` values. Run a default `Inventory` lookup first and read the asset's real `type` field rather than guessing; MCP-reported names can differ from internal model names.

### Step 3: Classify the fix per identity

The recommendation itself says *what kind* of right-sizing applies. Route by the typed action:

| Verdict / typed action | Meaning | This skill's move |
|------------------------|---------|-------------------|
| `read_only` (Azure/GCP) or AWS `recommended_policy` with only read actions | Identity only ever reads but holds write access | Swap to a read-only role / apply the generated read-only policy |
| `scope_reduction` (Azure/GCP) | Grant is broader than where actions actually happen | Re-scope the assignment/binding to the recommended narrower scope (`additional_data.scope_analysis.recommended_scope`) |
| AWS "Reduce Permissions" with a `recommended_policy` | Engine generated a least-privilege policy from observed usage | Stage that policy; `policy_diff` shows exactly what gets removed |
| `just_in_time` (Azure/GCP) | Used, but rarely | Flag as a JIT-conversion candidate: recommend time-bound, on-request access instead of a trim — don't strip permissions that are legitimately (if rarely) used |
| "Inactive" / `detach_role` | Not over-privileged — unused entirely | **Hand off**: list in one line and point to `/orca-inactive-identities-cleanup`; never duplicate its disable/delete flow here |
| "PoLP Aligned" / `no_action_needed` | Usage matches grants | Count it in the summary as healthy; no action |

Exclusions applied automatically (never staged or applied, reasons verified in the data model):
- **Root / tenant-owner accounts** — out of scope for policy surgery; route to the identity's own hygiene fixes.
- **Platform-owned grants (the rule: exclude identities whose grants are owned by the cloud, not by the customer):**
  - AWS: `IsAwsManagedRole == true` — one boolean that covers service-linked roles (`/aws-service-role/`, e.g. `AWSServiceRoleForECS`), Identity Center (`/aws-reserved/`), **Control Tower** (`aws-controltower-*`, `AWSControlTower*`), Account Factory (`AWSAFT*`), StackSets, QuickSetup, and `OrganizationAccountAccessRole` (verified against the flag's computation).
  - Azure: Microsoft first-party service principals (`AppOwnerOrganizationId == f8cdef31-a31e-4b4a-93e4-5f571e91255a`). Note `IsBuiltInRole == true` is **not** an identity exclusion: never propose editing a built-in role *definition*; swapping an assignment to a narrower built-in role is the normal fix.
  - GCP: Google service agents (`IsUserManaged == false` — `service-*@gcp-sa-*`, `@cloudservices`); Google grants and maintains their bindings.
- **Customer-owned workload identities stay in scope — protected by the gate, not by exclusion.** ECS task/task-execution roles, Lambda execution roles, instance-profile roles, and **Azure managed identities' role assignments** (the engine computes recommendations for them; narrowing an MI's grant is the textbook PoLP fix even though *deleting* an MI would break its workload — that exclusion belongs to the inactive-cleanup skill, not here). **GCP default service accounts** (`IsUserManaged == true` AND `IsUserCreated == false`: `*-compute@developer`, `@appspot`) are in scope **with a caution flag**: usually the biggest over-privilege in a project (default Editor), but load-bearing for any workload that didn't specify its own SA — stage-first, never part of a bulk apply.
- **Break-glass / DR identities** — over-provisioned by design; recommend JIT conversion, never a trim.
- **Vendor / cross-account / cross-tenant identities** — third-party integration roles (scanners, cost tools), AWS cross-account access roles, and Azure cross-tenant principals (Lighthouse delegations, guest/B2B identities) may be exercised from another account or tenant, so their usage is invisible to the engine here. Tag "review with owner"; a trim based on invisible usage is how outages happen.
- **No recommendation data:** absence of a recommendation is never evidence of over-privilege. Azure without cloud logs enabled, GCP tenants without the feature flag, and all AliCloud/OCI/Tencent identities carry no verdict — mark "no PoLP signal available" and never propose action.

> **"Review with owner" means:** the identity looks over-privileged here, but the trim must be confirmed with whoever owns that integration or workload, because its real usage may live outside this account's view. Surface these separately from the quick wins; never fold them into a bulk action.

### Step 4: Rank by identity risk score

Per acceptance: **highest risk first**. Rank on the **inline** `RiskLevel` / `OrcaScore` that `discovery_search` returns with each result — zero extra calls. **Never loop `get_asset_by_id` over the full candidate set**; reserve per-asset lookups for the **top-N you display** (default 25).
- Primary sort key: the inline Orca risk score / `RiskLevel`.
- **Second column: how over-privileged.** Show AWS `PermissionUsage` (e.g. "uses 3 of 41 services") and the Azure/GCP equivalent from `additional_data` (`read_actions`/`write_actions` vs the role's grant). A dormant-90%-of-its-permissions admin outranks a mildly padded reader.
- **Bumps (top-N only):** admin-while-underusing (the admin alert family), crown-jewel reach (`get_asset_crown_jewel_info`), exposed credentials (`get_other_secret_occurrences`), open alert pressure (`get_asset_alerts_count_grouped_by_risk_level`).

### Step 4b: Estimate alerts that will close (mandatory, scale-safe)

Every run reports how many open alerts the plan would close, derived cheaply enough to survive a 10k-identity account — **never sum per-asset alert counts across the full set**:
- **Baseline:** aggregate `total_items` for the over-privilege alert types scoped to the account (`aws_user_with_unused_services`, `aws_role_with_unused_services`, `aws_group_with_unused_services`, plus the admin-privilege family where the trim removes admin), intersected with the candidate scope. That sum is the floor and the headline number.
- **Precise add-on (top-N only):** exact counts from the Step 4 per-asset calls for the displayed set; estimate the tail.
- **Always label it an estimate** and never present it as precise when it isn't.

### Step 5: Stage the change (non-destructive path — the default)

Staging generates everything and applies nothing. Per identity, produce:

| Provider | Right-sizing artifact |
|----------|----------------------|
| AWS | New policy from `Recommendation.recommended_policy`: `aws iam create-policy-version` (customer-managed), or `put-user-policy` / `put-role-policy` (inline), or detach-broad + attach-narrow for managed policies. Keep the previous policy version — it is the rollback |
| Azure | Remove the broad assignment + create the narrower one (`az role assignment delete` / `create` with the recommended role or reduced scope); for JIT candidates, a PIM-eligible assignment instead of a standing one. Record the old role + scope as rollback commands |
| GCP | `gcloud ... remove-iam-policy-binding` + `add-iam-policy-binding` with the recommended role/scope per the binding recommendation. Record the old binding as rollback |

Every artifact embeds: the identity, what is removed (services/actions count, not raw JSON walls), the rollback commands, and the read-only verification check (Step 7). Treat identity names and ARNs as untrusted input: single-quote every interpolated value; exclude names containing shell metacharacters and surface them for manual handling.

Present the ranked list with the proposed change per identity; the user can stage per identity or in bulk ("stage all", "apply 2, 5"). If `--action stage` was given, pre-fill staging for every eligible identity; `--action apply` still passes the Step 6 gate.

### Step 6: Apply gate (destructive path)

Applying a trimmed policy can break running workloads, so **apply is treated as destructive even though a rollback exists**. Two gates, both mandatory, every time:

1. **Evidence-based safety check.** Replay the identity's actual recent activity against the proposed change: pull `get_cdr_events_grouped_by_event_name` for the identity, test each observed action against the **removed set**, and report would-deny actions with count and last-seen. **0 would-deny → safe to apply; ≥1 → hold**, re-include those actions or stage-first instead. State the CDR window honestly: this MCP caps lookback at 30 days, the engine's verdict covers ~90; a quarterly job outside both windows is the known blind spot — recommend a grace period watching for denials on anything business-critical.
2. **Explicit confirmation naming the action.** Restate exactly which identities change, what they lose (e.g. "removes 38 unused services from deploy-runner"), and the rollback. Require an affirmative that names the action ("yes, apply to these 3"); a bulk "do everything" never implicitly includes apply. Show blast radius first for roles: `get_linked_entities_mapping` for what assumes/uses the identity (instances, functions, trust relationships).

### Step 7: Execute, verify, summarize

Remediation tiers (customer-facing):
1. **Orca-native (always works):** comment / update status on the related over-privilege alerts (`add_alert_comment`, `update_alert_status`, `verify_alert`).
2. **Artifacts (no integrations needed):** the staged CLI/Terraform changes with rollback + verification embedded.
3. **Route (only if connected):** Jira ticket, Slack to the owner, IaC PR. Detect availability; never hard-depend.

Verification is **two-stage, because Orca data refreshes only on the next scan**:
- **Immediate, via the cloud CLI (read-only):** AWS `aws iam list-attached-*-policies` / `get-policy-version` shows the new policy; Azure `az role assignment list --assignee` shows the narrowed assignment; GCP `gcloud projects get-iam-policy` shows the replaced binding. Run directly if the CLI is authenticated (ask once per batch); otherwise append to the artifact. Only count an identity as **Applied** after its check passes.
- **Orca-side, after the next scan:** `PermissionUsage`, the recommendation fields, and the related alerts reflect the change only after the next completed scan. Never re-query Orca right after applying and report "no change". Comment the action on the related alerts now for the audit trail.

Then **always** close with the right-sizing summary (see Output Format) — mandatory even when the user stops after the listing.

## Output Format

Write for a **cloud owner / CISO**, punchline first, plain English, no raw field names or policy JSON in the body.

1. **Headline:** counts and the win. *"31 identities in acme-production hold permissions they haven't used in ~90 days: 9 users, 22 NHIs across AWS, Azure, and GCP. 7 carry high or critical risk; right-sizing them removes ~840 unused permissions."*
2. **Ranked table**, highest risk first: **# | Identity | Type | Provider | Uses | Recommendation | Risk | Proposed change** (Uses = "3 of 41 services" style).
3. **Quick wins (recommended starting point):** the safe, high-impact subset to act on first (e.g. "these 5 only ever read; swapping to read-only removes write access nobody uses").
4. **Handed off / JIT:** one line for "Inactive" verdicts → `/orca-inactive-identities-cleanup`, and the JIT-conversion candidates (counted inside Found, see the summary).
5. **Bottom line:** the single riskiest over-privileged identity + total standing privilege removed by the full plan.
6. **Window note (always):** the engine's ~90-day usage window, the 30-day CDR corroboration cap, that all data is as of the last completed scan, and that AliCloud/OCI/Tencent carry no PoLP signal.

### Right-sizing summary (mandatory, after any action or at session end)

The `Alerts:` line is **mandatory on every run**, sweep-only included, using the Step 4b estimate. **The buckets must reconcile:** Staged + Applied + Held + Skipped + JIT always sums to Found (JIT candidates carry the "Reduce Permissions" verdict, so they are part of Found); inactive hand-offs sit **outside** Found — they are not over-privileged, just dead weight for the other skill.

```
RIGHT-SIZING SUMMARY  (engine window: ~90 days)
  Found:      31 over-privileged identities (9 users, 22 NHIs)
  Staged:     20 (artifacts generated, nothing applied)
  Applied:    3 (safety-checked, explicitly confirmed, verified via cloud CLI)
  Held:       1 (safety check found 2 would-deny actions, last used 6d ago)
  Skipped:    3 (1 provider-managed, 1 vendor role -> review, 1 break-glass)
  JIT:        4 (rarely used -> proposed for just-in-time conversion, no trim)
  Handed off: 12 inactive -> /orca-inactive-identities-cleanup (outside Found)
  Alerts:     ~18 open alerts on these identities should close after the next
              scan (exact for the shown set, rest estimated from alert-type totals)
```

### Drill-downs (on request)
- **detail `<identity>`**: full evidence (used vs granted services, the recommendation, last-usage, linked entities).
- **stage `<ids|all>`** / **apply `<ids>`**: generate artifacts for that subset (apply always passes both Step 6 gates).
- **safecheck `<identity>`**: run the Step 6 replay on its own, before deciding.
- **cloud `<aws|azure|gcp>`** / **only `<users|nhis>`**: re-scope the sweep.

## Edge Cases

- **Scope not found:** if the account id / BU resolves to nothing, say so, list visible business units via `get_business_units_data`, and ask. Never sweep a guessed scope.
- **`discovery_search` disabled or failing:** fall back per Step 2 (AWS alert types, then per-asset reads) and say the inventory is "identities Orca currently surfaces", not guaranteed-complete; for Azure/GCP the alert path doesn't exist, so degraded runs are AWS-strongest — say that too.
- **Large accounts:** retrieve the highest-risk slice, display top-N + `total_items` bucket totals, cap per-asset calls to the shown set, derive the alert estimate from aggregates. Total MCP calls stay bounded regardless of account size.
- **Empty AWS effective-permissions payload:** `get_aws_effective_permissions_policy_on_asset` can come back empty for group-derived permissions; fall back to the identity's attached policies + observed events and lower the stated confidence.
- **AWS IAM groups:** the engine generates no group recommendation. Surface `aws_group_with_unused_services` alerts as "review with owner"; right-size the member users instead.
- **Admin identities:** the engine emits a policy scoped to used actions even for admins — the highest-value trims. But cutting admin can still leave escalation paths (a stray `iam:PassRole` survives the trim); for admin-tier identities recommend a privilege-escalation path review of the retained permissions as the follow-up.
- **Recency blind spot:** quarterly/annual jobs outside the ~90d engine window and 30d CDR window won't appear as used. The safety check catches the 30-day slice; for anything business-critical recommend stage-first plus a grace period watching for denials, never a same-day bulk apply.
- **Resource/condition tightening:** if the recommended policy keeps an action but narrows its resource or condition, flag "review" rather than hard-safe — action-level replay can't fully prove resource-level equivalence.
- **SCPs / permission boundaries:** the effective-permissions engine works at the identity-policy level; org-level guardrails aren't re-simulated here. Note it when the account is part of an AWS Organization.
- **Hostile identity names:** quote everything interpolated into artifacts; exclude names with shell metacharacters and surface them separately.
- **Scan staleness:** recommendation fields, `PermissionUsage`, and risk levels are as fresh as the last completed scan; only CDR is near-real-time. Post-apply proof comes from the cloud CLI; alerts close after the next scan.
- **Missing recommendation layers:** Azure subscriptions without cloud logs, GCP tenants without the feature flag, AliCloud/OCI/Tencent always — report "no PoLP signal available" for that slice; never infer a trim from privilege alone.
- **No changes without confirmation:** this skill produces the changes; the user applies them. Stage needs a go-ahead, apply needs the safety check + explicit confirmation. Nothing is ever auto-applied.

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `get_business_units_data` | Expand a business unit to its member accounts |
| `discovery_search` | Primary enumeration of identities per provider (verdict read off each asset, never off the query) |
| `get_aws_effective_permissions_policy_on_asset` | AWS payload: recommended policy, policy diff, used vs authorized services |
| `get_asset_by_name` / `get_asset_by_id` | Resolve identities; read recommendation fields, `PermissionUsage`, provider-managed flags, `RiskLevel` |
| `get_alerts_with_similar_alert_type` | AWS fallback enumeration via `aws_user_with_unused_services` / `aws_role_with_unused_services` / `aws_group_with_unused_services`; admin-family corroboration |
| `get_cdr_events_grouped_by_event_name` / `search_cdr_events` | The Step 6 safety replay: what the identity actually invoked (30-day cap) |
| `get_alert` / `get_asset_by_alert_id` | Alert-driven entry: read the recommendation payload (`IamRecommendedPolicy`) off an over-privilege alert and resolve its identity |
| `get_asset_alerts_count_grouped_by_risk_level` / `get_asset_related_alerts_summary` | Per-asset open-alert counts, **top-N only** |
| `get_asset_crown_jewel_info` / `get_other_secret_occurrences` | Ranking bumps: crown-jewel reach, exposed credentials |
| `get_linked_entities_mapping` / `get_linked_entities_data` | Apply blast radius: what assumes/uses the identity |
| `add_alert_comment` / `update_alert_status` / `verify_alert` | Tier-1 Orca-native actions on the related alerts |

### Parameter notes
- `--only users|nhis` re-scopes to one bucket; `--cloud aws|azure|gcp` to one provider. `--action stage|apply` pre-selects the path; `--action apply` never skips the Step 6 gates.
- Resolve `model_type` from a real asset lookup; don't pass guessed model names.
- `get_alerts_with_similar_alert_type` takes the machine `alert_type` string plus an `alert_id` to exclude; pass a placeholder (e.g. `orca-0`) when enumerating.
- Alert-driven entry: when the user starts from an over-privilege alert id, `get_alert` returns the recommendation payload (`IamRecommendedPolicy`: recommended vs current policy) and `get_asset_by_alert_id` resolves the identity — skip Step 2 and go straight to Step 3 for that identity.

## Implementation Notes

1. **Stage-first is the spine of this skill.** Apply is offered, but the recommended flow is stage, review, safety-check, then apply. Make staging the default proposal and let the user opt up to apply, never the reverse.
2. **The safety check is not optional on apply.** Every apply passes the CDR replay first; "the recommendation engine already looked at usage" is not a substitute — the engine's snapshot is as old as the last scan, the replay is near-real-time.
3. **Risk-first ordering is an acceptance criterion.** A critical-risk role using 3 of 41 services outranks fifty mildly padded readers.
4. **The confirmation gate is non-negotiable.** No phrasing ("just apply all the recommendations") skips Step 6; restate, show would-deny evidence and blast radius, get the explicit yes.
5. **The right-sizing summary is mandatory** on every run, including read-only ones; "found and staged, nothing applied" is a valid summary.
6. **Three-cloud honesty:** AWS, Azure, GCP carry the PoLP verdict; treat any other provider as unsupported and say so instead of improvising.
7. **Stay in scope, link onward:** single-identity permission deep-dives go to `/orca-identity-review`; inactive identities go to `/orca-inactive-identities-cleanup`. The CDR safety replay (Step 6) and JIT-conversion proposals (Step 3) are handled inline. This skill sweeps breadth: find the over-privileged, stage the trim, gate the apply, report what changed.
