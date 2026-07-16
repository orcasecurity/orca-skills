---
name: orca-inactive-identities-cleanup
description: Inactive-identity cleanup - finds inactive identities (users, groups, and non-human identities) across an account or business unit in every cloud provider Orca supports (AWS, Azure incl. Entra ID, GCP incl. Google Workspace, Alibaba Cloud, OCI, Tencent Cloud), ranks them by identity risk score (highest risk first), and drives remediation through a non-destructive path (disable) or a destructive path (delete) that always requires explicit confirmation. Asks for the inactivity time frame (e.g. last 60 days) when the user hasn't given one. Use when the user wants to clean up inactive or dormant identities, offboard unused users or service accounts, delete stale groups, or shrink the identity attack surface (e.g. "clean up inactive identities", "find dormant users", "disable unused service accounts").
trigger: When the user asks to "clean up inactive identities", "find dormant users", "which identities are unused", "delete stale accounts", "disable inactive service accounts", "remove identities nobody uses", "identity cleanup", "offboard stale identities", or passes an account / business unit for an inactive-identity sweep.
---

# Orca Inactive-Identity Cleanup Skill

Answers the question: **"Which of our identities are dead weight, and how do we safely disable or delete them?"**

Every identity that exists but is never used is pure attack surface: it can be phished, its keys can leak, and nobody notices when it starts doing things. This skill sweeps an account or business unit for inactive **users, groups, and non-human identities (NHIs)**, ranks them by identity risk score, and walks the user through cleanup with a **non-destructive path (disable)** and a **destructive path (delete)** that is always gated behind explicit confirmation.

**The core signal (verified in the Orca data model):** every identity Orca covers carries a pre-computed activity verdict on the asset itself: `LastActiveTime` (when it last did anything) and `IsIdentityActive` (Orca's uniform **90-day** activity convention, computed at scan time). This holds across **all six supported providers: AWS, Azure (incl. Entra ID), GCP (incl. Google Workspace), Alibaba Cloud, OCI, and Tencent Cloud**. Read the verdict off the asset first; CDR log replay is corroboration, never the primary source.

On top of that, three providers carry extra unused-access evidence for the grant side:
- **AWS:** `AccessKeyNLastUsedDate` per key, `PermissionUsage` scalar, Access Analyzer unused-access findings.
- **Azure:** an unused-access `Recommendation` inline on the `AzureIamRoleAssignment` asset.
- **GCP:** `Recommendation` + `LastUsageTime` on the `GcpIamPolicyBindingRecommendation` model (feature-flag gated in some tenants; fall back to the identity's own timestamps when absent).

## Usage

```
/orca-inactive-identities-cleanup 123456789012                 # one cloud account
/orca-inactive-identities-cleanup "Production"                 # a business unit
/orca-inactive-identities-cleanup 123456789012 --inactive 60d  # custom time frame (skips the question)
/orca-inactive-identities-cleanup 123456789012 --only nhis     # scope: users | groups | nhis
/orca-inactive-identities-cleanup 123456789012 --action disable  # pre-select the non-destructive path
```

Or natural language:
- "clean up inactive identities in acme-production"
- "which users haven't been active in the last 60 days?"
- "find groups nobody uses and get rid of them"
- "disable the dormant service accounts in the Production BU"
- "any stale RAM users in our Alibaba account?"

## Processing Logic

### Step 1: Resolve scope and time frame

1. **Resolve scope.** A **business unit** expands via `get_business_units_data` to its member accounts; an **account id** is used directly.
2. **Resolve the time frame (ask if not given).** If the user did not specify an inactivity window (via `--inactive Nd` or in their phrasing, e.g. "last 60 days"), ask before sweeping:

   > *"What inactivity window should I use? **90 days** is Orca's built-in convention (recommended); common alternatives are 30, 60, or 180 days. You can also give me a custom one."*

   - **Default 90d** maps directly onto the pre-computed `IsIdentityActive: false` verdict (the strongest, scan-time signal).
   - **Any other window** is evaluated by comparing the asset's `LastActiveTime` against the cutoff. Note in the output that a shorter window (e.g. 30d) flags more identities but with more false positives (vacations, quarterly jobs), and a longer one (180d) is more conservative.
   - Never re-ask on drill-downs or follow-up actions in the same session; the chosen window sticks until the user changes it.

### Step 2: Enumerate identities

**Primary path: one `discovery_search` sweep (if enabled).** The cross-cloud identity model set is verified against the Orca data model; query identities with `IsIdentityActive = false` (or fetch and post-filter on `LastActiveTime` for custom windows) across:

| Provider | Users | Groups | NHIs / roles |
|----------|-------|--------|--------------|
| AWS | `AwsUser`, `AwsSsoUser` | `AwsIamGroup`, `AwsSsoGroup` | `AwsIamRole`, `AwsSsoPermissionSet` |
| Azure / Entra ID | `AzureUser` | `AzureGroup` | `AzureServicePrincipal` (incl. managed identities), `AzureIamRoleAssignment` for the grant side |
| GCP / Google Workspace | `GcpUser` (Workspace users appear here when the integration is on) | `GcpGroup` | `GcpIamServiceAccount` (+ `GcpIamServiceAccountKey`), `GcpIamPolicyBindingRecommendation` for the grant side |
| Alibaba Cloud | `AliCloudUser` | `AliCloudRamGroup` | `AliCloudRamRole` |
| OCI | `OciUser` | `OciIamGroup`, `OciIamDynamicGroup` | dynamic groups act as the workload-identity primitive |
| Tencent Cloud | `TencentCloudUser` | `TencentCloudCamGroup` | `TencentCloudCamRole` |

**Fallbacks**, in order (`discovery_search` may return `Feature is not enabled`, and it can also fail transiently with 5xx errors while the asset and alert surfaces keep working; fall back on either signal):

1. **Alert-anchored enumeration.** Orca ships built-in inactive-identity alert rules; every alert of these types marks an inactive identity, so `get_alerts_with_similar_alert_type` on them rebuilds the inventory. Verified machine alert types (pass these exact strings):

   | Provider | Inactive users | Inactive groups | Inactive NHIs / roles |
   |----------|----------------|-----------------|------------------------|
   | AWS | `aws_inactive_user` | `aws_unused_groups`, `aws_inactive_group_with_inactive_users` | `aws_iam_old_role_without_policy`, `aws_iam_old_role_with_policy`, `aws_unused_external_identity_role` |
   | Azure | `azure_inactive_user` | `azure_inactive_group_without_users`, `azure_inactive_group_with_inactive_identities` | `azure_inactive_service_principal` |
   | GCP | `google_workspace_inactive_user` (note: not `gcp_inactive_user`) | `google_inactive_group_with_inactive_users` | `gcp_inactive_service_account` |
   | AliCloud | `alicloud_inactive_user`, `alicloud_unused_user_with_console_logon` | `alicloud_inactive_group_without_users`, `alicloud_inactive_group_with_inactive_users` | no role rule |
   | OCI | `oci_inactive_user` | `oci_inactive_group_without_users`, `oci_inactive_group_with_inactive_users` | no role rule |
   | Tencent | none | none | none |

   Unused-credential types (`aws_unused_aws_credentials`, `aws_credentials_older_than_90_days`, `oci_iam_credentials_unused_for_45_days`, `tencent_user_access_key_not_rotated_90_days`) corroborate and partially cover the gaps.

   Each returned alert embeds the identity asset, its `LastActiveTime`/`CreationTime`, attached policies, and Orca's own `RemediationCli` / `RemediationConsole` steps (verified live); reuse those remediation steps when generating artifacts for the less-battle-tested providers (Alibaba, OCI, Tencent).

   **Caveats of this path:** the rules bake in Orca's 90d convention, so a custom window can't be honored here; dismissed/suppressed alerts hide their identities; Tencent has no inactive-identity rules and only AWS has role-inactivity rules. State that the inventory is "identities Orca currently alerts on" and cover the gaps with path 3.
2. `get_linked_entities_mapping` on key compute assets to walk to workload identities (instance to instance profile to role).
3. `get_asset_by_name` per identity or name pattern, reading `IsIdentityActive` / `LastActiveTime` off each asset (works whenever the serving layer is up, verified during a discovery outage).

**Classify each identity** into the three buckets this skill acts on:
- **Human users** (console password, MFA, interactive sessions).
- **Groups** (all six providers have group models).
- **NHIs** (roles, service accounts, service principals and managed identities, plus service-account-style users: password disabled, an active access key, API-only usage).

> **Model-type caveat:** `get_asset_by_name` / `get_asset_by_id` reject unknown `model_type` values (e.g. `AwsIamUser` errors). Run a default `Inventory` lookup first and read the asset's real `type` field rather than guessing; MCP-reported names can differ slightly from internal model names (e.g. `AwsRole` vs `AwsIamRole`).

> **Never trust the query's "inactive" wording, re-check the field.** A natural-language `discovery_search` for "inactive X" is unreliable both ways (verified live): it returns empty for some providers even when inactive identities exist, and it can include *active* identities in the results. Query broadly (by identity type) and decide inactivity yourself from each asset's `IsIdentityActive` / `LastActiveTime`, never from the fact that an item came back.

### Step 3: Decide what is actually inactive

Primary signal, identical for **all six providers**: `IsIdentityActive: false` (default 90d window) or `LastActiveTime` older than the chosen cutoff (custom windows).

Corroboration on top, where available:

| Provider | Extra inactivity evidence |
|----------|---------------------------|
| AWS | `AccessKeyNLastUsedDate` old or never, `PermissionUsage` near zero; `get_cdr_events_grouped_by_event_name` (actor = identity ARN) shows zero events |
| Azure | `Recommendation` / `RecommendationType: "Inactive"` on the identity's role assignments; CDR events |
| GCP | `Recommendation`, `total_actions: 0`, `LastUsageTime` on binding recommendations; unused service-account keys; CDR events |
| Alibaba / OCI / Tencent | Asset timestamps only; no recommendation layer. Say so in the output and lean fully on `LastActiveTime` |
| Groups (all providers) | Inactive when **empty** (no members) or when **every member is itself inactive**. A group with even one active member is never a cleanup candidate. Fetch members via `get_linked_entities_mapping` (the `Users` relation); a group with zero user links is empty |

> **Window cap:** this MCP caps CDR lookback at **30 days** (`last_30_days`). Never call an identity "inactive" from CDR alone; true staleness is anchored on the asset's `LastActiveTime` / `IsIdentityActive`, and the output must say which signal decided.

Exclusions applied automatically:
- **Root / tenant-owner accounts:** never disable/delete candidates, in any cloud. AWS `<root_account>` regularly tops the inactive list with a high risk score; surface it separately with its own fixes (remove root access keys, enforce MFA, stop using root day-to-day) and keep it out of every bulk action.
- **Provider-managed roles:** AWS service-linked roles (`AWSServiceRoleFor*`) can only be removed via `aws iam delete-service-linked-role` and are frequently required or auto-recreated by their service (deleting `AWSServiceRoleForOrganizations` breaks org management); IAM Identity Center roles (`AWSReservedSSO_*`) are owned by Identity Center and deleting them through IAM breaks SSO provisioning. Skip both by default, list them under "provider-managed", and route SSO cleanup to Identity Center. The same pattern holds in other clouds and must be excluded too, e.g. AliCloud `AliyunServiceRoleFor*`, `AliyunReservedSSO-*`, and `AliyunCS*`/`Aliyun*DefaultRole` service-managed roles (verified live: an AliCloud account's roles were almost entirely these), GCP `roles/` service agents, and Azure-managed identities created by services.
- **Too new to judge:** identities created inside the chosen window are skipped (a two-week-old identity with no activity is new, not dead).
- **Possibly human, unclear:** listed under "review" with disable-only options, never proposed for delete.
- **Break-glass / DR identities:** dormant by design; flagged but exempt from delete. Recommend converting them to just-in-time (time-bound, on-request) access instead, so the capability stays available without the standing risk.
- **No activity fields:** absence of `IsIdentityActive` / `LastActiveTime` is never evidence of inactivity. GCP users only carry activity data when the Google Workspace integration is on; OCI IdP-federated users may lack the fields entirely; **AliCloud RAM roles carry no activity signal at all** (verified live: every role in a scanned AliCloud account had `IsIdentityActive: null` and no `LastActiveTime`); inventory-only identity types (e.g. Linode, Anthropic, Vercel users) never have them. Mark all of these "no inactivity signal available" and never auto-propose action, on roles especially lean on the alert-anchored path (Alibaba/OCI have inactive-*user* rules but no inactive-*role* rules, so roles without a signal simply can't be swept, say so).

### Step 4: Rank by identity risk score

Per acceptance: **highest risk first**. For each inactive identity read the risk signals off the asset (`get_asset_by_id`):
- The asset's **Orca risk score / `RiskLevel`** is the primary sort key.
- **Bumps:** privileged or admin holdings while dormant (the classic takeover target), credentials found in code or images (`get_other_secret_occurrences`), crown-jewel reach (`get_asset_crown_jewel_info`), open alert pressure (`get_asset_alerts_count_grouped_by_risk_level`).

### Step 5: Propose the action plan

Default recommendation is **disable first, delete after a grace period** (suggest 30 days disabled with no complaints, then delete). **Already-disabled identities** are detectable on the asset (Azure `AccountEnabled: false`, AWS all keys inactive and no login profile, GCP `disabled: true`): skip the disable proposal for them and propose delete-after-grace directly, noting how long they've been disabled. Present the ranked list with a proposed action per identity; the user can accept, override per identity, or act in bulk ("disable all", "delete 2, 5, 7"). If `--action` was given, pre-fill that action for every eligible identity instead of the per-identity default; `--action delete` still passes the confirmation gate in Step 6, and excluded buckets (break-glass, possibly human, too new) stay disable-only regardless.

| Provider | Identity type | Disable (non-destructive, reversible) | Delete (destructive, irreversible) |
|----------|---------------|----------------------------------------|-------------------------------------|
| AWS | IAM user | Deactivate access keys + delete console login profile | `delete-user` (after keys, MFA devices, policies, group memberships are removed) |
| AWS | IAM role | Restrict the trust policy so nothing can assume it | `delete-role` (after detaching policies and instance profiles) |
| AWS | IAM group | Remove members (group shell stays) | `delete-group` (after members and policies are removed) |
| Azure / Entra | User | Block sign-in (`accountEnabled: false`) | Delete the user |
| Azure / Entra | Service principal / managed identity | Set `accountEnabled: false` | Delete the principal |
| Azure | Role assignment | Remove the assignment (re-creatable) | Removal is the fix; nothing further to delete |
| GCP | Service account | `gcloud iam service-accounts disable` | `gcloud iam service-accounts delete` |
| GCP | IAM binding | Remove the binding (re-creatable) | Removal is the fix |
| Alibaba Cloud | RAM user / role / group | Deactivate access keys + console logon profile; for roles, empty the trust policy | Delete via RAM after detaching policies and memberships |
| OCI | User / group / dynamic group | Strip capabilities (console password, API keys) via user capabilities | Delete via IAM after removing group memberships and policies |
| Tencent Cloud | CAM user / role / group | Disable console login + deactivate keys | Delete via CAM after detaching policies and memberships |

For AWS, Azure, and GCP generate exact CLI/Terraform artifacts; for Alibaba, OCI, and Tencent generate the CLI steps at mechanism level and mark them for review before running (less battle-tested surface).

Root accounts and provider-managed roles (`AWSServiceRoleFor*`, `AWSReservedSSO_*`) never enter this table; they were excluded in Step 3. **Vendor and platform roles** (third-party integration roles like security scanners or cost tools, and org-plumbing like `OrganizationAccountAccessRole`) may pass the inactivity test yet be load-bearing: used rarely but critically, or exercised from another account so their activity is invisible here. Tag them "review with owner" instead of quick-win, and lean on the blast-radius links before proposing anything destructive.

### Step 6: Confirmation gate (destructive actions)

- **Disable** proceeds on a normal per-batch go-ahead.
- **Delete** requires an explicit confirmation step, every time:
  1. Restate exactly which identities will be deleted, **the time frame that condemned them** (e.g. "inactive for 60+ days"), and that deletion is **irreversible**.
  2. Show the blast radius first: what still references each identity (`get_linked_entities_mapping` for attached policies, trust relationships, group memberships, workloads).
  3. Require an affirmative response that names the action ("yes, delete these 4"); a bulk "do everything" never implicitly includes deletes.
- Never propose delete for the "review, possibly human" bucket, break-glass identities, or anything created inside the chosen window.

### Step 7: Execute and summarize

Remediation tiers (customer-facing):
1. **Orca-native (always works):** comment, verify, or update status on the related inactive-identity alerts (`add_alert_comment`, `update_alert_status`, `verify_alert`, `dismiss_alert`).
2. **Artifacts (no integrations needed):** ready-to-run disable/delete scripts per provider (with the deletion prerequisites ordered correctly), or Terraform removals. Treat identity names and ARNs from the environment as untrusted input: always single-quote interpolated values in generated scripts, and flag any identity whose name contains shell metacharacters or control characters instead of embedding it.
3. **Route (only if connected):** file a Jira ticket, Slack the owner, or open an IaC PR. Detect availability; never hard-depend.

Verification after actions are applied is **two-stage, because Orca data refreshes only on the next scan**:

- **Immediate, via the cloud CLI.** Confirm each identity's new state with read-only CLI checks. If the relevant CLI is available and authenticated in the session, run the checks directly (ask once per batch); otherwise append them to the generated script so the user gets verification for free when they run it.

  | Provider | Disabled check | Deleted check |
  |----------|----------------|----------------|
  | AWS | `aws iam list-access-keys` shows all keys `Inactive`; `aws iam get-login-profile` errors with `NoSuchEntity` | `aws iam get-user` / `get-role` errors with `NoSuchEntity` |
  | Azure / Entra | `az ad user show --query accountEnabled` returns `false` (same for service principals) | `az ad user show` / `az ad sp show` errors: resource not found |
  | GCP | `gcloud iam service-accounts describe` shows `disabled: true` | `describe` fails: not found |
  | Alibaba / OCI / Tencent | equivalent read-only describe/get calls, marked for review like the action scripts | same, expect not-found |

  Only count an identity as **Disabled** or **Deleted** in the summary after its check passes.
- **Orca-side, after the next scan.** Asset fields and the related alerts reflect the change only after the next completed scan. Say so explicitly, never re-query Orca right after applying and report "no change". Comment the action on the related alerts now (`add_alert_comment`) so the audit trail exists, report how many open alerts sit on the remediated identities and should close on their own after the next scan, and offer to verify in Orca then.

Then **always** close with the cleanup summary (see Output Format). The summary is mandatory even when the user stops after the listing: found N, actions proposed, nothing applied.

## Output Format

Write for a **cloud owner / CISO**, punchline first, plain English, no raw field names or policy JSON in the body.

1. **Headline:** the counts, the window, and the win. *"62 identities in acme-production have been inactive for 60+ days: 41 users, 6 groups, 15 NHIs across AWS, Azure, and GCP. 9 of them carry high or critical risk."*
2. **Ranked table**, highest risk first: **# | Identity | Type | Provider | Last active | Risk | Proposed action**.
3. **Quick wins:** the safe, high-impact subset (e.g. "these 12 have zero privileges and zero activity; disable today").
4. **Bottom line:** the single riskiest dormant identity + how much attack surface the full cleanup removes.
5. **Window note (always):** state the time frame used and where it came from (user-chosen vs the 90d default), the 30-day CDR corroboration cap, that all asset data is as of the last completed scan, and that Alibaba/OCI/Tencent verdicts rest on the asset timestamps alone.

### Cleanup summary (mandatory, after any action or at session end)

```
CLEANUP SUMMARY  (window: 60 days)
  Found:     62 inactive identities (41 users, 6 groups, 15 NHIs)
  Disabled:  14 (applied, verified via cloud CLI)
  Deleted:   3 (explicitly confirmed, verified via cloud CLI)
  Proposed:  38 (artifacts generated, not yet applied)
  Skipped:   7 (1 root, 2 provider-managed, 2 too new, 2 possibly human -> review)
  Alerts:    9 open alerts on the remediated identities should close
             after the next scan (Orca data refreshes on scan)
```

### Drill-downs (on request)
- **detail `<identity>`**: full evidence for one identity (timestamps, keys, recommendation, privileges, linked entities).
- **disable `<ids|all>`** / **delete `<ids>`**: generate the artifacts for that subset (delete always passes the confirmation gate first).
- **window `<Nd>`**: re-run the sweep with a different time frame.
- **only `<users|groups|nhis>`**: re-scope to one bucket.
- **cloud `<aws|azure|gcp|alicloud|oci|tencent>`**: re-scope to one provider.

## Edge Cases

- **Scope not found:** if the account id / BU name resolves to nothing (typo, wrong tenant, no permissions), say so, list the business units visible via `get_business_units_data`, and ask the user to pick. Never sweep a guessed scope.
- **Hostile identity names:** names and ARNs come from the cloud environment and are untrusted. Quote them in every generated artifact; if a name contains shell metacharacters or control characters, exclude it from scripts and surface it separately for manual handling.
- **`discovery_search` disabled or failing:** some tenants return `Feature is not enabled`, and the service can 500 or time out on specific queries while everything else works. Fall back to the Step 2 chain (alert types table, then linked entities, then per-asset reads) and say the inventory is "identities Orca currently surfaces", not a guaranteed-complete list.
- **Custom window vs the pre-computed verdict:** `IsIdentityActive` is fixed to Orca's 90d convention. For any other window, decide from `LastActiveTime` directly and never present `IsIdentityActive` as if it matched the custom window.
- **30-day CDR cap:** CDR corroborates, it never decides. Staleness is anchored on the asset's `LastActiveTime` / `IsIdentityActive`.
- **Scan staleness:** all asset fields (`LastActiveTime`, `IsIdentityActive`, risk levels, alert states) are as fresh as the last completed scan; only CDR events are near-real-time. Post-remediation proof comes from the cloud CLI checks, never from an immediate Orca lookup; alerts close after the next scan. Never re-sweep right after a cleanup expecting Orca to show the changes.
- **Cloud CLI unavailable or unauthenticated:** don't fail the flow; append the verification checks to the artifacts, count those identities as Proposed/applied-unverified in the summary, and tell the user what to run to confirm.
- **Missing GCP recommendations:** policy-binding recommendations are feature-flag gated in some tenants. Fall back to the identity's own timestamps and say the grant-side evidence was unavailable.
- **Google Workspace identities:** appear as GCP users/groups only when the Workspace integration is enabled; if the user expects them and they're absent, say the integration may be off.
- **Human vs NHI misclassification:** when unsure, put the identity in the "review, possibly human" bucket with disable-only options. A wrong delete on a human break-glass account is far worse than a missed cleanup.
- **Deletion prerequisites:** cloud deletes fail unless dependencies are removed first (keys, MFA devices, policies, group memberships, instance profiles, bindings). Generated scripts must order these steps correctly.
- **Federated / SSO identities:** deleting the cloud-side identity does not offboard the person or workload in the IdP (Okta, Entra ID, Google Workspace). Flag that the IdP side needs its own cleanup; AWS SSO users/groups/permission sets live in IAM Identity Center, not IAM.
- **Groups:** never delete a group with an active member; when a group is inactive because all members are inactive, clean the members first, then the group.
- **No changes without confirmation:** this skill produces the actions; the user (or a routed approval) applies them. Disable needs a go-ahead, delete needs the explicit confirmation gate. Nothing is ever auto-applied.

## MCP Tools Used

| Tool | Purpose |
|------|---------|
| `get_business_units_data` | Expand a business unit to its member accounts |
| `discovery_search` | Primary enumeration: users / groups / NHIs with `IsIdentityActive = false` across all six providers (if enabled) |
| `get_alerts_with_similar_alert_type` | Fallback enumeration via inactive-identity / unused-credential alerts |
| `get_asset_by_name` / `get_asset_by_id` | Resolve each identity; read `LastActiveTime`, `IsIdentityActive`, key last-used fields, `RiskLevel`; Azure role-assignment `Recommendation`; GCP `GcpIamPolicyBindingRecommendation` |
| `get_cdr_events_grouped_by_event_name` / `search_cdr_events` | Corroborate inactivity (30-day cap) |
| `get_asset_alerts_count_grouped_by_risk_level` / `get_asset_related_alerts_summary` | Risk-score ranking inputs |
| `get_other_secret_occurrences` | Bump identities whose credentials are exposed in code/images |
| `get_asset_crown_jewel_info` | Bump identities that can reach sensitive assets |
| `get_linked_entities_mapping` / `get_linked_entities_data` | Delete blast radius: what still references the identity; group membership via the `Users` relation |
| `add_alert_comment` / `update_alert_status` / `verify_alert` / `dismiss_alert` | Tier-1 Orca-native actions on the related alerts |

### Parameter notes
- Time frame: default **90 days** (Orca's built-in `IsIdentityActive` convention); when the user picks another window, compare `LastActiveTime` directly. CDR corroboration is capped at 30 days by the MCP.
- `--only users|groups|nhis` re-scopes the sweep to one bucket. `--action disable|delete` pre-selects the proposed action for every eligible identity (Step 5); `--action delete` never skips the Step 6 confirmation gate.
- Resolve `model_type` from a real asset lookup; don't pass guessed model names (MCP-reported types can differ from internal model names, e.g. `AwsRole` vs `AwsIamRole`).
- `get_alerts_with_similar_alert_type` takes the machine `alert_type` string plus an `alert_id` to exclude; pass a placeholder id (e.g. `orca-0`) when enumerating rather than pivoting from an existing alert.

## Implementation Notes

1. **Ask for the time frame when it's missing.** One question, sensible options (90d recommended, 30/60/180 as alternatives), then stick with the answer for the whole session. Don't silently assume, and don't re-ask.
2. **Disable-first is the spine of this skill.** Delete is offered, but the recommended flow is always disable, wait out a grace period, then delete. Make that the default proposal and let the user opt up to delete, never the reverse.
3. **Risk-first ordering is an acceptance criterion, not a nicety.** The customer promise is "highest-risk dormant identities at the top"; a dormant admin outranks fifty dormant no-privilege users.
4. **The confirmation gate is non-negotiable.** No phrasing of the request ("just delete everything unused") skips step 6; restate, show blast radius, get the explicit yes.
5. **The cleanup summary is mandatory** on every run, including read-only ones; "found and proposed, nothing applied" is a valid summary.
6. **Provider coverage is a product fact, not a guess:** AWS, Azure (incl. Entra ID), GCP (incl. Google Workspace), Alibaba Cloud, OCI, and Tencent Cloud all carry the shared 90-day activity verdict; treat a provider outside this set as unsupported and say so instead of improvising.
7. **Stay in scope, link onward:** over-privilege right-sizing and least-privilege policy work are separate flows (use `/orca-identity-review` for a single-identity permission deep dive); deep NHI hygiene (key rotation, OWASP NHI Top 10 scoring) is out of scope too. This skill sweeps breadth: find the dead weight, disable or delete it, report what changed.
