---
name: orca-mfa-enforcement
description: MFA enforcement - finds users signing in without multi-factor authentication across an account, business unit, or tag in every cloud provider Orca supports (AWS, Azure incl. Entra ID, GCP via Google Workspace, Alibaba Cloud, OCI, Tencent Cloud), ranks them by identity risk score (highest risk first), and drives remediation through a non-destructive path (guide: enrollment instructions + owner notifications) or a destructive path (enforce: require-MFA policy that locks the user out until they enroll; or removing an unused console password outright) that always requires explicit confirmation. Use when the user wants to find users without MFA, enforce MFA or 2FA, close MFA gaps, check MFA coverage, or produce MFA coverage evidence for an audit (e.g. "enforce MFA for users without it", "who doesn't have MFA?", "find users missing 2FA").
trigger: When the user asks to "enforce MFA", "find users without MFA", "who has no MFA / 2FA / two-factor", "check MFA coverage", "enable MFA for everyone", "close the MFA gap", "which admins lack MFA", "remove unused console passwords", or passes an account / business unit / tag for an MFA sweep.
---

# Orca MFA Enforcement Skill

Answers the question: **"Which of our users can sign in without MFA, and how do we close that gap without locking anyone out?"**

A password-only user is one phish away from being an attacker. This skill sweeps an account or business unit for **users whose console sign-in is not protected by MFA**, ranks them by identity risk score, and walks the user through remediation with a **non-destructive path (guide: per-user enrollment instructions and owner notifications)** and a **destructive path (enforce: apply a require-MFA policy)** that is always gated behind explicit confirmation — because no cloud lets an admin enroll MFA *on a user's behalf*, and enforcement locks the user out until they enroll themselves. Where usage data shows a console password nobody uses, it proposes the better fix: **remove the unused console access** instead of chasing enrollment.

**The core signal:** every user Orca models carries a pre-computed `MfaActive` boolean on the asset itself — one shared field across **all six supported providers: AWS, Azure (incl. Entra ID), GCP (via Google Workspace), Alibaba Cloud, OCI, and Tencent Cloud**. It is tri-state: `true` (covered), `false` (not covered), and **`null` (no signal — never treat as "no MFA")**; in live payloads a null usually shows up as the field being entirely absent, which means exactly the same thing. What it means differs per provider:

| Provider | `MfaActive` means | Extra fields |
|----------|-------------------|--------------|
| AWS | MFA device assigned (IAM credential report) | `HardwareMfaActive` (hardware vs virtual — matters for root), `PasswordEnabled` (console access) |
| Azure / Entra ID | **Computed coverage from 4 sources**, listed in `MfaSources`: Conditional Access policy, PIM role policy, registered Authentication Methods, Security Defaults | `MfaSources` (which control covers the user), `AccountEnabled` |
| GCP | Google Workspace **2-Step Verification enforcement** (`isEnforcedIn2Sv`) — populated **only when the Workspace integration is on**; otherwise absent for every user | `UserSuspended`, `IdentityProvider` (Workspace-derived — they vanish together with the MFA signal) |
| Alibaba Cloud | MFA bound (RAM credential report; `null` when the report omits it) | `ConsoleLogon` (console access) |
| OCI | MFA activated on the user | `Capabilities.canUseConsolePassword` (console access), `PasswordEnabled` |
| Tencent Cloud | Console-login MFA flag (CAM `LoginFlag.Stoken`) | `IsConsoleLoginEnabled`, `PasswordEnabled` |

**MFA is a console-sign-in control.** Access keys and API tokens are not protected by it, so a user with no password/console access has nothing for this skill to fix — that's a key-hygiene problem, not an MFA gap. The provider alert rules gate on exactly this, and so does this skill.

## Usage

```
/orca-mfa-enforcement 123456789012              # one cloud account
/orca-mfa-enforcement "Production"              # a business unit
/orca-mfa-enforcement --tag env=prod            # scope by tag (instead of account / BU)
/orca-mfa-enforcement 123456789012 --cloud aws  # one provider
/orca-mfa-enforcement 123456789012 --only root  # bucket: console | root
/orca-mfa-enforcement 123456789012 --action guide    # pre-select the non-destructive path
```

Or natural language:
- "enforce MFA for the users in acme-production who don't have it"
- "who can log in to our Azure tenant without MFA?"
- "find console users missing 2FA in the Production BU"
- "does everyone with admin rights have MFA?"
- "close the MFA gaps in our Alibaba account"

## Processing Logic

### Step 1: Resolve scope

1. **Resolve scope first (ask if not given).** Accept any one of three:
   - **Account** — an AWS account id, a GCP project or organization, an Azure subscription or tenant, an OCI tenancy. Resolve to its `CloudAccount` asset first, picking the lookup by how Orca names the account: `get_asset_by_name` with `model_type=CloudAccount` works when the given id is (or is embedded in) the display Name (AWS account ids, GCP project ids); for any identifier that is **not** the Orca Name — Azure GUIDs, OCI tenancy OCIDs (the account Name is just the OCID's trailing segment, so a full-OCID name lookup returns empty) — use the discovery query "cloud accounts with vendor id <id>". Then read `CloudAccountType`: `Regular` sweeps directly, `Tenant` expands to member accounts like a small BU. Never guess what an id refers to.

   **Users live on the identity-owning account, which is not always the account the user named.** Azure users are **tenant** objects and GCP users are **organization** objects; AWS, Alibaba, Tencent, and OCI users bind to the account/tenancy itself. A scope given as an Azure subscription or GCP project therefore resolves **upward** to its owning tenant/org for user enumeration — sweep there, report under the scope the user asked for, and say why (users are not per-subscription/per-project objects).
   - **Business unit**: `get_business_units_data` returns the BU's saved filter (accounts, providers, tags), not a ready-made account list — derive the member accounts from that filter before sweeping.
   - **Tag** (`--tag key=value`, repeatable): sweep every user carrying the tag(s), across accounts. Express the tag in the Step 2 query; post-filter on the identity's tag fields if the query can't honor it.

   **If the user gave none of the three, ask which account, business unit, or tag to sweep** (offer to list the visible BUs) and wait. Never sweep a whole org by default.

   **Confirm scope size before sweeping.** If the resolved scope expands to more than 3 accounts or spans more than 2 providers, show the breakdown and confirm how to prioritize first. A named scope is often bigger than the user expects.
2. **No time-frame question.** MFA coverage is binary — a user either signs in with MFA or doesn't — so there is nothing to ask. The only freshness caveat is scan staleness (state it in the output); CDR corroboration is capped at 30 days on this MCP.

### Step 2: Enumerate users without MFA

**Users only.** MFA is a human sign-in control: groups, roles, service accounts, and other NHIs are out of scope — dormant ones belong to an inactive-identity cleanup flow (`/orca-inactive-identities-cleanup`, if installed). Enumerate per provider:

| Provider | Model | Decide "needs MFA" from |
|----------|-------|--------------------------|
| AWS | `AwsUser` | `PasswordEnabled and not MfaActive` (root: see Step 3) |
| Azure / Entra ID | `AzureUser` | `not MfaActive` (+ `AccountEnabled` — a blocked user can't sign in) |
| GCP / Workspace | `GcpUser` | `MfaActive = false` (explicitly false; `null` = no Workspace signal) |
| Alibaba Cloud | `AliCloudUser` | `ConsoleLogon and not MfaActive` — `ConsoleLogon` is the gate. `PasswordEnabled` exists on this model too and can be true while `ConsoleLogon` is false, which reads like a contradiction; it isn't, and it doesn't gate console access |
| OCI | `OciUser` | `Capabilities.canUseConsolePassword and not MfaActive` |
| Tencent Cloud | `TencentCloudUser` | `PasswordEnabled / IsConsoleLoginEnabled and not MfaActive` |

**Primary path: `discovery_search` (if enabled).** Asset queries are **org-wide by default** — a bare "OCI users" spans every tenancy in the org, and the contamination is invisible in the rows — so put the scope in the phrase itself: "<provider> users in cloud account <id>", where `<id>` is the **identity-owning account** from Step 1 (the AWS/Alibaba/Tencent account or OCI tenancy; the Azure **tenant** — a subscription id comes back empty; the GCP **organization**). Scoped this way it filters server-side and is provably complete when `total_items` matches the row count — then **verify every row anyway** via the `asset_unique_id` prefix (below). Phrasing reliability varies in both directions: an MFA-filtered phrase can return rows that contradict the filter (a "users with MFA disabled" query yielding a user whose `MfaActive` is true) or undercount the same population a broad query sees, and a scoped phrase can silently return empty — an empty result is uninterpretable on its own (`total_items` comes back null, indistinguishable from a failed query), so on empty drop the scope, sweep broad, and post-filter by account prefix. **Counting is free:** `total_items` is independent of `limit`, so any query whose only purpose is "how big is this population" or "does this phrasing return anything" runs at `limit=1` and reads `total_items` inline — never spend a 300KB file dump on a count. But a `limit=1` hit validates the **count, not the phrase**: the identical wording can return a real `total_items` at `limit=1` and an empty `data` with null `total_items` at 20 or 50. When the fetch comes back empty where the count didn't, that is the limit, not the wording — retry at a smaller limit before rephrasing, then fall back to broad + post-filter. **The query is retrieval, not classification**: decide from each row's `MfaActive` + console-access fields, never from the fact that a row came back. Scope queries to the **user models above**; `MfaActive` also exists on non-user models (e.g. Alibaba VPN servers), so a bare field query pollutes the sweep.

**Run the sweep lean** (same rules as the sibling sweeps): delegate enumerate-and-classify to a subagent where available, returning a compact TSV (user, provider, MfaActive, console-access, password-last-used, risk, last-active) plus per-provider counts; batch independent calls in parallel; persist the compact inventory to the scratchpad so drill-downs never re-enumerate.

> **Expect file-dumped output.** Discovery payloads routinely exceed the tool's token limit and arrive as a saved file — plan for it instead of discovering it mid-run. The shape: `.total_items` at the top, rows under `.data[]`, each row's fields individually value-wrapped (`.data.<Field>.value`). Extract in **one `jq` pass carrying every field Steps 3-4 decide on for that provider** — MFA state, console access, password usage, activity, plus the provider's own extras (OCI: `Capabilities.canUseConsolePassword`, `IsIdentityActive`, `LastSuccessfulLoginTime`, `IdentityDomain`, key-activity fields; Azure: `MfaSources`, `AccountEnabled`, `IsMember`) — a second pass over a 400KB dump is a wasted round trip. Never read the blob whole:
> ```
> jq -r '.data[] | [.asset_unique_id, .name, .data.Type.value, .data.MfaActive.value, .data.PasswordEnabled.value // "-", (.data.PasswordLastUsed.value // "-"), .data.RiskLevel.value] | @tsv' file
> ```
> **A row's owning account is the middle segment of `asset_unique_id`** (`OciUser_<account>_<uuid>`, the same shape on every provider) — that prefix is the per-row scope check, and what it holds is the *identity-owning* account: the Azure tenant GUID and GCP org number, never a subscription or project id. Use it, not the noise fields: `RelatedCompliances` (~150 framework names per row), the embedded `CloudAccount`/`TenantAccount` hierarchy blob (a fallback account-id source, and absent entirely on some models such as `OciUser`), `bu_tags`, `OrcaTags`, `CodeOrigins` are the bulk of the payload — a few dozen users can arrive as several hundred KB, nearly all of it these fields. `get_business_units_data` file-dumps the same way but with its own top-level shape (`{business_units: {data: ...}}`); the one-pass rule applies there too.

> **Don't assume one query returns every user.** `discovery_search` returns a bounded, risk-ordered result set (read `total_items` for the true count, `app_url` for the full list). On large accounts retrieve the highest-risk slice, act on that, and report `total_items` as the real total — a best-effort ordering of the highest-risk slice, not a global sort.

**Routine cross-check: the account-scoped alert query.** After the asset sweep, one more `discovery_search` — "alerts with rule type <no-MFA rule for the provider> in account <id>", same identity-owning id as the sweep — earns its call three times over: it corroborates the sweep's count, yields every alert id for Step 7's close-the-loop, and carries the `ScoreVector` privilege flags for Step 4. Scoped this way it comes back complete, which is what lets the output claim enumeration was complete rather than best-effort. This is a different and better surface than `get_alerts_with_similar_alert_type` (org-wide and truncated) — keep that one for the fallback below. **When an alert row and the asset disagree, the asset wins.** An alert's embedded `RiskFindings` is a snapshot from when the alert was written and drifts from the asset (an MFA flag reading null there and false on the asset, console access true there and false on the asset) — take the verdict from the asset, take the alert id, `ScoreVector` privilege, and remediation text from the alert.

**Fallbacks**, in order (`discovery_search` may return `Feature is not enabled` or fail transiently with 5xx):

1. **Alert-anchored enumeration.** Orca ships built-in no-MFA alert rules; pass these exact machine strings to `get_alerts_with_similar_alert_type` (placeholder `alert_id` like `orca-0`):

   | Provider | No-MFA alert types |
   |----------|--------------------|
   | AWS | `aws_all_users_without_mfa` (console users incl. root), `aws_users_with_pw_without_mfa` (console users excl. root), `aws_root_user_without_mfa`, `aws_root_user_without_hardware_mfa` |
   | Azure | `az_org_level_privileged_users_without_mfa`, `az_org_level_non_privileged_users_without_mfa`, `azure_org_level_privilege_escalation_users_without_mfa` (+ subscription-level CIS variants `az_privileged_users_without_mfa`, `az_non_privileged_users_without_mfa`; tenant posture: `az_user_settings_security_defaults_disabled`) |
   | GCP | `google_workspace_user_without_active_mfa` |
   | Alibaba | `alicloud_user_without_mfa`, `alicloud_root_user_without_mfa` |
   | OCI | `oci_user_with_disabled_mfa` |
   | Tencent | **none** — field-only provider, no alert fallback |

   Each alert embeds the user asset and Orca's own `RemediationConsole` enrollment steps — reuse those in the guide artifacts. **Caveats:** dismissed/suppressed alerts hide their users; results are org-wide and the page is truncated (`total_items` far exceeds rows returned), so this is a spot-check, not complete enumeration — post-filter rows by the embedded account id and say the inventory is "users Orca currently alerts on".
2. **Per-asset reads:** `get_asset_by_name` with the explicit user `model_type`, reading `MfaActive` + console fields off each asset (works whenever the serving layer is up). Typed-lookup caveats apply: 50-row cap, no pagination, exactly-50 means truncated.

### Step 3: Classify each user

Route every `MfaActive != true` user into exactly one bucket, testing top-down — **the first match wins**. The order encodes two principles. An identity whose exposure is unbounded is judged first and **fail-closed**: root leads the table, and a root whose MFA state can't be read escalates there rather than being dismissed as no-signal. Below it, whole-identity verdicts (disabled, inactive) outrank credential-facet fixes, so a dormant user with an unused password is an inactive hand-off, never a remove-access candidate. Two runs over the same account must land on the same buckets.

| # | Bucket | Detection | This skill's move |
|---|--------|-----------|-------------------|
| 1 | **Root / tenant owner without MFA** | AWS `Name = '<root_account>'`, Alibaba `Name = '<root>'`. Only these two providers have a distinct root principal — on OCI the tenancy owner is an ordinary user in Administrators, and Azure/GCP have no root object, so this bucket is empty there by construction (don't hunt for one). **Root is fail-closed: an absent or null MFA signal belongs here**, which is how Orca's own root rules read it (they fire on absent-or-false) — a root whose MFA state can't be determined is a "confirm in the console" item, never a no-signal dismissal | Top severity, own bucket. **Guide only — no API can enable or force MFA on root**; the account owner must do it signed in as root. AWS sub-case: `MfaActive` true but `HardwareMfaActive` false → recommend hardware MFA (CIS). GovCloud roots (`arn:aws-us-gov`) have no root MFA — skip, as Orca's own rules do |
| 2 | **No signal** | `MfaActive` null — in live payloads usually an entirely absent field; on GCP without the Workspace integration the whole derived group (`UserSuspended`, `IdentityProvider`, last-activity) is missing with it | Never evidence of a gap for a non-root user (root was already claimed above, fail-closed). **Sample 3-5 users per type and tenant** — if none carry the field, mark the whole type-for-that-tenant "no MFA signal available" and stop sampling; then confirm the cause in one call (`get_integration_configs_data` shows whether `google_workspace` is connected), so the verdict ships as verified fact, not inference |
| 3 | **Break-glass / emergency account** | Named/tagged as such, or user says so | Often *deliberately* excluded from MFA policy (an unreachable MFA device during an outage defeats the account's purpose). Flag "review with owner"; **never include in bulk enforcement** |
| 4 | **Disabled / suspended user** | Azure `AccountEnabled: false`, Workspace `UserSuspended: true` | Can't sign in, so the MFA gap is moot. Skip here; if also inactive, it belongs to `/orca-inactive-identities-cleanup` |
| 5 | **Inactive user without MFA** | `IsIdentityActive: false` / stale `LastActiveTime` — where these fields exist at all: on Azure they derive from Graph `signInActivity`, which requires premium Entra ID licensing (P1/P2), so most tenants carry neither. Absent fields mean this bucket cannot fire — absence of activity data is not activity, keep routing down the list; and never substitute the scanner's `LastSeen` timestamp for a sign-in | The better fix is disable-then-delete, not MFA — hand off to `/orca-inactive-identities-cleanup` and don't chase enrollment (or password removal) for a user who never signs in |
| 6 | **Federated / external user** | Azure guests (`#EXT#` in name, `IsMember: false`), IdP-managed users | MFA registration lives in the **home tenant / IdP**, not here. Flag "route to IdP"; a resource-tenant Conditional Access policy can still require MFA at the boundary — note it, don't count as locally remediable |
| 7 | **API-only user** | No console access (`PasswordEnabled`/`ConsoleLogon`/`canUseConsolePassword` false) | MFA doesn't apply to access keys, so this is never an MFA gap — but read the keys before routing. **At least one active key** (`AccessKey1Active` / `AccessKey2Active` or the provider's equivalent) means a live API identity → key hygiene: rotate, scope, or remove. **No active credential at all** means a dormant identity, not a key-hygiene case → route it to the inactive-identity cleanup flow instead of advising key work on keys nobody can use |
| 8 | **Console user without MFA, password unused** | Console access on (per the Step 2 table), `MfaActive: false`, and **positive evidence** the password isn't used: `PasswordRecentlyUsed: false`, or a stale `PasswordLastUsed` (fall back to last-login fields where no password-specific usage exists). No usage signal at all proves nothing — the user stays in bucket 9 | **Usage beats posture:** propose removing the unused console access instead of MFA enrollment — zero user friction, strictly smaller attack surface. Offer enrollment only if the owner confirms console access is still needed |
| 9 | **Console user without MFA, password in use** | Console access on, `MfaActive: false`, and the password is recently used (AWS `PasswordRecentlyUsed` / a fresh `PasswordLastUsed` or last-login) | The remediable target: guide or enforce |

Users with `MfaActive: true` are **Covered** — healthy; count them. On Azure, name the covering source from `MfaSources`: coverage via a Conditional Access policy is one policy-edit away from disappearing, which is worth a line in the output.

**Where a provider's usage and activity signals are the same data, bucket 5 absorbs bucket 8.** Test for this rather than assuming it per provider: if a user's password-usage and activity timestamps hold the same value, password staleness *is* inactivity, so every candidate reaches bucket 5 first and remove-access is unreachable from here. Observed on **OCI** (`PasswordLastUsed`, `LastSuccessfulLoginTime`, `LastActiveTime` are one timestamp under three names) and **Alibaba** (`PasswordLastUsed`, `LastLogin`, `LastLoginTime`, `LastActiveTime` likewise), with `IsIdentityActive` derived from that timestamp on both — on those providers remove-access reaches the identity through the cleanup flow, not through bucket 8 here. That is the ordering working as intended, not a gap: it splits what looks like one big "everyone needs enrollment" list into a short guide list plus a much larger cleanup hand-off. Say so in the output rather than presenting remove-access as available.

### Step 4: Rank by identity risk score

Per acceptance: **highest risk first**. Rank on the **inline** `RiskLevel` / `OrcaScore` from the sweep rows — zero extra calls. **Never loop `get_asset_by_id` over the full candidate set**; per-asset lookups are for the **top-N you display** (default 25).
- Primary sort key: the inline Orca risk score / `RiskLevel`.
- **Second column: privilege, and it is free.** A no-MFA admin is the single worst identity in an account. Every no-MFA alert row carries the verdict in `ScoreVector.AssetContextScore.Features[]` — display names like "User Type: Root", "Effective Policy: Privileged", "Entity Policy: Privileged" — so the account-scoped alert cross-check fills this column for the whole set in the call you already made, on any provider. Azure additionally splits it by alert type (`…privileged…`, `…privilege_escalation…`), and AWS effective-permissions payloads corroborate with `IsPrivileged` / `AllowsPrivilegeEscalation`. Don't derive privilege from group membership: group models are thin (`OciIamGroup` carries no member list at all), so that path costs a call and returns nothing.
- **Bumps (top-N only):** crown-jewel reach (`get_asset_crown_jewel_info`), exposed credentials (`get_other_secret_occurrences`), open alert pressure (`get_asset_alerts_count_grouped_by_risk_level`).
- **Urgency bump — the gap is being exercised:** a recent console sign-in without MFA proves the risk is live, not theoretical. Check the CDR detection alerts (`console_login_without_mfa_from_any`, `root_account_console_login_without_mfa`) and recent ConsoleLogin events for the top-N; a root that logged in password-only last week outranks everything. This evidence exists for three providers only: **cloud-log events are available for AWS (CloudTrail), Azure (Activity / sign-in logs), and GCP (Audit Logs); Alibaba Cloud, OCI, and Tencent Cloud have no cloud-log ingestion.** For those unsupported providers there is nothing to query, so skip the lookup and report the bump as unavailable for the provider rather than spending a call to rediscover it. Where cloud logs do exist an empty result is genuinely ambiguous, and one probe resolves it: an unfiltered `search_cdr_events` for the provider (no account filter) returning zero org-wide means cloud logs aren't reaching Orca for that provider at all — an Azure tenant without the premium licensing / diagnostic settings, or an AWS account whose trail was never connected — while an account-scoped zero cannot separate "not connected" from "not exercised". Either way an absent bump is absent evidence, never "not exercised", so state which of the two you established.

### Step 5: Propose the action plan

**Guide-first is the spine of this skill**: enforcement without communication locks people out. Default proposal per user is **guide** — except the unused-password bucket, where **remove console access** is the better default. The user can override per user or in bulk ("enforce 2, 5", "guide all"). If `--action` was given, pre-fill it for every eligible user; `--action enforce` and `--action remove-access` still pass the Step 6 gate. Root and break-glass stay guide/review-only regardless.

**Guide (non-destructive):** per-user enrollment instructions (reuse the alert's embedded `RemediationConsole` steps — they're maintained per provider) plus an owner-notification artifact (message text naming the user, the risk, the deadline, and the enrollment link). Nothing changes in the cloud.

**Enforce (destructive — locks the user out until they enroll):**

| Provider | Enforcement mechanism | Notes |
|----------|----------------------|-------|
| AWS | Attach the AWS-documented "self-manage MFA" deny policy (deny everything except MFA management unless `aws:MultiFactorAuthPresent`) to the user or their group; org-wide via SCP | User keeps exactly enough access to enroll, everything else is denied until they do. Rollback = detach |
| Azure / Entra ID | Conditional Access policy requiring MFA for the selected users (needs Entra ID P1; **always exclude the break-glass accounts by name**); tenant-wide alternative: Security Defaults (free tier) | CA still allows the sign-in that registers MFA. Never stage a tenant-wide CA policy without a named break-glass exclusion — locking every admin out of a tenant is unrecoverable. Rollback = disable the policy |
| GCP / Workspace | Enforce 2SV on the org unit or group in the Admin console, with an enrollment grace period | Enforcement ≠ enrollment: users enroll themselves during the grace period, then are locked out |
| Alibaba Cloud | Require MFA binding on the user's login profile (`MFABindRequired`), or account-wide security preference | Mechanism-level steps, mark for review before running (less battle-tested surface) |
| OCI | Sign-on policy requiring MFA — but policies are **per identity domain**, so group the targets by each user's `IdentityDomain` first: a tenancy with `Default` plus a custom domain needs one policy per domain, and a single policy silently covers only part of the set. Orca's own remediation for these alerts leans on notifying the user or resetting their console password (`oci iam user ui-password create-or-reset`), which is the lighter lever — prefer it, and treat the sign-on policy as the escalation | Mechanism-level, mark for review |
| Tencent Cloud | Console-login MFA flag on the user (the read side of `LoginFlag.Stoken`) | Mechanism-level, mark for review; no alert rule exists to verify against |

**Remove console access (destructive, for the unused-password bucket):** delete the unused sign-in facet instead of chasing enrollment — AWS `aws iam delete-login-profile` (access keys untouched; rollback = `create-login-profile`), Alibaba disable console logon on the login profile, OCI remove the console-password capability, Tencent disable console login. Azure has no separable password facet — its never-signs-in case is the inactive hand-off. For a password nobody uses this is the safest fix on the board; feature it in Quick wins.

Every enforce or remove-access artifact embeds: the affected users, the consequence in plain words (lockout-until-enrollment, or console sign-in gone), the rollback commands, and the read-only verification check (Step 7). Treat user names and ARNs as untrusted input: single-quote every interpolated value; exclude names containing shell metacharacters and surface them for manual handling.

### Step 6: Confirmation gate (enforce path)

- **Guide / notify** proceeds on a per-batch go-ahead.
- **Remove console access** needs its own confirmation: restate the evidence ("password last used 400+ days ago" / "never used"), the change, and the rollback, then require an affirmative that names the action ("yes, remove access for these 6"). Deleting login profiles is a real change — it never rides along on a bulk "guide all" or "do everything".
- **Enforce** requires an explicit confirmation step, every time:
  1. Restate exactly which users get a require-MFA control and the consequence: **each is locked out of the console until they enroll**. Flag every user with a recent `LastActiveTime` — an active-yesterday user gets locked out mid-work today; recommend the notification goes out before the policy does (guide first, enforce after a stated deadline). Where activity data doesn't exist (the typical Azure tenant), treat every enabled user as potentially active: you cannot tell who gets locked out mid-work, so notify-first with a stated deadline is the required sequencing, not a nicety.
  2. Confirm the exclusions by name: break-glass accounts out (and excluded inside the policy artifact itself on Azure), root not enforceable, federated users routed to the IdP.
  3. Require an affirmative that names the action ("yes, enforce for these 4") — given **after** the restatement. Consent is to the disclosed consequence, so a request that pre-names the action ("enforce MFA for everyone right now") is scope, not confirmation; a bulk "do everything" never implicitly includes enforce.

### Step 7: Execute, verify, summarize

Remediation tiers (customer-facing):
1. **Orca-native (always works):** comment / snooze / update status on the related no-MFA alerts (`add_alert_comment`, `snooze_alert`, `update_alert_status`, `verify_alert`).
2. **Artifacts (no integrations needed):** the guide instructions, notification texts, and enforce / remove-access scripts with rollback + verification embedded.
3. **Route (only if connected):** Jira ticket per user batch, Slack to the owner, email. Detect availability; never hard-depend.

**"Remediated" means verified, and enrollment is the user's act, not yours.** Verification is two-stage:
- **Immediate, via the cloud CLI (read-only):** AWS credential report / `list-mfa-devices` shows the enrollment, `list-attached-user-policies` shows the enforce policy landed; Azure Graph authentication-methods / CA policy state; Workspace user 2SV status. **The user designates the credentials.** One identity check against the already-active CLI context (`aws sts get-caller-identity` / `az account show` / `gcloud config list`) is the only permitted probe: it either confirms the target account or it doesn't. On mismatch or no active credentials, ask which profile/credential to use and remember the answer for the session — never enumerate local profiles hunting for a match. "No credentials for this account" is a valid answer: the checks ship inside the artifact. Count a user as **Enforced** only after the policy check passes, and as **Enrolled** only after the MFA check passes.
- **Orca-side, after the next scan:** `MfaActive` flips and the no-MFA alerts close only on the next completed scan. Never re-query Orca right after acting and report "no change".

**Close the loop on the alerts — this is what makes "remediated" auditable.** For each actioned user, locate their no-MFA alert (already surfaced by the Step 2 enumeration or the alert-type query), `add_alert_comment` documenting the action taken, the owner, and the deadline, and `snooze_alert` until that deadline so the alert resurfaces exactly when follow-up is due instead of sitting as noise. After the next scan, the **recheck** drill-down re-runs the sweep from the saved inventory and reports the delta: who enrolled, which alerts closed, who is past deadline and still exposed.

Then **always** close with the enforcement summary (see Output Format) — mandatory even when the user stops after the listing.

## Output Format

Write for a **cloud owner / CISO**, punchline first, plain English, no raw field names in the body.

1. **Headline:** counts and the exposure. *"41 users in acme-production can sign in without MFA: 28 AWS, 9 Azure, 4 Alibaba — including 2 root accounts and 6 admins. 11 carry high or critical risk."*
2. **Ranked table**, highest risk first: **# | User | Provider | Privilege | Last active | Risk | Proposed action**.
3. **Root & break-glass (own section):** roots without MFA (or without hardware MFA) with their guide steps; break-glass accounts flagged for review — never in the bulk plan.
4. **Quick wins (recommended starting point):** the safe, high-impact subset (e.g. "these 5 console passwords were never used — remove them today, nobody notices"; "these 6 admins are active weekly; notify today, enforce Friday").
5. **Routed elsewhere:** API-only users → key hygiene, federated → IdP, inactive → `/orca-inactive-identities-cleanup`, no-signal slices (e.g. "GCP: Workspace integration off — no MFA visibility").
6. **Bottom line:** the single riskiest unprotected user + what full coverage closes.
7. **Coverage note (always):** data is as of the last completed scan; cloud-log corroboration is capped at 30 days and exists for AWS, Azure, and GCP only (Alibaba, OCI, and Tencent have none); GCP visibility requires the Workspace integration; Tencent has no alert-rule fallback; Azure coverage counts Conditional Access / PIM / Security Defaults as MFA (per `MfaSources`), and Azure activity/inactivity is observable only with premium Entra licensing.

### Enforcement summary (mandatory, after any action or at session end)

**The buckets must reconcile:** Proposed + Guided + Enforced + Access removed + Skipped always sums to Found. **Proposed** is the start state (gap surfaced, no action go-ahead yet), so a sweep-only run reconciles without pretending anything was sent. Routed-elsewhere buckets (API-only, federated, inactive, disabled, no-signal) sit **outside** Found — they are not remediable MFA gaps here.

```
MFA ENFORCEMENT SUMMARY
  Found:      41 users without MFA (28 AWS, 9 Azure, 4 Alibaba; 2 root, 6 admins)
  Proposed:       19 (gap surfaced, awaiting a go-ahead)
  Guided:         12 (enrollment instructions + owner notifications generated/sent)
  Enforced:        3 (require-MFA policy applied, explicitly confirmed, verified via cloud CLI)
  Access removed:  5 (unused console passwords deleted, last-used evidence confirmed)
  Skipped:         2 (1 break-glass -> review with owner, 1 hostile username -> manual)
  Routed:     9 outside Found (5 API-only -> key hygiene, 2 federated -> IdP,
              2 inactive -> /orca-inactive-identities-cleanup)
  No signal:  GCP (Workspace integration off)
  Alerts:     ~38 open no-MFA alerts commented + snoozed to their deadlines; they
              close after enrollment and the next scan (estimated from alert-type
              totals; Orca data refreshes on scan)
```

### Drill-downs (on request)

The sweep's compact inventory lives in the scratchpad — drill-downs read from it, never re-enumerate.
- **detail `<user>`**: full evidence (MFA state and source, console access, password usage, privilege, last activity, open alerts).
- **guide `<ids|all>`** / **enforce `<ids>`** / **remove-access `<ids>`**: generate artifacts for that subset (enforce and remove-access always pass the Step 6 gate).
- **recheck**: after the next scan, re-run the sweep from the saved inventory and report the delta — who enrolled, which alerts closed, who is past deadline and still exposed.
- **cloud `<aws|azure|gcp|alicloud|oci|tencent>`** / **only `<console|root>`**: re-scope the sweep.

## Edge Cases

- **Scope not found:** if the account id / BU / tag resolves to nothing, say so, list visible business units via `get_business_units_data`, and ask. Never sweep a guessed scope.
- **`discovery_search` disabled, failing, or lying:** silent-empty phrasings and wrong-row results are both live failure modes (an "MFA disabled" query returned an `MfaActive: true` user). Decide from the field on every row; on empty results retry broader phrasing before concluding the population is empty; fall back per Step 2 and say the inventory is "users Orca currently surfaces". Tencent has no alert fallback — a degraded Tencent sweep is per-asset reads or nothing, say so.
- **Alert liveness is `Status` / `IsLive`, never the closed fields:** live no-MFA alerts routinely carry a stale `ClosedReason` ("asset deleted") and `ClosedTime` while sitting open, in progress, and last-seen yesterday. Filtering on those fields would drop the entire finding and report zero gaps. For the same reason, an alert's `asset_unique_id` / `GroupUniqueId` can point at pre-re-keying asset ids that no longer match inventory — join alerts to users on `RiskFindings.id` (or the embedded name plus account) instead of assuming the unique ids line up.
- **Null vs false:** `MfaActive: null` — usually an entirely absent field in live payloads — is "no signal", never a gap. The no-signal bucket is never proposed for action; a whole provider can be no-signal (GCP without Workspace), and the integration-status check turns that verdict from a guess into a verified statement.
- **Non-user models carry `MfaActive`** (e.g. Alibaba VPN servers): enumerate by the user models in Step 2's table, never by a bare field query.
- **Large accounts:** retrieve the highest-risk slice, display top-N + `total_items` bucket totals, cap per-asset calls to the shown set. Total MCP calls stay bounded regardless of account size.
- **Azure activity data is premium-gated:** `LastActiveTime` / `IsIdentityActive` derive from Graph `signInActivity`, which requires premium Entra ID licensing (P1/P2) — most tenants have neither field on any user, as the normal state, not a telemetry bug. The MFA verdict itself is unaffected (`MfaActive` computes from registration and policy, not sign-ins), but the inactive bucket and the urgency bump degrade by design: report "activity not observable for this tenant" instead of presenting every user as active, and sequence enforcement as if everyone is (Step 6).
- **Azure "covered" is policy-dependent:** `MfaActive: true` via Conditional Access or Security Defaults reflects tenant policy, not a registered device; if the tenant later drops the policy, coverage evaporates. `MfaSources` says which case each user is; mention it when coverage rests on a single policy. `az_user_settings_security_defaults_disabled` corroborates tenant-level posture.
- **Azure guests / federated users:** `#EXT#` guests register MFA in their home tenant; Workspace-federated and SSO users likewise live in the IdP. Route onward instead of reporting a local gap — and note a resource-side Conditional Access policy as the boundary control.
- **Root accounts:** no provider exposes an API to enroll or force MFA on root — artifacts are guidance for the account owner, and root never joins a bulk enforce. AWS GovCloud roots have no MFA concept at all (Orca's own rules exclude them).
- **Break-glass lockout is the worst outcome:** an emergency account locked behind an unreachable MFA device during an incident is exactly what break-glass exists to avoid. Review with the owner; on Azure the exclusion is written into the CA artifact itself.
- **Enforcement ≠ enrollment:** the policy lands instantly, the user enrolls later (or gets locked out). Recommend notify-first with a stated deadline; the AWS deny-policy pattern leaves self-enrollment open, Azure CA allows the registering sign-in, Workspace has a grace period.
- **Scan staleness:** `MfaActive`, risk levels, and alert states are as fresh as the last completed scan; only CDR is near-real-time. Post-action proof comes from the cloud CLI; alerts close after the next scan.
- **Hostile user names:** quote everything interpolated into artifacts; exclude names with shell metacharacters and surface them separately.
- **No changes without confirmation:** guide needs a go-ahead, enforce needs the Step 6 gate. Nothing is ever auto-applied.

## MCP Tools Used

Load every tool below in a **single ToolSearch at the start of the run** — never stop mid-flow to fetch a schema.

| Tool | Purpose |
|------|---------|
| `get_business_units_data` | Expand a business unit to its member accounts |
| `discovery_search` | Primary enumeration per provider (verdict decided from each row's `MfaActive` + console fields, never from the match) |
| `get_asset_by_name` / `get_asset_by_id` | Resolve users; read `MfaActive`, `MfaSources`, `HardwareMfaActive`, console-access fields, `RiskLevel`, `LastActiveTime` |
| `get_alerts_with_similar_alert_type` | Fallback enumeration via the verified no-MFA alert types; source of per-provider `RemediationConsole` enrollment steps |
| `get_alert` / `get_asset_by_alert_id` | Alert-driven entry: start from a no-MFA alert id and resolve its user |
| `get_integration_configs_data` | Verify an integration-dependent signal in one call (is `google_workspace` connected?) before declaring a provider slice no-signal |
| `search_cdr_events` / `get_cdr_events_grouped_by_event_name` | Urgency corroboration: recent console sign-ins without MFA — AWS / Azure / GCP only, 30-day cap |
| `get_asset_alerts_count_grouped_by_risk_level` | Per-asset open-alert pressure for the ranking bump, **top-N only** |
| `get_asset_crown_jewel_info` / `get_other_secret_occurrences` | Ranking bumps: crown-jewel reach, exposed credentials |
| `add_alert_comment` / `snooze_alert` / `update_alert_status` / `verify_alert` | Tier-1 Orca-native actions; the closed loop: comment the action + deadline on each user's alert, snooze until the deadline |

### Alert-driven entry
When the user starts from a no-MFA alert id, `get_alert` returns the evidence and remediation steps and `get_asset_by_alert_id` resolves the user — skip Step 2 and go straight to Step 3 for that user.

### Parameter notes
- `--action guide|enforce|remove-access` pre-selects the proposed action for every eligible user (Step 5); `--action enforce` and `--action remove-access` never skip the Step 6 gate.
- `--only console|root` re-scopes to one bucket; `--cloud <provider>` re-runs Step 2 for that provider's user model only.
- `--tag key=value` (repeatable) is a scope, an alternative to an account id or BU; state in the output that results are tag-scoped.
- `get_alerts_with_similar_alert_type` takes the machine `alert_type` string plus an `alert_id` to exclude; pass a placeholder id (e.g. `orca-0`) when enumerating.
- Resolve `model_type` from a real asset lookup when unsure; MCP-reported types can differ from internal model names.

## Implementation Notes

1. **Guide-first is the spine of this skill.** Enforce is offered, but the recommended flow is notify, give a deadline, then enforce. Make guiding the default proposal and let the user opt up to enforce, never the reverse — with one exception: an **unused** console password's default is removal (usage beats posture; enrollment for a password nobody uses is wasted friction).
2. **The lockout consequence must be said out loud.** Every enforce proposal names who gets locked out and that recently-active users get locked out mid-work. "Apply MFA for everyone now" still gets the Step 6 restatement and named confirmation.
3. **Risk-first ordering is an acceptance criterion.** A no-MFA admin who signed in yesterday outranks fifty dormant password-only users.
4. **Null is not a gap.** `MfaActive: null` slices (GCP without Workspace, missing report columns) are reported as "no MFA visibility", never folded into Found.
5. **The enforcement summary is mandatory** on every run, including read-only ones; "found and proposed, nothing sent" is a valid summary.
6. **Provider coverage is a product fact:** all six providers carry the shared `MfaActive` field; GCP populates it only via the Google Workspace integration; Tencent has the field but no alert rules. Treat a provider outside this set as unsupported and say so.
7. **Stay in scope, link onward:** inactive users → `/orca-inactive-identities-cleanup` and single-identity permission deep-dives → `/orca-identity-review`, each **if that skill is installed** — otherwise name the fix in plain words (for a dormant user: disable now, delete after a grace period) instead of pointing at a skill the user doesn't have; cross-account role trust without MFA conditions (`aws_cross_account_access_without_mfa_or_eid`) is a role-policy fix, not a user-MFA fix — mention it, don't chase it. This skill sweeps breadth: find the unprotected sign-ins, guide the enrollment, gate the enforcement, report what changed.
