# Provider reference

Everything provider-specific for the MFA sweep: what each cloud exposes, how to enumerate it, and how enforcement works there. Read the capability matrix before improvising for a provider.

## Contents
- [Capability matrix](#capability-matrix)
- [Enumeration models](#enumeration-models)
- [No-MFA alert types](#no-mfa-alert-types)
- [Enforcement mechanisms](#enforcement-mechanisms)
- [Remove console access](#remove-console-access)
- [Provider-specific edge cases](#provider-specific-edge-cases)

## Capability matrix

What each column says is a product fact: a blank capability is not a data-collection failure to work around, it is a limit to state in the output.

| Provider | MFA signal | Console gate | No-MFA alert rules | Cloud logs | Privilege signal | Remove-access from here |
|----------|-----------|--------------|--------------------|-----------|------------------|------------------------|
| AWS | `MfaActive` from the IAM credential report, plus `HardwareMfaActive` (matters for root) | `PasswordEnabled` | 4 (incl. root and hardware-root) | CloudTrail | free on alert rows (`ScoreVector`), effective-permissions payloads corroborate | **yes — the only provider where bucket 8 fires** |
| Azure / Entra ID | `MfaActive` **computed from 4 controls**, named per user in `MfaSources`: Conditional Access, PIM role policy, registered Authentication Methods, Security Defaults | `AccountEnabled` (no separable password facet) | 3 org-level + CIS subscription variants, tiered by privilege | Activity / sign-in logs, **premium-gated** | free (`ScoreVector` + the privilege-tiered alert types) | no separable password facet → inactive hand-off |
| GCP / Workspace | Workspace 2-Step Verification enforcement (`isEnforcedIn2Sv`) — **absent entirely without the integration**, and `UserSuspended` / `IdentityProvider` / activity vanish with it | Workspace-managed, not per-project | 1 | Audit Logs | free on alert rows (`ScoreVector`) | no — suspension is a Workspace/cleanup action |
| Alibaba Cloud | `MfaActive` from the RAM credential report; null when the report omits it | `ConsoleLogon`; `PasswordEnabled` exists but does **not** gate | 2 (user and root) | none | free on alert rows (`ScoreVector`) | mechanism exists, but bucket 5 absorbs bucket 8 → via the cleanup flow |
| OCI | `MfaActive` on the user | `Capabilities.canUseConsolePassword` | 1 | none | free on alert rows (`ScoreVector`, e.g. "Entity Policy: Privileged") | mechanism exists, but bucket 5 absorbs bucket 8 → via the cleanup flow |
| Tencent Cloud | `MfaActive` from the CAM console-login flag (`LoginFlag.Stoken`) | `IsConsoleLoginEnabled` is the gate; `PasswordEnabled` expresses the same console-login setting and is the less reliable read of it, so where the two disagree trust `IsConsoleLoginEnabled` | **none** | none | not free — derive from attached `Policies` (a statement allowing wildcard action on wildcard resource with no condition) or the CAM policy alert rules | no usable usage timestamp → unreachable |

## Enumeration models

Users only — groups, roles, and service accounts are out of scope for MFA.

**The gate field is a tri-state, not a boolean.** These expressions are shorthand for retrieval; when the gate reads null or is absent, that is *unknown*, never `false`. A null gate keeps the user in the console buckets with the gate flagged unreadable — the Alibaba credential report is documented below as omitting fields, so this is a live case, and coercing it to false silently deletes real console users from the findings.

| Provider | Model | Decide "needs MFA" from |
|----------|-------|--------------------------|
| AWS | `AwsUser` | `PasswordEnabled and not MfaActive` (root: bucket 1) |
| Azure / Entra ID | `AzureUser` | `not MfaActive` (+ `AccountEnabled` — a blocked user can't sign in) |
| GCP / Workspace | `GcpUser` | `MfaActive = false` (explicitly false; absent = no Workspace signal) |
| Alibaba Cloud | `AliCloudUser` | `ConsoleLogon and not MfaActive` |
| OCI | `OciUser` | `Capabilities.canUseConsolePassword and not MfaActive` |
| Tencent Cloud | `TencentCloudUser` | `IsConsoleLoginEnabled and not MfaActive` |

## No-MFA alert types

Machine strings for the account-scoped alert cross-check and for `get_alerts_with_similar_alert_type` (which takes a placeholder `alert_id` such as `orca-0`).

| Provider | No-MFA alert types |
|----------|--------------------|
| AWS | `aws_all_users_without_mfa` (console users incl. root), `aws_users_with_pw_without_mfa` (console users excl. root), `aws_root_user_without_mfa`, `aws_root_user_without_hardware_mfa` |
| Azure | `az_org_level_privileged_users_without_mfa`, `az_org_level_non_privileged_users_without_mfa`, `azure_org_level_privilege_escalation_users_without_mfa` (+ subscription-level CIS variants `az_privileged_users_without_mfa`, `az_non_privileged_users_without_mfa`; tenant posture: `az_user_settings_security_defaults_disabled`) |
| GCP | `google_workspace_user_without_active_mfa` |
| Alibaba | `alicloud_user_without_mfa`, `alicloud_root_user_without_mfa` |
| OCI | `oci_user_with_disabled_mfa` |
| Tencent | **none** |

Each alert embeds the user asset and Orca's own `RemediationConsole` enrollment steps — reuse those in the guide artifacts.

## Enforcement mechanisms

Applying any of these locks the user out of the console until they enroll, so all of them pass the Step 6 gate.

| Provider | Enforcement mechanism | Notes |
|----------|----------------------|-------|
| AWS | Attach the AWS-documented "self-manage MFA" deny policy (deny everything except MFA management unless `aws:MultiFactorAuthPresent`) to the user or their group; org-wide via SCP | User keeps exactly enough access to enroll, everything else is denied until they do. Rollback = detach |
| Azure / Entra ID | Conditional Access policy requiring MFA for the selected users (needs Entra ID P1; **always exclude the break-glass accounts by name**); tenant-wide alternative: Security Defaults (free tier) | CA still allows the sign-in that registers MFA. Never stage a tenant-wide CA policy without a named break-glass exclusion — locking every admin out of a tenant is unrecoverable. Rollback = disable the policy |
| GCP / Workspace | Enforce 2SV on the org unit or group in the Admin console, with an enrollment grace period | Enforcement ≠ enrollment: users enroll themselves during the grace period, then are locked out. **Rollback:** turn 2SV enforcement back off for that OU or group (record which one, and its prior setting) |
| Alibaba Cloud | Require MFA binding on the user's login profile (`MFABindRequired`), or account-wide security preference | Mechanism-level steps, mark for review before running (less battle-tested surface). **Rollback:** set `MFABindRequired` back to its recorded prior value on each user, or restore the account-wide preference |
| OCI | Sign-on policy requiring MFA in the IAM identity domain — but policies are **per identity domain**, so group the targets by each user's `IdentityDomain` first: a tenancy with `Default` plus a custom domain needs one policy per domain, and a single policy silently covers only part of the set. Note that Orca's own remediation text for these alerts leans on notifying the user or resetting their console password (`oci iam user ui-password create-or-reset`) — that is a **guide-path action, not enforcement**: it neither requires nor verifies MFA, so it must never be applied under a consent gate that disclosed a lockout | Mechanism-level, mark for review. **Rollback:** delete or disable the sign-on policy rule that was added (capture the policy's prior statement text before editing) |
| Tencent Cloud | Console-login MFA flag on the user (the write side of `LoginFlag.Stoken`) | Mechanism-level, mark for review; no alert rule exists to verify against. **Rollback:** restore the user's prior console-login MFA flag, recorded before the change |

## Remove console access

For bucket 8 only, and bucket 8 requires **positive evidence the password is unused**. Read the precondition before reaching for a command: on Alibaba and OCI the timestamps collapse, so those users are claimed by bucket 5 and reach removal through the cleanup flow instead; on Tencent no password-usage field exists at all, so the evidence the confirmation gate must restate cannot be stated truthfully and removal is not available from here. **In practice that leaves AWS as the provider where this path fires.** The others are listed so a cleanup flow acting on the same identity knows the mechanism, not as an invitation to generate one from this skill.

- **AWS** — `aws iam delete-login-profile` (access keys untouched; rollback = `create-login-profile`, which requires setting a new password)
- **Alibaba** — disable console logon on the login profile (rollback: re-enable it, password must be reset)
- **OCI** — remove the console-password capability (rollback: restore the capability, password must be reset)
- **Tencent** — disable console login (rollback: re-enable it, password must be reset)
- **Azure** — no separable password facet; its never-signs-in case is the inactive hand-off

## Provider-specific edge cases

- **Azure activity data is premium-gated:** `LastActiveTime` / `IsIdentityActive` derive from Graph `signInActivity`, which requires premium Entra ID licensing (P1/P2) — most tenants have neither field on any user, as the normal state, not a telemetry bug. The MFA verdict itself is unaffected (`MfaActive` computes from registration and policy, not sign-ins), but the inactive bucket and the urgency bump degrade by design: report "activity not observable for this tenant" instead of presenting every user as active, and sequence enforcement as if everyone is.
- **Azure "covered" is policy-dependent:** `MfaActive: true` via Conditional Access or Security Defaults reflects tenant policy, not a registered device; if the tenant later drops the policy, coverage evaporates. `MfaSources` says which case each user is; mention it when coverage rests on a single policy. `az_user_settings_security_defaults_disabled` corroborates tenant-level posture.
- **Azure guests / federated users:** `#EXT#` guests register MFA in their home tenant; Workspace-federated and SSO users likewise live in the IdP. Route onward instead of reporting a local gap — and note a resource-side Conditional Access policy as the boundary control.
- **Root accounts:** no provider exposes an API to enroll or force MFA on root — artifacts are guidance for the account owner, and root never joins a bulk enforce. AWS GovCloud roots have no MFA concept at all (Orca's own rules exclude them).
- **Tencent has no degraded path at all:** no alert rules, and the per-asset reader matches on names while names come only from discovery — so if discovery is down for a Tencent scope there is nothing to fall back to. Say that plainly rather than implying a fallback exists.
- **Non-user models carry `MfaActive`** (e.g. Alibaba VPN servers): enumerate by the user models above, never by a bare field query.
