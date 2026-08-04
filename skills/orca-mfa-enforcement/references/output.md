# Output reference

Templates and required shapes for what the skill reports. Write for a **cloud owner / CISO**: punchline first, plain English, no raw field names in the body.

## Contents
- [Standard run](#standard-run)
- [Zero-finding runs](#zero-finding-runs)
- [Enforcement summary](#enforcement-summary)
- [Drill-downs](#drill-downs)

## Standard run

1. **Headline:** counts and the exposure. *"41 users in acme-production can sign in without MFA: 28 AWS, 9 Azure, 4 Alibaba — including 2 root accounts and 6 admins. 11 carry high or critical risk."*
2. **Ranked table**, highest risk first: **# | User | Provider | Privilege | Last active | Risk | Proposed action**.
3. **Root & break-glass (own section):** roots without MFA (or without hardware MFA) with their guide steps; break-glass accounts flagged for review — never in the bulk plan.
4. **Quick wins (recommended starting point):** the safe, high-impact subset (e.g. "these 5 console passwords were never used — remove them today, nobody notices"; "these 6 admins are active weekly; notify today, enforce Friday").
5. **Routed elsewhere:** API-only users → key hygiene, federated → IdP, inactive → the cleanup flow, no-signal slices (e.g. "GCP: Workspace integration off — no MFA visibility").
6. **Bottom line:** the single riskiest unprotected user + what full coverage closes.
7. **Coverage note (always):** data is as of the last completed scan, and cloud-log corroboration is capped at 30 days. Name every capability the swept providers lack, reading them off the capability matrix in `references/providers.md` — what MFA means on that provider, whether alert rules and cloud logs exist, whether remove-access is reachable — so the reader can tell a clean result from a blind spot.

## Zero-finding runs

**A clean result is the case that most needs evidence, because a false all-clear is this skill's worst failure and "MFA coverage evidence for an audit" is a stated use.** "I found nothing" is not an output. When Found = 0, replace the ranked table and quick wins with the proof that the zero is real:

1. **Completeness of the sweep:** `total_items` against rows actually classified, and confirmation that every row's `asset_unique_id` prefix matched the intended account — a zero over an incomplete or wrong-scoped population is worthless.
2. **The scoped-vs-broad delta:** what the same query returns unscoped. Equal numbers mean the scope filter did nothing (suspect it); a larger org-wide count that drops to zero in scope is what a genuine clean account looks like.
3. **Second-surface corroboration:** the account-scoped alert query returning zero open no-MFA alerts, or, where the provider has no alert rules, an explicit statement that no second surface exists here.
4. **What the clean result does *not* cover:** the swept providers' missing capabilities from the matrix, and the buckets that were routed out (API-only, federated, no-signal) — a user population that is 100% API-only is not an MFA success story.

State the conclusion at the strength the evidence supports: "every console user in this account has MFA" is a claim; "no console users without MFA were found, and here is why that population is complete" is the defensible version.

## Enforcement summary

Mandatory after any action and at session end, including read-only runs.

**The buckets must reconcile:** Proposed + Guided + Staged + Enforced + Access removed + Failed + Skipped always sums to Found. **Proposed** is the start state (gap surfaced, no action go-ahead yet), so a sweep-only run reconciles without pretending anything was sent. The last three encode the three outcomes of the verification check and must not be collapsed: **Staged** (gate passed, artifact delivered, no check could run), **Enforced** (check passed), **Failed** (check ran and did not confirm the change). Enrollment is reported as a sub-count of Guided, never as its own bucket. Routed-elsewhere buckets (API-only, federated, inactive, disabled, no-signal) sit **outside** Found — they are not remediable MFA gaps here.

```
MFA ENFORCEMENT SUMMARY
  Found:      41 users without MFA (28 AWS, 9 Azure, 4 Alibaba; 2 root, 6 admins)
  Proposed:       16 (gap surfaced, awaiting a go-ahead)
  Guided:         12 (instructions + notifications sent; 3 confirmed enrolled)
  Staged:          2 (confirmed, artifact delivered, no credentials to verify with)
  Enforced:        3 (require-MFA policy applied, explicitly confirmed, verified via cloud CLI)
  Access removed:  5 (unused console passwords deleted, last-used evidence confirmed)
  Failed:          1 (policy applied but the verification check did not confirm it)
  Skipped:         2 (1 break-glass -> review with owner, 1 whose enforce command
                      needs manual handling -> guide still delivered)
  Routed:     9 outside Found (5 API-only -> key hygiene, 2 federated -> IdP,
              2 inactive -> inactive-identity cleanup)
  No signal:  GCP (Workspace integration off)
  Alerts:     ~38 open no-MFA alerts commented + snoozed to their deadlines; they
              close after enrollment and the next scan (estimated from alert-type
              totals; Orca data refreshes on scan)
```

## Drill-downs

The sweep's compact inventory lives in the scratchpad — drill-downs read from it, never re-enumerate.

- **detail `<user>`**: full evidence (MFA state and source, console access, password usage, privilege, last activity, open alerts).
- **guide `<ids|all>`** / **enforce `<ids>`** / **remove-access `<ids>`**: generate artifacts for that subset (enforce and remove-access always pass the Step 6 gate).
- **recheck**: after the next scan, re-run the sweep from the saved inventory and report the delta — who enrolled, which alerts closed, who is past deadline and still exposed.
- **cloud `<aws|azure|gcp|alicloud|oci|tencent>`** / **only `<console|root>`**: re-scope the sweep.
