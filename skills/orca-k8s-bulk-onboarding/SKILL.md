---
name: orca-k8s-bulk-onboarding
description: Gets many Kubernetes clusters fully connected to Orca in one pass — public clusters with native connectivity issues, private clusters Orca already knows about, and clusters Orca has never seen at all — triaging each one to the right fix instead of defaulting every cluster to the Kubernetes Connector tunnel. For connector-based clusters it mints a single shared tunnel credential pair and installs the chart across every target (resolving a cloud account for self-managed clusters, and per-cluster flags like OpenShift), reporting success/failure per cluster. Also covers the case where a user's own CI/Terraform automation creates clusters dynamically, pointing it at a reusable Terraform module instead of a one-off batch run. Use when the user wants to bulk-onboard, mass-connect, or fleet-onboard many Kubernetes clusters at once, or has a batch of clusters showing connection problems in Cluster Management (e.g., "bulk onboard these 20 clusters", "connect all these kube-contexts to Orca", "fix connectivity for this list of clusters", "our CI creates clusters dynamically, how do we auto-connect them").
trigger: When a user has multiple Kubernetes clusters — any mix of public-but-blocked, private/self-managed, or completely undiscovered — and wants them all connected to Orca without repeating a per-cluster flow for each one, or when a user's own CI/Terraform/automation creates clusters dynamically and needs the Connector wired into that pipeline. E.g. "bulk connect our clusters", "mass onboard these kube-contexts", "fleet onboarding for K8s", "these 30 clusters all show connection errors, fix them", "our Terraform creates clusters on the fly, how do we auto-onboard them to Orca", "script the connector install across all these contexts".
---

# Orca Kubernetes Bulk Cluster Onboarding Skill

Answers: **"I have a batch of clusters — public, private, with or without connection issues, maybe created by my own automation — how do I get all of them fully connected to Orca?"**

## Background

Orca connects a Kubernetes cluster one of two ways: **natively**, by reaching the cluster's public API endpoint from a connected cloud account, or via the **Kubernetes Connector** (`helm-k8s-tunnel` chart, release `orca-tunnel`) — an outbound tunnel for clusters with no public endpoint, or that Orca can't reach natively for some other reason.

A cluster that isn't fully connected falls into one of a few distinct situations, and each needs a different fix. Treating all of them the same way wastes effort — deploying a Connector tunnel onto a cluster that just needs a security-group rule fixed, or vice versa, both miss the actual problem. This skill's job is to **triage each cluster first**, then apply the right fix, and only fall back to a shared-tunnel Connector rollout for the clusters that genuinely need one.

### The situations a cluster can be in

1. **Already connected and healthy.** Nothing to do — report it and move on.
2. **Public and discovered, but connection-blocked.** Orca found the cluster through a connected cloud account and tried to reach it natively, but hit a blocker — missing network access, an unsupported auth mode, or missing permissions. **Fix the native access first** — it's simpler, needs no tunnel, and Orca already has fully-authored, per-cluster-type remediation guidance for exactly this (Step 2 below pulls it live from the API — nothing here is guessed). Fall back to the Connector only if the native fix doesn't resolve it, or the user doesn't want to make that change.
   - **Exception:** if the blocker is specifically that a previously-working Connector tunnel dropped, that cluster isn't a "switch to native" case — hand it to `orca-k8s-connector-troubleshoot` instead of touching it here.
3. **Private and discovered.** Orca already has a record of the cluster (typically because there's no public API endpoint for it to reach) but it's never been connected. Go straight to the Connector — there's no native path to try.
4. **Private and not discovered at all.** Orca has no record of the cluster whatsoever — its cloud account was never onboarded, or it's a genuinely self-managed/on-prem cluster with no cloud account of its own. Go straight to the Connector, using the chart's `isUndiscovered` flag (or `automation`, its older, equivalent name — see Step 5) so the cluster self-registers the moment it connects. These clusters also need a cloud account chosen for them — see Step 3.

A single batch can freely mix all of these — this skill classifies every target cluster first, resolves what it can natively, and only mints a shared tunnel for the clusters that actually land on the Connector.

## One-Time Batch vs. Ongoing CI/Terraform Automation

Before doing anything else, find out which of these the user actually needs:

- **A one-time batch** — a fixed list of existing clusters to connect right now. Follow Steps 1–7 below.
- **An ongoing pipeline** — their own CI, Terraform, or other automation creates clusters dynamically and needs the Connector wired into that process so each new cluster self-onboards without anyone running this skill again. In that case, don't loop installs yourself — point them at the **reusable Terraform module** in `k8s-tunnel-client/terraform/` (parameterized, no hardcoded cluster identity or credentials — see its `README.md`), with `is_undiscovered = true` (its default) so every cluster it creates self-registers. If they're not using Terraform, the same idea applies to whatever templates their pipeline already uses to install the chart: the one thing that must change is setting `isUndiscovered=true` (or `automation=true` on an older chart) on every install, since a cluster created by automation is — by definition — one Orca hasn't discovered yet. Mention that Terraform can't fan a single `helm_release` out across many real clusters in one apply (provider configs can't be parameterized per `for_each` instance) — the module's README covers the two supported patterns: static provider aliases for a known fleet, or invoking the module once per cluster from the pipeline itself for a dynamic one.

A batch can also be mixed: resolve the fixed list now (Steps 1–7), and separately point an ongoing pipeline at the Terraform module for whatever it creates going forward.

## Prerequisites

- `helm` v3+ and `kubectl`, with a working kubeconfig context for every cluster that might end up on the Connector path (situations 3, 4, and any situation-2 fallback).
- An Orca API token covering Kubernetes read, tunnel creation, and cloud account read (Settings → API Tokens — the same permissions the UI's "Connect Kubernetes Cluster" flow and Cluster Management error banners rely on). If a cloud-account lookup comes back `403`, the token's role is missing the cloud-account read permission — ask an Orca admin to add it rather than guessing an ID.
- A target-cluster list: for each cluster, enough to identify it in Orca (`clusterName`, `region`, `cloudVendorId`) plus, for anything that might need the Connector, a kube-context and `clusterType` (`eks`/`aks`/`gke`/`k8s` — self-managed clusters must set `k8s` explicitly, it only auto-detects for EKS/AKS/GKE). Also ask whether any target is **OpenShift** or sits behind an **enterprise proxy** — both are easy to miss and both need an explicit flag at install time (Step 5).

## Usage

```
/orca-k8s-bulk-onboarding <paste or attach a list of clusters: clusterName, region, cloudVendorId, clusterType, kube-context>
```

Or natural language:
- "bulk onboard these 20 clusters, here's the list"
- "these clusters show connection errors in Cluster Management, fix them"
- "our CI creates clusters dynamically, how do we auto-connect them to Orca"

## How It Works

1. **Classify** every target cluster into one of the four situations above.
2. **Fix natively** whatever's blocking situation-2 clusters, falling back to the Connector only when that doesn't clear it.
3. **Resolve a cloud account** for every situation-4 (and situation-2-fallthrough) cluster that doesn't have one.
4. **Mint one shared tunnel** for everything that still needs the Connector.
5. **Loop the Connector install** across that merged list, with `isUndiscovered`/`automation`, `openshift`, and `proxyURL` set only where actually needed.
6. **Verify** every Connector-path cluster actually comes online.
7. **Report** one consolidated table covering the whole batch, across every path.

### Step 1: Classify Every Cluster

For each target, look it up in Orca by `clusterName`/`region`/`cloudVendorId` — the org-wide cluster list (`GET /api/organization/k8s_clusters`) is the most efficient single call if the token has broad-enough read access; otherwise look it up per cloud account (`GET /api/cloudaccount/<cloud_account_id>/k8s_cluster`). Each result carries a `status` and a short-code `connection_errors` list. Classify:

| Found? | `connection_errors` | → Situation |
|---|---|---|
| No | — | **4. Not discovered** |
| Yes | empty, status already onboarded | **1. Already healthy** — skip, report as-is |
| Yes | contains `connector_disconnected` | **Hand off** to `orca-k8s-connector-troubleshoot` — don't touch it here |
| Yes | contains `awaiting_onboarding` only | **3. Private, discovered** |
| Yes | contains anything else (`network_access_blocked`, `unsupported_authentication_mode`, `missing_permissions`, `missing_onboarding_permissions`, `connection_failed`) | **2. Public, blocked** |

If a cluster can't be classified confidently from this data (e.g. a cloud account was only just connected and hasn't scanned yet), ask the user whether it's public or private rather than guessing.

While classifying, also ask (or note from what the user already told you) which targets are **OpenShift** and which sit behind an **enterprise proxy** — carry that forward to Step 5 regardless of which situation a cluster lands in.

### Step 2: Fix Native Access for Situation 2

For each situation-2 cluster, pull its live, per-cluster-type remediation content:

```bash
curl -s "https://<your-orca-api-host>/api/cloudaccount/<cloud_account_id>/k8s_cluster/<cluster_id>/connection_errors" \
  -H "Authorization: Bearer $ORCA_API_TOKEN"
```

This returns, per blocking error, a ready-made `title`, `explanation`, `fix_steps` (what to change in the console/UI), `cli_fix_steps` (literal commands), `ctas`, and `doc_links` — already authored by Orca for that exact cluster type and error. **Don't write your own remediation text for these — always pull it live**, so it stays in sync with whatever Orca's backend currently recommends.

- Present the `title` and `explanation` to the user.
- If `cli_fix_steps` are present, offer to run them — but these touch the customer's own cloud account (e.g. updating a security group or IAM policy), so **always show the exact command and get explicit confirmation before running each one**. Never run them unattended.
- If the user prefers to apply the `fix_steps` themselves (console/UI), or there are no `cli_fix_steps`, present them and wait for confirmation that it's done.

**After a fix lands, don't just wait and re-check — trigger a fresh probe.** Unlike the Connector path (Step 6), a natively-reached cluster's `connection_errors` only gets re-evaluated on the cloud account's next *scheduled* scan — daily, or weekly on some plans — so waiting "a bit" before re-checking can mean waiting up to a week for nothing to have changed. Force an immediate re-check instead:

```bash
curl -s "https://<your-orca-api-host>/api/cloudaccount/<cloud_account_id>/discovery/k8s_cluster" \
  -H "Authorization: Bearer $ORCA_API_TOKEN"
```

This runs the actual connectivity probe synchronously (the same check the scheduled scan would run) and writes the result immediately — then re-check `connection_errors` right after. It's narrowly scoped to Kubernetes discovery, so prefer it as the default. If it's unavailable for some reason (e.g. the token's role lacks access to it), triggering a full cloud account rescan has the same effect since the native K8s probe runs as part of any scan — either `POST /scan-requests` (needs `ORCA_PERM_SCAN_CREATE`) or the product's own "Scan now" action for that cloud account — just slower and heavier than the targeted call above, since it rescans everything in the account, not just Kubernetes connectivity. If it comes back clean, that cluster is done, no Connector involved. If it's still blocked, or the user doesn't want to make the native change, **fold that cluster into the Connector batch** below — it needs a kube-context from the user at this point if it doesn't have one yet, and it now also needs Step 3 if it has no cloud account of its own.

### Step 3: Resolve a Cloud Account for Self-Managed/Undiscovered Clusters

Every cluster that reaches the Connector install needs a `cloudVendorId` that resolves to an **existing** Orca `CloudAccount` in the org — there's no "placeholder" cloud-account concept today. Situation-3 clusters already have one (they came from an existing `KubernetesCluster` record). Situation-4 clusters, and any situation-2 fallthrough with no account of its own, don't — the user has to pick one.

List the org's cloud accounts:

```bash
curl -s "https://<your-orca-api-host>/api/cloudaccount?account_type=REGULAR" \
  -H "Authorization: Bearer $ORCA_API_TOKEN"
```

From each entry, the field to use as `cloudVendorId` is `cloud_provider_id` (or `azure_subscription_id` specifically for an Azure/AKS target) — the display label is `name`, the provider is `cloud_provider`.

- Only offer `REGULAR` accounts. Don't suggest a `TENANT` account (an Azure AD tenant root with no subscription of its own — the chart rejects it outright for AKS, and it's not a meaningful home for any cluster) or a `MANAGEMENT` account (an AWS Organizations payer account — technically accepted but not a meaningful home either).
- If there's exactly one `REGULAR` account in the org, suggest it and let the user confirm rather than making them pick from a list of one.
- If there are several, ask which one — a reasonable default to suggest is whichever account's cloud provider matches the cluster's actual infrastructure (e.g. a cluster running on AWS EC2 nodes maps more naturally under an AWS account than a GCP one), but always let the user override it.

Record the chosen account's `cloud_provider_id`/`azure_subscription_id` as that cluster's `cloudVendorId` for Step 5.

### Step 4: Mint One Shared Tunnel

For the merged list of clusters that need the Connector (situations 3, 4, and any situation-2 fallthrough), create a single tunnel in self-discovery mode — the same API call Cluster Management's "Connect Kubernetes Cluster → Self-managed" flow makes under the hood:

```bash
curl -s -X POST "https://<your-orca-api-host>/api/tunnel" \
  -H "Authorization: Bearer $ORCA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "bulk-onboarding-'"$(date +%Y%m%d)"'", "discovery_mode": "self", "targets_type": "k8s"}'
```

Capture the tunnel id and secret from the response (field names may vary slightly by API version — check your tenant's API reference under Settings → API if the shape looks different). Then fetch the ready-made single-cluster install command for this tunnel:

```bash
curl -s "https://<your-orca-api-host>/api/tunnel/<tunnelId>/helm/install_cmd" \
  -H "Authorization: Bearer $ORCA_API_TOKEN"
```

Read the `tunnelAddr` value out of that generated command and reuse it as-is for every cluster in the batch.

**Treat this credential pair carefully** — it's shared across the whole batch, so a leak is more consequential than a single-cluster credential. Prefer the chart's `existingSecret` value over inline `--set tunnelId=... --set tunnelToken=...` so it never lands in shell history or `helm get values` output — create it once per target namespace before installing:

```bash
kubectl --context "<context>" create namespace orcasecurity --dry-run=client -o yaml | kubectl --context "<context>" apply -f -
kubectl --context "<context>" -n orcasecurity create secret generic orca-tunnel-shared \
  --from-literal=tunnelId="<tunnelId>" --from-literal=tunnelToken="<tunnelToken>"
```

### Step 5: Install the Connector Across the Batch

Split the merged Connector batch into two groups before installing anything — they're handled differently:

**Non-self-managed clusters (cluster_type != k8s)** — call the bulk Helm script endpoint once with every such cluster's id, then run the returned script:

```bash
curl -s -X POST "https://<your-orca-api-host>/api/tunnel/<tunnelId>/helm/bulk_install_script" \
  -H "Authorization: Bearer $ORCA_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cluster_ids": ["<id-1>", "<id-2>", "..."]}' \
  -o orca_k8s_connector_bulk_install.sh
bash orca_k8s_connector_bulk_install.sh
```

Before touching any cluster, the script detects your local kubeconfig contexts (`kubectl config view`) and cross-checks them against what Orca knows per cluster (in particular its API server endpoint) to suggest or correct each cluster's `--kube-context` value, then prints a summary table and asks for approval — type `e` to manually edit any row's context (or, for the Terraform script, its auth mode) before proceeding, or `a` to abort with nothing applied. Only after approval does it loop `helm install` per cluster, printing a per-cluster OK/FAIL summary at the end — it does not stop the batch on the first failure. Pass `-y`/`--yes` to accept all suggestions non-interactively (e.g. from CI), or `--no-detect` to skip the local kubeconfig lookup entirely. A cluster id that doesn't resolve to this organization, or that resolves to a self-managed cluster, is skipped and listed in a trailing comment rather than silently dropped — check that comment block against your intended batch before running.

**Self-managed clusters (cluster_type == k8s), and any cluster needing a per-cluster flag the bulk script can't express (OpenShift, proxy, tolerations, `forceSelfManaged`)** — install individually. Prefer the single-cluster command endpoint over hand-typing:

```bash
curl -s "https://<your-orca-api-host>/api/tunnel/<tunnelId>/helm/install_cmd?cluster_id=<id>" \
  -H "Authorization: Bearer $ORCA_API_TOKEN"
```

append the flag(s) below, then run the returned command:

- **Situation 4 (not discovered at all), or a situation-2 fallthrough with no matching cloud account:** add `--set isUndiscovered=true`. This requires chart `helm-k8s-tunnel` **v1.0.73+**; on an older chart version, use `--set automation=true` instead — it's the same flag under its older, less clear name, so either works, but prefer `isUndiscovered` on current chart versions since it says what it actually does.
- **OpenShift target:** add `--set openshift=true` (and `--set openshiftSCC=<name>` only if it needs a non-default SCC — the chart defaults to `nonroot-v2`). Getting this wrong is silent: with `openshift=false` on an actual OpenShift cluster, the pod just fails admission with no obvious hint why (see `orca-k8s-connector-troubleshoot`, Category 14).
- **Behind an enterprise proxy:** add `--set proxyURL=<url>` (FRP format, e.g. `http://user:pass@proxy.company.com:8080`).
- **Tainted/dedicated node pools:** add `--set "tolerations[0].key=..." --set "tolerations[0].operator=..." --set "tolerations[0].value=..." --set "tolerations[0].effect=..."` (repeat the index for more than one toleration).
- **A managed cluster (EKS/AKS/GKE) that should be treated as self-managed:** add `--set forceSelfManaged=true`.

Record the exit code and `helm install` output for every cluster — don't stop the batch on the first failure, keep going and collect results for all of them. A given cluster's install failure (RBAC, image pull, bad parameter, resource constraints, etc.) is exactly the territory `orca-k8s-connector-troubleshoot` covers in depth; hand that cluster's error off to it rather than re-deriving a fix here. Re-running the install for just the clusters that failed is safe — it reuses the same tunnel credential and the same per-cluster identity, so it won't create a duplicate tunnel or double-register a cluster that already succeeded.

### Step 6: Verify Each Connector-Path Cluster Came Online

Give newly-connected clusters a minute or two, then re-check each one the same way as Step 1 (`GET /api/organization/k8s_clusters` or the per-account listing) and confirm `status` shows onboarded with an empty `connection_errors`. This flips synchronously the moment the Connector's tunnel authenticates successfully — it is **not** gated on a full scan completing, so a short wait is genuinely enough; don't tell the user to wait longer "to be safe." If a cluster's `helm install --wait` succeeded but it still isn't showing up after a reasonable wait, treat that as a connectivity issue — same install-time-vs-runtime triage `orca-k8s-connector-troubleshoot` uses — rather than retrying the install again. For an instant, live ping instead of waiting even a minute, `GET /api/tunnel/clusters/connectivity-check?cluster_id=<id>` returns `{"is_connected": true/false}` straight from the tunnel, with no DB-state delay at all.

**This confirms connectivity, not a completed scan.** `status`/`connection_errors` reflect the tunnel being up, not Orca's asset inventory or scan findings for that cluster — those populate on a separate, slower timeline (potentially much longer than the connectivity check). Don't wait for scan data to appear before reporting a cluster as successfully onboarded in Step 7, and don't treat a lack of scan data shortly after onboarding as a failure — see `orca-k8s-connector-troubleshoot`, Category 15 ("connected but no scan data"), for when that gap is actually worth investigating.

### Step 7: Report Results Across the Whole Batch

```
=====================================================================
K8S BULK ONBOARDING — RESULTS
=====================================================================
SHARED TUNNEL ID      <tunnelId, or "n/a — none needed">
CLUSTERS IN BATCH     <N>

CLUSTER          SITUATION                  CLOUD ACCOUNT         PATH                RESULT               NOTES
<cluster_name>   already healthy            —                     —                   skipped (healthy)    —
<cluster_name>   public, blocked            (already had one)     native fix          fixed                network_access_blocked resolved
<cluster_name>   public, blocked            (already had one)     connector fallback  verified onboarded   native fix declined by user
<cluster_name>   private, discovered        (already had one)     connector           verified onboarded   —
<cluster_name>   not discovered             <chosen account>      connector           helm failed          openshift=true missing, see orca-k8s-connector-troubleshoot
<cluster_name>   connector disconnected     —                     —                   not handled here     see orca-k8s-connector-troubleshoot
=====================================================================
```

Anything not cleanly resolved needs a follow-up — retry the install (Step 5), re-attempt the native fix (Step 2), or hand off to `orca-k8s-connector-troubleshoot` with that cluster's specific error.

## Known Limitations

- **Classification depends on a recent scan.** A cloud account connected moments ago, or one that hasn't had its scheduled scan run yet (daily, or weekly on some plans), may not have error data for a cluster at all — don't force a classification you're not confident in; trigger an on-demand discovery (Step 2) or ask instead.
- **`cli_fix_steps` commands touch the customer's own cloud account.** Always show the exact command and get explicit per-command confirmation before running one — never run them unattended, and never chain them without the user seeing each one.
- **No placeholder cloud account exists yet.** A self-managed/undiscovered cluster must be attached to a real, existing `CloudAccount` (Step 3) — there's no synthetic/virtual account to fall back to today.
- **`isUndiscovered` needs chart v1.0.73+.** Use `automation=true` on older chart versions — identical effect, older name.
- **OpenShift and proxy settings are silent failures if missed.** Neither produces an obvious "you forgot this" error — `openshift=false` on an OpenShift cluster just fails pod admission; a missing `proxyURL` just looks like a generic connectivity timeout.
- **Name collisions silently attach, not fail.** A `cluster_name`/`region`/`cloud_vendor_id`/`cluster_type` combination that matches an existing cluster updates that entry rather than erroring out — double-check the batch for accidental reuse of a name already in use.
- **The Connector path bypasses the UI, not network prerequisites.** Every Connector-path cluster still needs outbound connectivity to the tunnel endpoint.
- **"Onboarded" (Step 6) means connected, not scanned.** `status`/`connection_errors` reflect the tunnel being up and flip within a minute or two of install — they say nothing about whether a scan has run or findings/inventory exist yet for that cluster. Report Step 7 results based on connectivity, not on scan data showing up.
- **The "instant" re-check only applies to the Connector path, never to native.** A Connector tunnel authenticating flips `status`/`connection_errors` synchronously (Step 6). A natively-reached cluster's `connection_errors` only updates on its cloud account's next scheduled scan unless you trigger the on-demand discovery endpoint in Step 2 — don't apply Step 6's "give it a minute" expectation to a situation-2 native fix.
- **The bulk Helm script endpoint (`/helm/bulk_install_script`) excludes self-managed clusters by design.** `cluster_type=k8s` clusters in your batch always need the per-cluster loop in Step 5 (manual, or the single-cluster `helm/install_cmd` endpoint called once per cluster) — they're never silently dropped, but they're also never in the generated script.
- **Both bulk endpoints (`/helm/bulk_install_script` and `/terraform/bulk_install_script`) now return a single bash script**, not a zip or a bare `.tf` file. The Terraform one wraps a multi-cluster Terraform configuration (one aliased provider pair + `helm_release` per cluster, matching the "static provider aliases" pattern the Terraform module's `README.md` documents for a fixed fleet) and, before running `terraform apply`, goes through the same local-kubeconfig-detection → summary-table → approve/edit flow described in Step 5. Its `auth_mode` body field defaults to `auto`, which picks `cloud_native` per cluster where supported (EKS/AKS/GKE, and for AKS only when `resource_group_name` is known) and `kube_context` otherwise — nothing is excluded under `auto`. Pass `auth_mode=kube_context` to force kube-context for every cluster, or the strict `auth_mode=cloud_native` to force cloud-native and exclude (with a reason) anything that can't do it. Helm has no cloud-native mode (kube-context only).

## Reference Docs

- [Connecting Clusters Using Kubernetes Connector](https://docs.orcasecurity.io/docs/connecting-clusters-using-kubernetes-connector) — install steps, self-managed cluster identifier formats.
- [Delete a specific K8s cluster](https://docs.orcasecurity.io/docs/en/delete-specific-k8-cluster) — self-service cleanup if a cluster ends up with a duplicate/stale entry.
- Per-tenant API reference (Settings → API) — exact schema for `/tunnel`, `/organization/k8s_clusters`, `/cloudaccount`, `/cloudaccount/<id>/k8s_cluster/<id>/connection_errors`, and `/cloudaccount/<id>/discovery/k8s_cluster` (the on-demand native re-check used in Step 2).
- `k8s-tunnel-client/terraform/` — the reusable, parameterized Terraform module for CI/Terraform-driven onboarding (see its `README.md` for single-cluster and multi-cluster usage).
- `orca-k8s-connector-troubleshoot` — the companion skill for diagnosing any individual cluster's install/connectivity failure, or a dropped (`connector_disconnected`) tunnel.

## Implementation Notes

1. **Classify before acting.** The single most common way this goes wrong is skipping Step 1 and defaulting every cluster straight to the Connector — that creates duplicate entries for situation-2/3 clusters that didn't need one, and wastes a native fix that would've been simpler.
2. **Never hardcode remediation text for situation-2 clusters.** Always pull `fix_steps`/`cli_fix_steps` live from the `connection_errors` API so this skill can't drift out of sync with what Orca's backend actually recommends.
3. **Don't let self-managed clusters silently fail on a missing cloud account.** Step 3 isn't optional for situation-4 clusters — `handle_k8s_tunnel` rejects with "cloud_account not found" if `cloudVendorId` doesn't resolve to a real account, which looks like a generic install failure if you haven't walked through account selection first.
4. **Ask about OpenShift and proxy up front (Step 1), not after a failed install.** Both failure modes in Step 5 are silent and easy to misdiagnose as something else.
5. **This skill owns triage and fan-out, not individual diagnosis.** When a specific cluster's `helm install` fails, or a tunnel shows `connector_disconnected`, defer to `orca-k8s-connector-troubleshoot`'s failure categories instead of duplicating them here.
6. **Prefer `existingSecret` over inline `--set tunnelId=.../tunnelToken=...`** in the loop — this credential is shared across the whole batch, so keeping it out of shell history and `helm get values` output matters more here than in a single-cluster install.
7. **For CI/Terraform-driven onboarding, point to the module, don't re-implement the loop.** The reusable Terraform module already handles per-cluster parameterization correctly — don't hand-roll an equivalent `helm_release` block inline when the module covers the case.
