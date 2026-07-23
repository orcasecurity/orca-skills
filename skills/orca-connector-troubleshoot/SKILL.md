---
name: orca-connector-troubleshoot
description: Diagnoses Kubernetes Connector (K8s Tunnel Client / Helm chart `orca-tunnel`) install and connectivity failures from raw customer input — error text, `helm status`, `kubectl describe`, or pod logs — and walks through step-by-step remediation. Use when a user reports the K8s Connector won't install, won't connect, keeps disconnecting, or the cluster shows connected but no scan data appears.
trigger: When user reports a Kubernetes Connector / K8s tunnel client problem — helm install failures, pod crash-looping or stuck Pending/ImagePullBackOff, tunnel not connecting, TLS/DNS/proxy errors, RBAC or ClusterRoleBinding errors, OpenShift SCC issues, duplicate cluster entries, or a cluster showing "connected" with no scan data (e.g., "k8s connector won't connect", "tunnel pod is crashlooping", "helm install failed for orca-tunnel", "cluster shows connected but no data", "TLS handshake timeout k8s connector")
---

# Orca Kubernetes Connector Troubleshooting Skill

Answers: **"Why isn't my Kubernetes Connector installing or connecting, and how do I fix it myself before opening a support ticket?"**

## Background

The Kubernetes Connector (aka K8s Tunnel Client, Helm chart `orca-tunnel`, image `k8s-tunnel-client`) runs entirely on the customer's own cluster. It opens a read-only outbound tunnel (built on `frp`) back to Orca so private and self-managed clusters can be scanned without exposing the cluster's API server to Orca. Because it runs on customer infrastructure, failures are invisible to Orca until the customer reports them. Most of what's covered here can be self-diagnosed from `helm status`, `kubectl describe`, and pod logs alone — that's the point of this skill.

## Usage

```
/orca-connector-troubleshoot <paste error, helm status, kubectl describe, or pod logs output>
```

Or natural language:
- "the k8s connector pod is stuck in ImagePullBackOff"
- "helm install for orca-tunnel failed, here's the output: ..."
- "tunnel keeps disconnecting, logs show TLS handshake timeout"
- "cluster shows connected in Orca but no inventory data is showing up"

## How It Works

1. **Triage** — classify as install-time (chart never deployed successfully) vs. runtime (chart deployed, tunnel/scan not working).
2. **Match** — map the raw input to one of the known failure categories below using its error signature.
3. **Remediate or ask** — walk through that category's fix; if the input doesn't clearly match a signature, ask a targeted clarifying question instead of guessing.
4. **Escalate** — if nothing resolves it (including the "known platform limitations" below, which the customer cannot fix themselves), produce a clean handoff summary.

## Step 1: Triage — Install-Time vs. Runtime

Settle this first, with one command if the customer hasn't already supplied it:

```
kubectl get pods -n <namespace>
helm status <release> -n <namespace>
```

- **Install-time**: `helm install`/`helm upgrade` itself failed, or the pod has never reached a stable `Running` state (`CrashLoopBackOff`, `ImagePullBackOff`, `Pending`, or an error creating the chart's cluster-scoped resources).
- **Runtime**: the chart deployed and the pod has been `Running` at some point, but the tunnel drops, never establishes, or the cluster looks "connected" in Orca yet nothing scans.

If this isn't clear from what the customer gave you, ask before guessing (Step 3).

## Step 2: Match to a Known Failure Category

### Install-time categories

**1. TLS handshake timeout / can't reach the tunnel endpoint**
- *Signature*: pod logs show repeated `dial tcp ... i/o timeout` or `TLS handshake timeout` from `frpc`; the connector retries with backoff (starts at 15s, doubles up to a 60s cap) but never gets past the first connection attempt.
- *Root cause*: firewall or NetworkPolicy blocks outbound TCP 443 from the cluster to `tunnelAddr`.
- *Remediation*:
  1. Confirm `tunnelAddr` is copied exactly from the Orca install command (don't reuse one from a different cluster/region).
  2. The tunnel-client image itself has no `curl` — verify connectivity from a throwaway debug pod instead: `kubectl run tmp-curl --rm -it --image=curlimages/curl -n <namespace> -- curl -v https://<tunnelAddr>:443`.
  3. If that fails, check egress firewall rules / NetworkPolicies allow outbound 443 to Orca's static IP allowlist and to the `tunnelAddr` FQDN specifically (see **Connecting Clusters** doc).
  4. If a corporate proxy is required to reach the internet at all, this is really the **proxy misconfiguration** category below — configure `proxyURL` first.

**2. RBAC / permission errors applying the chart**
- *Signature*: `helm install` fails outright (often on the `ClusterRole`/`ClusterRoleBinding`/`ServiceAccount` objects), or the chart installs but pod logs show `forbidden`/`Unauthorized` when listing cluster resources.
- *Root cause*: the identity running `helm install` lacks rights to create cluster-scoped RBAC objects, or the deployed `ClusterRole` (`orca-k8s-collector-role` by default) is missing a resource/apiGroup the connector needs.
- *Remediation*: confirm the installer has sufficient cluster-scoped rights to create the chart's RBAC objects. For post-install `forbidden` errors: `kubectl auth can-i --list --as=system:serviceaccount:<namespace>:orca-k8s-collector` and diff against the chart's `clusterRole.rules`. The `ClusterRole` can be safely narrowed via a values override (e.g. dropping `secrets` access) if company policy requires it — core scanning still works without `secrets` `get`/`list`, though some findings that depend on secret metadata will be reduced.

**3. Image pull failures**
- *Signature*: pod stuck in `ImagePullBackOff` / `ErrImagePull`.
- *Root cause*: outbound access to the image registry (`public.ecr.aws` or `ghcr.io`, whichever the install command references) is blocked, or `image.pullSecrets` is missing/wrong for a private mirror.
- *Remediation*: `kubectl describe pod <pod>` to see the exact image/registry being pulled; confirm outbound access to that registry hostname; set `image.repository`/`image.pullSecrets` if mirroring internally. If the install is more than a few chart versions old, also suggest upgrading — recent releases fix both CVEs and unrelated bugs.

**4. Incorrect, missing, or malformed `--set` parameters**
- *Signature*: `helm install` succeeds but the pod crash-loops immediately, or logs show a rejection at the `frpc` login step, e.g.:
  ```
  [E] [client/service.go:363] cloud_account not found
  [W] [client/service.go:381] connect to server error: cloud_account not found
  login to the server failed: cloud_account not found. With loginFailExit enabled, no additional retries will be attempted
  ```
- *Root cause*: one of `tunnelAddr`, `tunnelId`, `tunnelToken`, `clusterName`, `region`, `clusterType`, `cloudVendorId` is missing, blank, or wrong — most commonly `cloudVendorId` pasted as the wrong identifier for the cloud vendor (e.g. a full OCI tenancy OCID instead of just its trailing unique-ID segment) or a `tunnelToken`/`tunnelId` copied from a different cluster's install command.
- *Remediation*: re-copy the exact install command from Orca's cluster-onboarding screen rather than reusing/editing an old one; confirm `clusterType` is one of `eks`/`aks`/`gke`/`k8s`; confirm `cloudVendorId` matches the format Orca expects for that vendor (see the **Connecting Clusters** doc's self-managed cluster section for the exact identifier format per vendor).

**5. Kubernetes version incompatibility**
- *Signature*: the chart installs but the pod fails on startup with an API compatibility error, or specific chart resources fail to apply.
- *Root cause*: cluster is below the connector's minimum supported version (1.16+).
- *Remediation*: confirm with `kubectl version`; this needs a cluster upgrade — not something the skill can work around.

**6. Misuse of `automation=true`, or duplicate/conflicting cluster entries**
- *Signature*: Orca's cluster list shows two entries for what should be one cluster — a "self-managed" entry and a properly-typed one (EKS/AKS/GKE) — both referencing the same physical cluster.
- *Root cause*: `automation=true` exists for clusters created by automation that Orca hasn't auto-discovered yet. Setting it (or otherwise onboarding as self-managed) on a cluster that's already visible to Orca through its cloud account — or that a later cloud-account scan auto-discovers — creates a second, duplicate entry. Self-managed rows don't automatically get cleaned up when auto-discovery later finds the same cluster.
- *Remediation*: before using `automation=true`, confirm the cluster isn't already discoverable under the customer's connected cloud account. If a duplicate already exists, this is generally not self-service-cleanable — escalate (Step 4) with both cluster entries' names/IDs and the shared cloud account so support can merge/remove the stale row.

**7. Resource constraints**
- *Signature*: pod `OOMKilled`, or stuck `Pending` with insufficient-CPU/memory scheduling events.
- *Root cause*: node doesn't have enough allocatable CPU/memory for the chart's `resources.requests`/`resources.limits`.
- *Remediation*: `kubectl describe pod` for the exact values in effect — don't assume defaults from memory, they change between chart versions; `helm get values <release>` shows what's actually applied. Free node capacity, or override `resources` in the install command.

**8. Custom namespace issues**
- *Signature*: `helm install` fails saying a referenced secret doesn't exist, even though `kubectl get secret` shows it exists somewhere in the cluster.
- *Root cause*: installing into a non-default namespace needs both `--namespace <ns>` and `--create-namespace` (if new); an `existingSecret` (with `tunnelId`/`tunnelToken` keys) must live in that *same* namespace as the release — a secret created in `default` isn't visible to a release installed into e.g. `orca-security`.
- *Remediation*: confirm the `--namespace`/`--create-namespace` flags match where the secret was created; `kubectl get secret <name> -n <namespace>` to check directly.

### Runtime / post-install categories

**9. Rate limiter / `context deadline exceeded` reaching the Kubernetes API**
- *Signature*: pod `Running`, tunnel may be up, but logs show `context deadline exceeded` or throttling when the connector tries to list cluster resources.
- *Root cause*: the connector can't reach the in-cluster API server — either the `ClusterRoleBinding` isn't actually bound to the running ServiceAccount, or a NetworkPolicy blocks pod-to-API-server traffic.
- *Remediation*: confirm the `ClusterRoleBinding` binds the ServiceAccount actually in use (`orca-k8s-collector` by default) to the `orca-k8s-collector-role` `ClusterRole`; `kubectl auth can-i --list --as=system:serviceaccount:<namespace>:orca-k8s-collector`; check NetworkPolicies allow egress from the tunnel pod to the API server's Service IP.

**10. Tunnel establishes, then drops on auth/token errors**
- *Signature*: logs show a successful initial connection, then periodic disconnects citing auth/token rejection.
- *Root cause*: usually a `tunnelToken` reused from a different cluster's install, or — if this is a reconnect after a previous tunnel was supposedly deleted — a **stale tunnel target** left over on Orca's side. Re-onboarding can fail with something like:
  ```json
  "status": ["K8s Tunnel client is unreachable"]
  ```
  referencing a `tunnel_target_id` that should no longer exist.
- *Remediation*: confirm the `tunnelId`/`tunnelToken` pair is unmodified from the original install command. If this follows a prior delete/re-onboard, stale-tunnel cleanup is not currently customer-self-serviceable — escalate (Step 4) with the `tunnel_target_id` (or cluster/tunnel IDs from the error) so support can clear it.

**11. Proxy misconfiguration**
- *Signature*: works with no proxy, breaks once `proxyURL` is set; or the environment requires a proxy but none is configured.
- *Root cause*: `proxyURL` follows FRP's URL format — scheme, optional embedded credentials, host, and port — with `http`, `socks5`, and `ntlm` schemes all supported. A wrong scheme, bad credentials, or a proxy allowlist that doesn't include the tunnel endpoint will break the connection.
- *Remediation*: validate the `proxyURL` scheme and credentials against the chart's own documented format (`helm/values.yaml`'s `proxyURL` comment, and the README's "Proxy Configuration" section, in the `k8s-tunnel-client` repo); confirm the proxy itself permits egress to the tunnel endpoint; re-check pod logs for the specific `frpc` connection error after setting it.

**12. DNS resolution failures**
- *Signature*: logs show `no such host` or similar DNS failures resolving `tunnelAddr`.
- *Root cause*: cluster DNS (CoreDNS/kube-dns) can't resolve the Orca tunnel FQDN — common in air-gapped or custom-DNS environments.
- *Remediation*: from a debug pod in the cluster, resolve `tunnelAddr` directly (e.g. `nslookup`/`getent hosts`); if it fails, check the cluster's DNS config / custom upstream resolvers can reach public DNS or have an internal record for the Orca FQDN.

**13. OpenShift-specific SCC issues**
- *Signature*: pod fails to schedule or start, only on OpenShift, with an SCC-related admission error (e.g. "unable to validate against any security context constraint").
- *Root cause*: on OpenShift, `openshift: true` must be set at install time. When set, the chart adds an `openshift.io/scc` annotation on the Deployment *and* a `ClusterRole` rule granting `use` on the named `SecurityContextConstraints` (`security.openshift.io` apiGroup, default name `nonroot-v2`, or the `openshiftSCC` override) to the connector's ServiceAccount via the existing `ClusterRoleBinding` — this is the correct, automatic way OpenShift grants an SCC via RBAC, so no manual `oc adm policy` step should be needed. The two most common failure modes instead: (1) `openshift: true` was never set, so the pod falls under the cluster's default `restricted`-type SCC, which typically rejects the chart's pinned `runAsUser`/`fsGroup` (1001); or (2) `openshiftSCC` points at a name that doesn't exist in the target cluster — the RBAC rule applies without error, but pod admission then fails because no matching SCC can be found.
- *Remediation*: confirm `openshift: true` was actually set on install (`helm get values <release>`); confirm the named SCC (`openshiftSCC`, default `nonroot-v2`) exists in the cluster (`oc get scc <name>`) and is compatible with the chart's pod/container security context (non-root, all capabilities dropped, read-only root filesystem); if it doesn't exist, either create it or point `openshiftSCC` at an existing compatible SCC.

**14. Cluster shows "connected" but scan results never populate**
- *Signature*: tunnel pod healthy, no errors in its logs, Orca console shows the cluster as connected — but no inventory/scan data appears after a reasonable wait.
- *Root cause*: the connector's job (a healthy tunnel) is done at this point — this is almost always an Orca-side scanning/discovery issue, not a connector defect. One specific known case: **BYOC (Bring-Your-Own-Cloud) accounts do not run Kubernetes scanning by design** — a cluster attached to a BYOC cloud account will register and show connected but never get scanned, with no workaround on the customer's side other than attaching the cluster to a standard (non-BYOC) cloud account instead.
- *Remediation*: check whether the cluster's associated cloud account is a BYOC account — if so, this is a known platform limitation to escalate/discuss with support, not a connector bug. Otherwise, treat it as an escalation case (Step 4): this can't be diagnosed further from the customer's side.

## Step 3: Ask Clarifying Questions When Input Is Ambiguous

Don't guess a category from a vague report. Ask:
- "Can you share the tunnel pod's logs (`kubectl logs <pod> -n <namespace>`) and `kubectl describe pod <pod> -n <namespace>`?"
- "Is this a managed cluster (EKS/AKS/GKE) or self-managed/on-prem?"
- "Did `helm install`/`helm upgrade` complete successfully, or did the command itself fail?"
- "Has this connector ever worked, or has it never connected since install?"
- "Are you behind a corporate proxy or air-gapped network?"
- "Is this cluster on OpenShift?"
- "Was this cluster (or its cloud account) previously onboarded and then removed?"

## Step 4: Escalation / Handoff

If the category can't be resolved from the customer's side — including any of the known platform limitations above — produce a clean handoff summary rather than leaving the customer stuck:

```
=====================================================================
K8S CONNECTOR — SUPPORT HANDOFF
=====================================================================
CLUSTER TYPE       <eks | aks | gke | k8s / self-managed>
CONNECTOR VERSION  <from pod logs / image tag>
INSTALL OR RUNTIME <install-time | post-install>
CATEGORY           <matched category, or "unmatched">
WHAT WAS TRIED      <steps already attempted>
RELEVANT IDS        <tunnelId / tunnel_target_id / cluster name, if known>
LOGS ATTACHED       <yes/no — attach kubectl logs + describe output>
=====================================================================
```

## Output Format

```
=====================================================================
K8S CONNECTOR TRIAGE
=====================================================================
STAGE:      <install-time | runtime>
CATEGORY:   <matched category name>
CONFIDENCE: <high | medium — ask clarifying question if medium/low>

ROOT CAUSE:
  <one-line explanation>

REMEDIATION:
  1. <step>
  2. <step>
  ...

REFERENCE: <relevant doc section>
=====================================================================
```

If nothing matches confidently, skip straight to Step 3's clarifying questions instead of forcing a category.

## Known Platform Limitations (not fixable by the customer)

Recognize these so the skill doesn't send a customer in circles trying to self-fix something that needs an Orca-side change:
- **BYOC accounts don't run Kubernetes scanning** (category 14) — by design, not a bug.
- **Stale tunnel targets** can block re-onboarding or cause auth drops (category 10) and generally require Orca-side cleanup.
- **Duplicate self-managed + auto-discovered cluster entries** (category 6) generally require Orca-side merge/removal once created.

For all three, the fastest path is a clean escalation (Step 4) rather than repeated customer-side troubleshooting.

## Reference Docs

- [Connecting Clusters Using Kubernetes Connector](https://docs.orcasecurity.io/docs/connecting-clusters-using-kubernetes-connector) — install steps, static IP allowlist, self-managed cluster identifier formats.
- Proxy and OpenShift configuration have no dedicated public doc page — the chart itself is the source of truth. In the `k8s-tunnel-client` repo: `helm/values.yaml`'s `proxyURL`, `openshift`, and `openshiftSCC` comments, and the README's "Proxy Configuration" section and configuration options table.

## Implementation Notes

1. **Validate before launch** against a sample of real past support tickets for the K8s Connector — the categories above were cross-checked against real customer threads in `#domain-k8s-container-security`, but coverage should be re-confirmed periodically as the connector evolves.
2. **Don't guess when input is ambiguous** — a wrong category sends the customer down the wrong remediation path and erodes trust in the skill faster than admitting uncertainty and asking a follow-up.
3. **Always distinguish install-time from runtime** first (Step 1) — most of the categories only make sense once you know which side of that line the customer is on.
4. **Recognize platform limitations as out of customer scope** — don't ask a customer to retry indefinitely against something engineering needs to fix; escalate cleanly instead.
