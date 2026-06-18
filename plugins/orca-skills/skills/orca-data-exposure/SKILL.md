---
name: orca-data-exposure
description: DSPM view — sensitive data at risk across the environment, exposed secrets/PII/credentials, data store security posture, and remediation priorities. Use when user asks about data exposure, sensitive data, or secrets (e.g., "data exposure", "where is our PII", "sensitive data at risk", "exposed secrets", "DSPM view").
trigger: When user asks about sensitive data, data exposure, secrets, PII, DSPM, "where's our sensitive data", "exposed credentials", "data at risk", "sensitive data alerts", or data security posture (e.g., "find exposed API keys", "what PII is at risk?", "data exposure report")
---

# Orca Data Exposure Skill

Answers the question: **"Where is our sensitive data, is it protected, and what's at risk right now?"**

Provides a DSPM (Data Security Posture Management) view: discovers sensitive data across the environment (secrets, PII, credentials, API keys, financial data), identifies unprotected or exposed data stores, ranks data risks by exposure level, and generates a remediation plan to secure the most critical data first.

## Usage

```
/orca-data-exposure
/orca-data-exposure secrets
/orca-data-exposure account 123456789012
```

Or natural language:
- "where's our sensitive data?"
- "find exposed API keys"
- "what PII is at risk?"
- "data exposure report"
- "show me unprotected data stores"
- "DSPM summary"

## Processing Logic

### Step 1: Determine Scope

Parse user input:
- **All data types**: no argument → full DSPM view
- **Specific type**: "secrets" / "PII" / "credentials" / "API keys" → filter
- **Account-specific**: "account 123456789012" → filter by account
- **Asset-specific**: "data on bastion-admin" → filter by asset

### Step 2: Gather Data (run ALL in parallel)

Run 6 discovery_search queries covering different data exposure categories:

**Query 1: Exposed secrets and credentials**
```
discovery_search:
  search_phrase: "exposed secrets credentials API keys passwords"
  limit: 10
```

**Query 2: PII exposure**
```
discovery_search:
  search_phrase: "sensitive data PII personally identifiable information exposed"
  limit: 10
```

**Query 3: Unencrypted data stores**
```
discovery_search:
  search_phrase: "unencrypted S3 buckets databases storage with sensitive data"
  limit: 10
```

**Query 4: Public data stores with sensitive content**
```
discovery_search:
  search_phrase: "publicly accessible storage buckets with sensitive data or secrets"
  limit: 10
```

**Query 5: Sensitive data on internet-facing assets**
```
discovery_search:
  search_phrase: "internet facing assets with sensitive data or secrets"
  limit: 10
```

**Query 6: Certificate and key exposure**
```
discovery_search:
  search_phrase: "exposed private keys certificates TLS SSL"
  limit: 10
```

### Step 3: Enrich Critical Findings

For the top 5 most critical data exposure findings, run in parallel:

**Per asset:**
```
get_asset_related_alerts_summary:
  asset_id: <UUID>
```
```
get_asset_crown_jewel_info:
  group_unique_id: <group_unique_id>
```

### Step 4: Compliance Context

Check data protection compliance:
```
get_enabled_compliance_frameworks:
  (no filters)
```

Extract data-relevant frameworks and scores:
- PCI DSS (payment card data)
- HIPAA (health data)
- GDPR (EU personal data)
- SOC 2 (security controls)
- CIS Benchmarks (encryption, access controls)

### Step 5: Classify and Rank

#### Data Risk Classification

```
CRITICAL — Immediate data breach risk:
  • Secrets/credentials on public-facing assets
  • PII in publicly accessible storage
  • Unencrypted database with sensitive data exposed to internet
  • API keys/tokens in container images or public repos

HIGH — Significant exposure:
  • Secrets on internal assets with other vulnerabilities
  • Unencrypted data stores with sensitive content
  • PII without encryption at rest
  • Credentials in environment variables or config files

MEDIUM — Suboptimal protection:
  • Encrypted but overly permissive access to sensitive data
  • Secrets in private storage but without rotation
  • PII with encryption but weak access controls

LOW — Minor gaps:
  • Internal data stores with proper encryption but missing audit logging
  • Secrets managed properly but rotation overdue
```

#### Data Type Classification

Group findings by data type:
- **Secrets & Credentials**: API keys, passwords, tokens, connection strings
- **PII (Personally Identifiable Information)**: names, emails, SSNs, addresses, phone numbers
- **Financial Data**: credit card numbers, bank accounts, payment tokens
- **Health Data (PHI)**: medical records, insurance IDs, health information
- **Private Keys & Certificates**: TLS/SSL private keys, SSH keys, signing certificates
- **Infrastructure Secrets**: cloud access keys, database passwords, service account keys

## Proactive Remediation Behavior

**CRITICAL: Never leave the user with just data. After EVERY output layer, suggest the next action and offer to generate remediation code.**

After the dashboard and after every drill-down section:
1. **Suggest what to do next** — based on the data risk, recommend the most urgent fix
2. **Offer remediation format selection** — always ask: "I can generate the fix. What format do you prefer?"
3. **Supported formats**: Terraform, CloudFormation, Ansible, CLI commands (aws/az/gcloud), step-by-step instructions, Pulumi, ARM/Bicep
4. **Auto-suggest the most critical fix** — proactively say "The #1 priority is rotating the exposed API key on X. Want me to generate the rotation script?"

When the user selects a format:
- Generate the remediation code immediately (secret rotation, bucket policies, encryption configs, access controls)
- Write it to a file: `secure-data-<asset-name>.<ext>` (e.g., `.tf`, `.yml`, `.sh`)
- Include verification commands
- Suggest the next data exposure to fix after the first one is done

**Format mapping:**
| User says | Extension | Template |
|-----------|-----------|----------|
| Terraform | `.tf` | HCL with bucket policy / encryption / KMS resources |
| CloudFormation | `.cfn.yaml` | YAML template with security resources |
| Ansible | `.yml` | Playbook with data protection tasks |
| CLI | `.sh` | Shell script with aws/az/gcloud CLI commands |
| Instructions | inline | Numbered step-by-step console walkthrough |
| Pulumi | `.ts` | TypeScript Pulumi program |
| ARM/Bicep | `.bicep` | Bicep template |

## Output Format

### Layer 1: Dashboard

```
═══════════════════════════════════════════════════════════════════
DATA EXPOSURE REPORT — <scope>
<date> | <account scope>
═══════════════════════════════════════════════════════════════════

DATA POSTURE: <assessment — 1 line>

┌─────────────────────────────────────────────────────────────────┐
│  TOTAL FINDINGS    <N> data exposure alerts                     │
│  CRITICAL          <N> — immediate breach risk                  │
│  HIGH              <N> — significant exposure                   │
│  SECRETS           <N> exposed credentials/API keys/tokens      │
│  PII               <N> assets with personally identifiable data │
│  PUBLIC DATA       <N> publicly accessible data stores          │
│  UNENCRYPTED       <N> data stores without encryption           │
│  CROWN JEWELS      <N> data findings on critical assets         │
│  COMPLIANCE        <frameworks with data requirements>          │
└─────────────────────────────────────────────────────────────────┘

TOP DATA RISKS:
  [1] <alert-id> — <title> (score: <X.X>)
      <asset> | <data type> | <exposure: public/internal>
  [2] <alert-id> — <title> (score: <X.X>)
      <asset> | <data type> | <exposure>
  [3] <alert-id> — <title> (score: <X.X>)
      <asset> | <data type> | <exposure>
  [4] <alert-id> — <title> (score: <X.X>)
  [5] <alert-id> — <title> (score: <X.X>)

RECOMMENDED ACTION:
  Priority #1: <top data risk — e.g., "Rotate the exposed API
  key on <asset> and move to Secrets Manager.">
  I can generate the fix right now.

  What format? terraform | cloudformation | ansible | cli |
  instructions | pulumi | arm/bicep

═══════════════════════════════════════════════════════════════════
Or drill down: secrets | pii | public data | unencrypted |
compliance | accounts | remediation plan | full
═══════════════════════════════════════════════════════════════════
```

### Layer 2: Drill-Down Sections

#### "secrets" — Exposed Secrets & Credentials

```
───────────────────────────────────────────────────────────────────
SECRETS & CREDENTIALS — Exposed
───────────────────────────────────────────────────────────────────

CRITICAL (rotate immediately):
  <alert-id>  <score>  <title>
              Asset: <asset> (<type>) in <account>
              Secret type: <API key / password / token / connection string>
              Location: <file path / env var / config>
              Exposure: <public / internal>
              Fix: Rotate secret, move to secrets manager

  ...

HIGH (rotate soon):
  ...

SUMMARY:
  Total exposed secrets: <N>
  Public-facing: <N> (CRITICAL)
  Internal only: <N> (HIGH)
  Types: <breakdown by secret type>

RECOMMENDED ACTIONS:
  1. Rotate all publicly exposed secrets NOW
  2. Move secrets to AWS Secrets Manager / Azure Key Vault / GCP Secret Manager
  3. Scan code repos for committed secrets
  4. Implement secret detection in CI/CD pipeline

FIX NOW:
  I'll generate rotation scripts and Secrets Manager configs.
  Choose format: terraform | cloudformation | ansible | cli |
  instructions | pulumi | arm/bicep

───────────────────────────────────────────────────────────────────
```

#### "pii" — PII Exposure

```
───────────────────────────────────────────────────────────────────
PII EXPOSURE — Personally Identifiable Information
───────────────────────────────────────────────────────────────────

  <alert-id>  <score>  <title>
              Asset: <asset> in <account>
              PII types: <names / emails / SSNs / addresses / phone>
              Records: <estimated count if available>
              Encrypted: YES/NO
              Access: <public / internal / restricted>
              Compliance: <GDPR / HIPAA / PCI affected>

  ...

COMPLIANCE IMPACT:
  GDPR: <N> findings with EU personal data
  HIPAA: <N> findings with health data
  PCI DSS: <N> findings with payment data

───────────────────────────────────────────────────────────────────
```

#### "public data" — Publicly Accessible Data Stores

```
───────────────────────────────────────────────────────────────────
PUBLIC DATA STORES — Internet Accessible
───────────────────────────────────────────────────────────────────

  ⚠ <storage name> (<type>) in <account>
    Access: PUBLIC READ / PUBLIC WRITE / PUBLIC LIST
    Content: <data types detected>
    Sensitive: YES — <what sensitive data>
    Encryption: <encrypted / NOT encrypted>
    Fix: <specific action — remove public access, add auth>

  ⚠ <database name> (<type>) in <account>
    Access: Internet-facing on port <port>
    Auth: <strong / weak / default / none>
    Content: <data types>
    Fix: <action>

LOCK IT DOWN:
  I can generate bucket policies, access controls, and
  encryption configs. Choose format: terraform | cloudformation |
  ansible | cli | instructions | pulumi | arm/bicep

───────────────────────────────────────────────────────────────────
```

#### "unencrypted" — Unencrypted Data Stores

```
───────────────────────────────────────────────────────────────────
UNENCRYPTED DATA STORES
───────────────────────────────────────────────────────────────────

  <storage/database name> (<type>) in <account>
    Contains: <data types>
    Sensitive data: YES/NO
    Encryption at rest: MISSING
    Encryption in transit: <YES/NO>
    Fix: Enable <SSE-S3/SSE-KMS/AES-256/TDE>

  ...

SUMMARY:
  Total unencrypted: <N>
  With sensitive data: <N> (PRIORITY)
  Without sensitive data: <N> (still fix)

ENABLE ENCRYPTION:
  I'll generate encryption configs for all unencrypted stores.
  Choose format: terraform | cloudformation | ansible | cli |
  instructions | pulumi | arm/bicep

───────────────────────────────────────────────────────────────────
```

#### "compliance" — Data Protection Compliance

```
───────────────────────────────────────────────────────────────────
DATA PROTECTION COMPLIANCE
───────────────────────────────────────────────────────────────────

  Framework          Score    Data Controls    Status
  ─────────────────────────────────────────────────────
  PCI DSS v4.0       <X>%    <N> failing      ⚠ GAPS
  HIPAA              <X>%    <N> failing      ⚠ GAPS
  GDPR               <X>%    <N> failing      ⚠ GAPS
  SOC 2              <X>%    <N> failing      ✓ OK
  ...

DATA-SPECIFIC CONTROL FAILURES:
  <control> — <description> (<N> assets)
  <control> — <description> (<N> assets)
  ...

───────────────────────────────────────────────────────────────────
```

#### "accounts" — Data Risk by Account

```
───────────────────────────────────────────────────────────────────
DATA RISK BY ACCOUNT
───────────────────────────────────────────────────────────────────

  Account              Secrets    PII    Public    Unencrypted
  ────────────────────────────────────────────────────────────
  <account-1>          <N>        <N>    <N>       <N>
  <account-2>          <N>        <N>    <N>       <N>
  ...

WORST ACCOUNT: <account> — <why>

───────────────────────────────────────────────────────────────────
```

#### "remediation plan" — Prioritized Data Protection Plan

```
───────────────────────────────────────────────────────────────────
DATA PROTECTION REMEDIATION PLAN
───────────────────────────────────────────────────────────────────

PHASE 1: STOP THE BLEEDING (immediate)
  [ ] Rotate <N> publicly exposed secrets
  [ ] Remove public access from <N> data stores with sensitive data
  [ ] Add authentication to <N> exposed databases

PHASE 2: ENCRYPT EVERYTHING (this week)
  [ ] Enable encryption at rest on <N> data stores
  [ ] Enable encryption in transit where missing
  [ ] Move <N> secrets to managed secrets service

PHASE 3: ACCESS CONTROLS (this month)
  [ ] Implement least-privilege access to data stores
  [ ] Enable audit logging on all sensitive data stores
  [ ] Set up automated secret rotation

PHASE 4: GOVERNANCE (ongoing)
  [ ] Implement data classification policy
  [ ] Deploy DLP controls
  [ ] Set up continuous monitoring for new data exposure
  [ ] Regular compliance audits

ESTIMATED IMPACT:
  Phase 1: Eliminates <N> critical data exposure alerts
  Phase 2: Resolves <N> encryption compliance failures
  Phase 3: Reduces unauthorized access risk by ~<X>%

START NOW:
  Tell me which phase to begin and your preferred format.
  I'll generate implementation code for each fix.

  Format: terraform | cloudformation | ansible | cli |
  instructions | pulumi | arm/bicep

───────────────────────────────────────────────────────────────────
```

#### "full" — Everything Expanded

Show all sections in order.

## Edge Cases

### No Sensitive Data Found
```
✅ No exposed sensitive data detected.

Your data protection posture appears clean. Consider:
  • Verify Orca DSPM scanning is enabled for all accounts
  • Check data classification settings
  • This scan covers known patterns — custom sensitive data may need custom rules
```

### Massive Data Exposure (> 50 findings)
```
⚠ Significant data exposure: <N> findings detected.

Showing top 10 by risk. This indicates a systemic data protection gap.

Recommendations:
  1. Prioritize: Fix publicly exposed data stores first
  2. Automate: Deploy encryption-by-default policies
  3. Prevent: Add pre-commit hooks for secret detection
  4. Monitor: Set up real-time alerts for new public data stores
```

### Secret Already Rotated
Some secrets may already be rotated but the alert remains open. Note:
```
Note: Verify if this secret has already been rotated.
If rotated, the alert may close on next Orca scan.
If not rotated, treat as active exposure.
```

## MCP Tools Used

### Primary Tools

| Tool | Purpose | Parameter |
|------|---------|-----------|
| `discovery_search` | Find data exposure findings | `search_phrase`, `limit` |
| `get_asset_related_alerts_summary` | All alerts on data-holding assets | `asset_id` (UUID) |
| `get_asset_crown_jewel_info` | Crown jewel status of data stores | `group_unique_id` |
| `get_enabled_compliance_frameworks` | Data protection compliance scores | optional `filters` |

### Secondary Tools

| Tool | Purpose | When |
|------|---------|------|
| `get_asset_by_id` | Full asset details | Drill-down on specific data store |
| `get_compliance_framework_control_tests` | Failing data controls | "compliance" drill-down |
| `search_cdr_events` | Who accessed the data store | Investigation |
| `get_linked_entities_mapping` | What connects to the data store | Access analysis |

### Parameter Notes

- `discovery_search` max 10 results per query — use multiple queries with different search phrases to cover all data types
- Crown jewel check is important for data stores — databases and storage with critical data are often crown jewels
- Compliance frameworks with data protection requirements: PCI DSS, HIPAA, GDPR, SOC 2

## Implementation Notes

1. **6 parallel discovery_search queries** cover secrets, PII, public data, unencrypted stores, internet-facing data, and certificates.
2. **Data type classification** is key — different data types have different compliance implications.
3. **Public + sensitive is always CRITICAL** — publicly accessible data with sensitive content is the highest priority.
4. **Secrets should be rotated, not just hidden** — always recommend rotation for exposed credentials.
5. **Compliance mapping** adds business context — "this violates PCI DSS" gets more traction than "this is exposed".
6. **Link to other skills** — suggest `/orca-alert-triage <alert-id>` for individual findings, `/orca-exposure-map` for full attack surface, `/orca-asset-profile` for data store details.
7. **Remediation plan** should be phased — don't overwhelm with 50 things to fix at once.
