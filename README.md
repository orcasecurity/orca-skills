<div align="center">

<p align="center">
  <img src="assets/orca_ai_skills_banner.png" alt="Orca Skills" width="700">
</p>

<a href="LICENSE" target="_blank"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
<a href="https://docs.anthropic.com/en/docs/claude-code" target="_blank"><img src="https://img.shields.io/badge/Claude_Code-compatible-blueviolet" alt="Claude Code"></a>
<a href="https://cursor.com" target="_blank"><img src="https://img.shields.io/badge/Cursor-compatible-blue" alt="Cursor"></a>
<a href="https://openai.com/codex/" target="_blank"><img src="https://img.shields.io/badge/Codex-compatible-green" alt="Codex"></a>
<a href="https://docs.orcasecurity.io/docs/mcp-integration" target="_blank"><img src="https://img.shields.io/badge/MCP-Orca_Security-00D4AA" alt="MCP"></a>

</div>

---

### Table of Contents
- [Skills Overview](#skills-overview)
- [Installation](#installation)
- [MCP Configuration](#mcp-configuration)
- [Skill Details](#skill-details)
- [Testing](#testing)
- [Contributing](#contributing)
- [Support](#support)
- [License](#license)
- [Credits](#credits)


## Skills Overview

| Skill | Question It Answers |
|-------|-------------------|
| [`orca-alert-triage`](#orca-alert-triage) | "What is this alert and should I care?" |
| [`orca-impact-analysis`](#orca-impact-analysis) | "If I fix this, what else closes — and what breaks?" |
| [`orca-config-origin`](#orca-config-origin) | "Who did this, how was it deployed, and what introduced the issue?" |
| [`orca-morning-briefing`](#orca-morning-briefing) | "What happened while I was away, and what needs my attention?" |
| [`orca-asset-profile`](#orca-asset-profile) | "Tell me everything about this asset in one place." |
| [`orca-compliance-gap`](#orca-compliance-gap) | "Where are we failing, what's the fastest path to improve?" |
| [`orca-data-exposure`](#orca-data-exposure) | "Where is our sensitive data, is it protected, and what's at risk?" |
| [`orca-exposure-map`](#orca-exposure-map) | "What can an attacker see from outside?" |
| [`orca-identity-review`](#orca-identity-review) | "Is this identity overprivileged, and what's the blast radius?" |
| [`orca-investigate`](#orca-investigate) | "What happened, who did it, and how far did they get?" |
| [`orca-cloud-cost-optimizer`](#orca-cloud-cost-optimizer) | "Where are we overspending and what should we fix first?" |

### Recommended Workflows

> **Daily ops:** Morning briefing → Triage → Asset profile → Impact analysis → Config origin → Fix
>
> **Proactive posture:** Compliance gaps → Exposure map → Data exposure → Identity review
>
> **Incident response:** Investigate → Identity review → Asset profile → Contain and remediate

## Installation

### Claude Code CLI

```bash
/plugin marketplace add orcasecurity/orca-skills
```

**Next step:** Configure the Orca Security MCP server (see [MCP Configuration](#mcp-configuration) below).

### Claude Desktop

Add the marketplace to your Claude Desktop configuration, then install skills from the marketplace UI.

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/orcasecurity/orca-skills.git
cd orca-skills

# Copy skills to your skills directory
cp -r skills/* ~/.claude/skills/
```

## MCP Configuration

**Required:** These skills need the Orca Security MCP server to access your environment data.

Add to your `.mcp.json` (in project root or `~/.claude/.mcp.json`):

```json
{
  "mcpServers": {
    "orca-security": {
      "type": "http",
      "url": "https://api.orcasecurity.io/mcp",
      "headers": {
        "Authorization": "Token YOUR_ORCA_API_TOKEN"
      }
    }
  }
}
```

**Get your API token:** [Orca API Authentication Guide](https://docs.orcasecurity.io/docs/managing-api-tokens)  
**MCP Integration Docs:** [Orca MCP Setup](https://docs.orcasecurity.io/docs/orca-security-mcp-server)


## Skill Details

<details>
<summary><strong><a id="orca-alert-triage"></a>orca-alert-triage</strong></summary>

**"What is this alert and should I care?"**

Intelligent alert triage that transforms raw Orca alerts into analyst-friendly summaries with behavioral timelines, risk assessment, and progressive disclosure. Supports anomalies, vulnerabilities, malware, and misconfigurations.

**Features:**
- Verdict-first summaries with confidence scoring (Likely Benign, Active Threat, Patchable Risk, etc.)
- Visual timeline analysis showing alert behavior, status changes, and remediation blockers
- Blast radius calculation with related asset and alert correlation
- Orca-first automated investigation — queries CloudTrail, related alerts, attack paths before suggesting manual steps
- Remediation format picker — choose Terraform, CloudFormation, ARM/Bicep, Pulumi, CLI, or step-by-step instructions
- Code output written to files automatically (e.g., `remediate-orca-3456789.tf`)

**Usage:**
```bash
# Triage an alert
/orca-alert-triage orca-1234567

# Or use natural language
triage alert orca-9012345
explain orca-2345678
```

**Follow-up commands** (type after triage):
```
investigate    # Automated Orca-first investigation with manual steps only for gaps
evidence       # Detailed metadata, hashes, links, MITRE ATT&CK mappings
remediate      # Choose output format, then get remediation written to a file
correlate      # Related alerts and attack pattern analysis
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
ANOMALY DETECTION: Unusual User Agent on EKS Node Role
═══════════════════════════════════════════════════════════════════

VERDICT: Likely Benign | CONFIDENCE: 90% | ACTION: Review & Close | TIMELINE: 48h

WHAT HAPPENED:
  EKS node role used a new AWS SDK version (boto3/1.35.x → 1.36.x)
  during routine cluster operations. Single occurrence, no recurrence.

WHY IT MATTERS:
  Risk Level: Low (Orca Score: 3.0)
  Same tool family, minor version bump, clean 30-day baseline.
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-alert-triage/)

</details>


<details>
<summary><strong><a id="orca-impact-analysis"></a>orca-impact-analysis</strong></summary>

**"If I fix this, what closes — and what breaks?"**

Analyzes the full remediation impact of fixing a single Orca alert — both the security gains (alerts closed, attack paths broken, compliance passed) AND the operational risk (production workflows, automation, services that might break).

**Features:**
- Cascade analysis — maps all alerts that share the same root cause as the target alert
- Attack path impact — identifies kill chains that break when the alert is fixed
- Compliance score change — shows before/after compliance percentages per framework
- Environment-wide view — finds the same issue across other assets and accounts
- Breakage simulation — analyzes CloudTrail/CDR events and effective permissions to identify production dependencies
- Executive verdict — clear FIX NOW / FIX WITH CAUTION / PLAN FIX / DEFER recommendation balancing security gain vs. operational risk
- Safe deployment checklist — steps to apply the fix without breaking production

**Usage:**
```bash
# Analyze impact of fixing an alert
/orca-impact-analysis orca-3456789

# Or use natural language
what's the impact of fixing orca-5678901?
if I fix orca-0123456, what else closes?
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
IMPACT ANALYSIS — orca-3456789
Root Account Without MFA Enabled
"If I enable MFA on root, what closes — and what breaks?"
═══════════════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│  VERDICT: FIX NOW                                               │
│                                                                 │
│  Security gain:   HIGH — 2 critical alerts, 3 attack paths      │
│  Breakage risk:   LOW — no automation uses root console login   │
│  Blast radius:    2 alerts, 3 attack paths, 8 frameworks        │
└─────────────────────────────────────────────────────────────────┘

REMEDIATION IMPACT SUMMARY:
  Alerts directly closed:    2 (including this one)
  Attack paths broken:       3
  Compliance frameworks:     8 frameworks improved

  COMPLIANCE SCORE CHANGE:
    Framework              Current    After Fix    Change
    ─────────────────────────────────────────────────────
    PCI DSS v4.0.1          87%   →    89%         +2%
    NIST 800-53             91%   →    93%         +2%

BREAKAGE RISK:
  [ok] EKS automation — uses access keys (MFA doesn't apply)
  [ok] Orca scanner — uses service role (not affected)
  [x]  Unknown Kali agent — SHOULD break (that's the goal)

BOTTOM LINE: High-leverage, low-risk fix. Apply immediately.
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-impact-analysis/)

</details>


<details>
<summary><strong><a id="orca-config-origin"></a>orca-config-origin</strong></summary>

**"Who did this, how was it deployed, and what introduced the issue?"**

Traces any Orca alert — misconfiguration, vulnerability, sensitive data, or anomaly — back through cloud audit logs, Orca CodeOrigins (Shift Left), and asset metadata to find who created the resource, what tool deployed it, what introduced the specific issue, and a full timeline from deployment to alert detection.

**Features:**
- Alert category classification — traces origin differently for misconfigurations (config IS the cause), vulnerabilities (package is the cause), sensitive data (image/script placed the secret), and anomalies (actor IS the finding)
- CodeOrigins / Shift Left integration — extracts exact IaC source code (repo, file, line numbers, git blame author/commit)
- Audit log tracing via Orca CDR (CloudTrail, Azure Activity Log, GCP Audit Log)
- Full visual timeline from IaC code commit → resource creation → issue introduction → alert detection, with exposure window calculation
- Split ownership — distinguishes resource owner (who deployed) from issue owner (who should fix)
- IaC drift detection — flags resources created by IaC but later modified via Console
- Category-aware remediation routing — tells you WHERE to apply the fix based on alert type AND deployment method

**Usage:**
```bash
# Trace origin of any alert
/orca-config-origin orca-3456789

# Or use natural language
who created this misconfiguration? orca-3456789
trace back orca-5678901
where did this config come from? orca-3364845
```

**Example output (vulnerability alert):**
```
═══════════════════════════════════════════════════════════════════
CONFIG ORIGIN — orca-4567890
Apache Log4j Remote Code Execution Vulnerability (CVE-2021-45046)
═══════════════════════════════════════════════════════════════════

ASSET: web-bastion-host (AwsEc2Instance) in 123456789012
ISSUE: log4j-core v2.3 installed — critically vulnerable to RCE

┌─────────────────────────────────────────────────────────────────┐
│  DEPLOYED BY: Terraform (module "ec2_unpatched")                │
│  OWNER:       Alex Chen (alex@example-corp.com)                       │
│  ROOT CAUSE:  user_data script installs log4j-core-2.3.jar     │
│  LAST CHANGE: 2025-12-01 (137 days ago)                         │
│  METHOD:      Terraform → module "ec2/unpatched_ubuntu"         │
└─────────────────────────────────────────────────────────────────┘

TIMELINE:
  2024-06-23  ● Terraform code committed                  Alex Chen
              │ file: ec2.tf:71-80, commit: abc1234
  2025-12-01  ● Instance created — user_data installs log4j 2.3
              │ ⚠ VULNERABILITY INTRODUCED HERE
  2025-12-01  ● Alert detected by Orca (73 min after creation)
  2026-04-17  ● Today — 137 days exposed, still open

REMEDIATION ROUTING:
  ⚠ The fix is NOT in ec2.tf — the Terraform deploys correctly.
  FIX IN: module.scripts.ec2_unpatched (the user_data script)
  → Update script to install log4j-core ≥ 2.16.0
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-config-origin/)

</details>


<details>
<summary><strong><a id="orca-morning-briefing"></a>orca-morning-briefing</strong></summary>

**"What happened while I was away, and what needs my attention?"**

Daily security briefing for the last 24-72 hours. Scans your environment for new critical alerts, escalated findings, attack path changes, compliance drift, exposure changes, CDR activity anomalies, crown jewel risks, and aging unactioned alerts — then presents it all as a scannable dashboard with drill-down sections.

**Features:**
- Environment pulse — quick health assessment (stable, degrading, needs attention)
- New critical/high alerts with priority ranking
- Escalated alerts — severity increases and reopened findings
- Compliance drift — framework scores that dropped, with account breakdown
- CDR activity overview — event volumes, unusual actors, suspicious patterns
- Crown jewel risk — new alerts on your most critical assets
- Aging criticals — unactioned alerts with Jira ticket status
- Progressive disclosure — dashboard first (~20 lines), drill down by keyword
- Time range support — 24h (daily), 72h (Monday morning), week (PTO return)

**Usage:**
```bash
# Daily briefing (last 24 hours)
/orca-morning-briefing

# Monday morning (last 72 hours)
/orca-morning-briefing 72h

# Weekly review
/orca-morning-briefing week
```

**Drill-down keywords** (type after briefing):
```
alerts         # Full list of new critical/high alerts
escalated      # Alerts that changed severity or reopened
attack paths   # New/worsened attack paths with stories
compliance     # Framework scores, trends, worst accounts
exposure       # Internet-facing assets with critical alerts
crown jewels   # New alerts on crown jewel assets
aging          # Unactioned critical alerts sorted by age
activity       # CDR event volumes, unusual actors
new types      # Alert types seen for the first time
trends         # Week-over-week comparison, top affected assets
full           # All sections expanded (for reports/handoffs)
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
MORNING BRIEFING — 2026-04-17
Last 24 hours | Account: 123456789012
═══════════════════════════════════════════════════════════════════

PULSE: ⚠ NEEDS ATTENTION — 3 new critical alerts

┌─────────────────────────────────────────────────────────────────┐
│  NEW ALERTS         12 total (3 critical, 4 high, 5 medium)    │
│  ESCALATED          2 alerts changed severity or reopened       │
│  ATTACK PATHS       1 new, 2 worsened                           │
│  COMPLIANCE         PCI DSS dropped 2%                          │
│  EXPOSURE           1 asset newly internet-facing               │
│  CROWN JEWELS       1 new alert on critical asset               │
│  AGING CRITICALS    4 critical alerts open > 7 days             │
│  CDR ACTIVITY       Elevated — 3.2k events (normal: ~1k)       │
└─────────────────────────────────────────────────────────────────┘

TOP PRIORITIES:
  [1] orca-4567890 — Log4j RCE on public bastion (137d open!)
  [2] orca-6789012 — S3 bucket publicly accessible (new today)
  [3] orca-7890123 — SendGrid API key exposed in container
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-morning-briefing/)

</details>


<details>
<summary><strong><a id="orca-asset-profile"></a>orca-asset-profile</strong></summary>

**"Tell me everything about this asset in one place."**

Full 360° security profile of any cloud asset — all open alerts (grouped by category), attack paths, compliance violations, permissions, network exposure, sensitive data, CDR activity summary, crown jewel status, and linked entities.

**Features:**
- Complete asset identity — name, type, account, region, IPs, OS, tags, creation date, IaC source
- Risk summary with Orca Score, crown jewel status, and exposure classification
- Alerts grouped by category — vulnerabilities, misconfigurations, malware, sensitive data, anomalies, IAM
- Attack path mapping — kill chains with the asset's role (entry point, pivot, target)
- Compliance framework violations per asset
- Effective permissions analysis (AWS IAM assets) with used vs unused breakdown
- CDR activity summary — 30-day event volumes, top actions, unique actors
- Linked entities — connected roles, instances, buckets, databases, load balancers
- Proactive remediation — suggests the highest-impact fix and offers to generate code in Terraform, CloudFormation, Ansible, CLI, Pulumi, or ARM/Bicep

**Usage:**
```bash
# Profile an asset by name, ID, or ARN
/orca-asset-profile web-bastion-host
/orca-asset-profile i-1234567890abcdef0

# Or use natural language
tell me about web-bastion-host
asset risk for vm-chain3-1
```

**Drill-down keywords** (type after profile):
```
alerts         # All alerts by category
attack paths   # Kill chains with this asset
compliance     # Framework violations
permissions    # IAM analysis (used vs unused)
exposure       # Network exposure details
activity       # CDR events (last 30 days)
linked         # Connected assets
code origin    # IaC source mapping
full           # All sections expanded
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
ASSET PROFILE — web-bastion-host
AwsEc2Instance | 123456789012 | us-east-1 | running
═══════════════════════════════════════════════════════════════════

RISK: Orca Score 9.0 (Critical) | Crown Jewel: NO

┌─────────────────────────────────────────────────────────────────┐
│  ALERTS        12 total (3 critical, 4 high, 5 medium)         │
│  ATTACK PATHS  4 active kill chains                             │
│  COMPLIANCE    6 frameworks, 18 failing controls                │
│  EXPOSURE      public_facing | ports: 22, 443                   │
│  SENSITIVE     API keys, credentials                            │
│  PERMISSIONS   overprivileged (via instance profile)            │
│  CDR ACTIVITY  847 events in 30d (elevated)                     │
│  LINKED        9 connected assets                               │
└─────────────────────────────────────────────────────────────────┘

TOP ALERTS:
  [1] orca-4567890 — Log4j RCE (score: 9.0, vulnerability)
  [2] orca-7890123 — SendGrid API key exposed (score: 8.5, sensitive data)
  [3] orca-3456789 — Root account without MFA (score: 8.0, misconfiguration)

RECOMMENDED ACTION:
  The highest-impact fix is orca-4567890 (Log4j RCE on a public
  asset). I can generate remediation code right now.

  What format? terraform | cloudformation | cli | instructions
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-asset-profile/)

</details>


<details>
<summary><strong><a id="orca-compliance-gap"></a>orca-compliance-gap</strong></summary>

**"Where are we failing, what's the fastest path to improve?"**

Deep compliance gap analysis for any framework — failing controls ranked by blast radius, quick wins (single-fix controls), account breakdown, score trends, and a phased remediation plan with projected score improvements.

**Features:**
- Framework overview with scores, trends, and worst/best identification
- Failing controls ranked by cross-framework impact and asset count
- Quick win detection — single-config fixes that improve multiple frameworks at once
- Account/business unit breakdown — who owns the worst gaps
- 30-day compliance trend analysis — improving, stable, or degrading
- Phased remediation plan — quick wins (days), systematic fixes (weeks), architectural changes (months)
- Projected score improvements per phase
- Proactive remediation — offers to generate fix code for any control in Terraform, CloudFormation, Ansible, CLI, Pulumi, or ARM/Bicep

**Usage:**
```bash
# All frameworks overview
/orca-compliance-gap

# Specific framework deep-dive
/orca-compliance-gap PCI DSS
/orca-compliance-gap CIS AWS

# Or use natural language
how's our PCI compliance?
what's failing in SOC 2?
quick wins for compliance
```

**Drill-down keywords** (type after analysis):
```
controls         # All failing controls ranked by impact
quick wins       # Fastest path to score improvement
accounts         # Gap breakdown by account
trends           # 30-day score history
remediation plan # Phased fix plan with projections
full             # All sections expanded
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
COMPLIANCE GAP ANALYSIS — All Frameworks
2026-04-17 | All accounts
═══════════════════════════════════════════════════════════════════

POSTURE: Moderate — 3 frameworks below 85% target

┌─────────────────────────────────────────────────────────────────┐
│  FRAMEWORKS     8 enabled                                       │
│  AVG SCORE      84%                                             │
│  WORST          HIPAA at 71%                                    │
│  BEST           CIS AWS at 94%                                  │
│  TREND (30d)    degrading — PCI dropped 2%                      │
│  QUICK WINS     6 controls fixable with single changes          │
│  WORST ACCOUNT  123456789012 — 76% avg score                   │
└─────────────────────────────────────────────────────────────────┘

TOP FAILING CONTROLS (highest impact):
  [1] Enable MFA for root — failing on 3 accounts, affects 5 frameworks
  [2] Encrypt EBS volumes — failing on 12 assets, affects 4 frameworks
  [3] Restrict SSH access — failing on 8 assets, affects 4 frameworks

RECOMMENDED ACTION:
  The fastest score improvement: enable MFA for root —
  affects 3 accounts across 5 frameworks. I can generate the fix.

  What format? terraform | cloudformation | cli | instructions
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-compliance-gap/)

</details>


<details>
<summary><strong><a id="orca-data-exposure"></a>orca-data-exposure</strong></summary>

**"Where is our sensitive data, is it protected, and what's at risk?"**

DSPM (Data Security Posture Management) view: discovers sensitive data across the environment — secrets, PII, credentials, API keys, financial data — identifies unprotected or exposed data stores, ranks data risks by exposure level, and generates a remediation plan.

**Features:**
- Full DSPM scan — secrets, PII, credentials, API keys, certificates, financial data
- Risk classification — critical (public + sensitive), high (internal + vulnerable), medium, low
- Data type grouping — secrets & credentials, PII, financial data, health data, private keys
- Public data store detection — S3 buckets, databases, file shares with public access
- Unencrypted data store identification with encryption recommendations
- Compliance context — PCI DSS, HIPAA, GDPR, SOC 2 data protection control status
- Account breakdown of data risk distribution
- Phased remediation plan — stop the bleeding, encrypt everything, access controls, governance
- Proactive remediation — generates rotation scripts, bucket policies, encryption configs in Terraform, CloudFormation, Ansible, CLI, Pulumi, or ARM/Bicep

**Usage:**
```bash
# Full DSPM report
/orca-data-exposure

# Filter by type or account
/orca-data-exposure secrets
/orca-data-exposure account 123456789012

# Or use natural language
where's our sensitive data?
find exposed API keys
what PII is at risk?
```

**Drill-down keywords** (type after report):
```
secrets          # Exposed secrets & credentials
pii              # PII exposure details
public data      # Publicly accessible data stores
unencrypted      # Data stores without encryption
compliance       # Data protection compliance status
accounts         # Data risk by account
remediation plan # Phased data protection plan
full             # All sections expanded
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
DATA EXPOSURE REPORT — All Accounts
2026-04-17 | Full environment
═══════════════════════════════════════════════════════════════════

DATA POSTURE: At Risk — 3 critical data exposures on public assets

┌─────────────────────────────────────────────────────────────────┐
│  TOTAL FINDINGS    24 data exposure alerts                      │
│  CRITICAL          3 — immediate breach risk                    │
│  HIGH              8 — significant exposure                     │
│  SECRETS           11 exposed credentials/API keys/tokens       │
│  PII               5 assets with personally identifiable data   │
│  PUBLIC DATA       2 publicly accessible data stores            │
│  UNENCRYPTED       6 data stores without encryption             │
│  CROWN JEWELS      2 data findings on critical assets           │
│  COMPLIANCE        PCI DSS, HIPAA gaps on data controls         │
└─────────────────────────────────────────────────────────────────┘

TOP DATA RISKS:
  [1] orca-7890123 — SendGrid API key in container image (score: 8.5)
      web-bastion-host | credential | public-facing
  [2] orca-8901234 — AWS access key in environment variable (score: 8.0)
      ci-build-server | infrastructure secret | internal
  [3] orca-6789012 — S3 bucket publicly accessible (score: 7.5)
      s3-data-lake-prod | PII + financial data | public

RECOMMENDED ACTION:
  Priority #1: Rotate the SendGrid API key on web-bastion-host and
  move to Secrets Manager. I can generate the rotation script.

  What format? terraform | cloudformation | cli | instructions
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-data-exposure/)

</details>


<details>
<summary><strong><a id="orca-exposure-map"></a>orca-exposure-map</strong></summary>

**"What can an attacker see from outside?"**

External attack surface mapping: discovers all internet-facing assets, ranks them by exploitability from an attacker's perspective, groups by attack vector (exposed services, public storage, vulnerable web apps, open management ports), and maps outside-in kill chains to crown jewels.

**Features:**
- Full external attack surface inventory — internet-facing assets ranked by risk
- Attacker-perspective ranking — "how would an attacker prioritize these targets?"
- Attack vector grouping — easy wins, web apps, management ports, public data, lateral movement entry points
- Outside-in attack path mapping — from exposed asset through pivots to crown jewels
- Exposed management interfaces (SSH, RDP, admin panels) with authentication status
- Public data store detection (S3, databases, file shares)
- Account-level exposure breakdown
- Proactive remediation — generates security group rules, bucket policies, WAF configs in Terraform, CloudFormation, Ansible, CLI, Pulumi, or ARM/Bicep

**Usage:**
```bash
# Full attack surface map
/orca-exposure-map

# Filter by account or vector
/orca-exposure-map account 123456789012
/orca-exposure-map web services

# Or use natural language
what's exposed to the internet?
show me our attack surface
what can an attacker see?
```

**Drill-down keywords** (type after map):
```
easy wins      # Immediately exploitable — fix first
web apps       # Exposed web applications
management     # SSH, RDP, admin panels
data           # Public data stores
attack paths   # Outside-in kill chains
accounts       # Exposure by account
all assets     # Complete exposed asset list
full           # All sections expanded
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
EXPOSURE MAP — External Attack Surface
2026-04-17 | All accounts
═══════════════════════════════════════════════════════════════════

SURFACE: Moderate — 4 immediately exploitable targets

┌─────────────────────────────────────────────────────────────────┐
│  EXPOSED ASSETS     18 internet-facing                          │
│  CRITICAL RISK      4 immediately exploitable                   │
│  HIGH RISK          7 exploitable with effort                   │
│  PUBLIC STORAGE     2 buckets/blobs publicly accessible         │
│  EXPOSED MGMT       3 SSH/RDP/admin panels                      │
│  EXPOSED DATABASES  1 database reachable from internet          │
│  CROWN JEWELS       2 exposed critical assets                   │
│  ATTACK PATHS       5 outside-in kill chains                    │
└─────────────────────────────────────────────────────────────────┘

TOP TARGETS (attacker's priority list):
  [1] web-bastion-host — Log4j RCE + public SSH (score: 9.0)
      AwsEc2Instance | 54.210.xx.xx | ports: 22, 443, 8080
  [2] s3-data-lake-prod — public S3 with PII (score: 7.5)
      AwsS3Bucket | public-read | contains financial data
  [3] ci-build-server — exposed admin panel (score: 7.0)
      AwsEc2Instance | 52.90.xx.xx | ports: 8080, 50000

RECOMMENDED ACTION:
  Priority #1: Lock down web-bastion-host — patch Log4j and
  restrict SSH to VPN CIDR. I can generate the fix.

  What format? terraform | cloudformation | cli | instructions
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-exposure-map/)

</details>


<details>
<summary><strong><a id="orca-identity-review"></a>orca-identity-review</strong></summary>

**"Is this identity overprivileged, and what's the blast radius?"**

IAM identity analysis: compares effective permissions vs actual CloudTrail usage, identifies overprivileged access, maps lateral movement potential (role assumptions, cross-account reach), and generates least-privilege policy recommendations.

**Features:**
- Effective permissions analysis — total actions across all services
- Used vs unused permission comparison from 30-day CloudTrail data
- Overprivilege classification — severe, high, moderate, or minimal
- Dangerous permission detection — iam:*, sts:AssumeRole(broad), s3:*, kms:Decrypt, etc.
- Lateral movement mapping — assumable roles, cross-account reach, service access
- Attack path analysis — kill chains passing through this identity
- CDR activity patterns — source IPs, user-agents, time patterns
- Least-privilege policy recommendation with estimated risk reduction
- Safe deployment checklist — audit mode, testing, monitoring, rollback
- Proactive remediation — generates updated IAM policies in Terraform, CloudFormation, Ansible, CLI, Pulumi, or ARM/Bicep

**Usage:**
```bash
# Review an identity by name or ARN
/orca-identity-review admin-role
/orca-identity-review arn:aws:iam::123456789012:role/ec2-bastion-role

# Or use natural language
is terraform-deploy overprivileged?
review the permissions on admin-role
what can this role access?
```

**Drill-down keywords** (type after review):
```
permissions    # Full permission list (used, unused, dangerous)
usage          # CDR activity details (actions, IPs, agents)
lateral        # Lateral movement analysis
attack paths   # Kill chains through this identity
alerts         # Open alerts on this identity
activity       # 30-day CDR event summary
recommend      # Least-privilege policy recommendation
full           # All sections expanded
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
IDENTITY REVIEW — ec2-bastion-role
AwsIamRole | 123456789012 | arn:aws:iam::123456789012:role/ec2-bastion-role
═══════════════════════════════════════════════════════════════════

VERDICT: OVERPRIVILEGED

┌─────────────────────────────────────────────────────────────────┐
│  PERMISSIONS     312 effective actions across 28 services       │
│  OVERPRIVILEGE   SEVERE — has admin-level access it doesn't use│
│  USED (30d)      47 actions actually used                       │
│  UNUSED          265 actions never used — removal candidates    │
│  DANGEROUS       8 high-risk permissions (iam:*, s3:*, kms:*)  │
│  BLAST RADIUS    28 services, 150+ resources reachable          │
│  LATERAL MOVE    5 roles assumable, 2 accounts reachable        │
│  ATTACK PATHS    3 kill chains through this identity            │
│  ALERTS          4 open (2 critical, 1 high, 1 medium)         │
│  CDR ACTIVITY    847 events in 30d, 47 unique actions           │
│  CROWN JEWEL     NO                                             │
└─────────────────────────────────────────────────────────────────┘

TOP RISK:
  This role has 265 unused permissions including iam:*, enabling
  full privilege escalation if compromised.

RECOMMENDED ACTION:
  Remove 265 unused permissions to reduce blast radius by 85%.
  I can generate the updated least-privilege policy.

  What format? terraform | cloudformation | cli | instructions
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-identity-review/)

</details>


<details>
<summary><strong><a id="orca-investigate"></a>orca-investigate</strong></summary>

**"What happened, who did it, and how far did they get?"**

CDR-powered incident investigation: traces actor activity through Orca CDR (CloudTrail/audit logs), builds session timelines, maps actions to MITRE ATT&CK techniques, clusters related sessions, assesses blast radius, and generates a verdict with containment recommendations.

**Features:**
- Multi-axis investigation — by actor (IAM identity), source IP, target resource, account, or alert
- Session clustering — groups raw events into coherent sessions by actor, IP, and time gaps
- MITRE ATT&CK mapping — maps every action to techniques and tactics with confidence levels
- Kill chain assessment — how many ATT&CK tactics are covered (partial, near-complete, complete)
- Blast radius classification — contained, moderate, broad, or severe
- Persistence detection — new users, access keys, role policies created
- Defense evasion detection — trail deletion, security group changes, logging disabled
- Cross-account activity flagging
- IOC extraction — IPs, user-agents, identities, created resources (copy-paste ready for SOC tools)
- Verdict with confidence — active compromise, probable compromise, suspicious, likely benign, inconclusive
- Proactive containment — generates revocation scripts, isolation configs, detection rules in Terraform, CloudFormation, Ansible, CLI, Pulumi, or ARM/Bicep

**Usage:**
```bash
# Investigate by actor, IP, or resource
/orca-investigate arn:aws:iam::123456789012:role/ec2-bastion-role
/orca-investigate 10.0.1.50
/orca-investigate account 123456789012

# Or use natural language
investigate what this role did in the last 24 hours
trace activity from IP 10.0.1.50
who accessed the prod database?
```

**Drill-down keywords** (type after investigation):
```
timeline       # Chronological event timeline
sessions       # Clustered sessions with assessment
mitre          # MITRE ATT&CK technique mapping
blast radius   # Impact assessment
actions        # All actions summary
resources      # Resources touched
alerts         # Related alerts
iocs           # Indicators of compromise (copy-paste ready)
contain        # Containment recommendations
full           # All sections expanded
```

**Example output:**
```
═══════════════════════════════════════════════════════════════════
INVESTIGATION — ec2-bastion-role
arn:aws:iam::123456789012:role/ec2-bastion-role | Last 24 hours
═══════════════════════════════════════════════════════════════════

VERDICT: SUSPICIOUS | CONFIDENCE: 72%

┌─────────────────────────────────────────────────────────────────┐
│  EVENTS          156 total, 23 unique actions                   │
│  SESSIONS        3 distinct sessions                            │
│  TIME SPAN       04:12 → 16:47 UTC (12h 35m)                  │
│  SERVICES        7 AWS services touched                         │
│  RESOURCES       34 distinct resources accessed                 │
│  SOURCE IPs      2 unique (1 known VPN, 1 unknown)             │
│  USER AGENTS     2 unique (boto3, aws-cli)                      │
│  BLAST RADIUS    MODERATE — multiple services, same account     │
│  MITRE ATT&CK   5 techniques across 4 tactics                  │
│  ALERTS          4 related alerts on involved assets            │
│  ATTACK PATHS    3 kill chains involving this actor             │
└─────────────────────────────────────────────────────────────────┘

EXECUTIVE SUMMARY:
  ec2-bastion-role had 3 sessions in the last 24h. Session 2 came
  from an unknown IP and performed unusual discovery actions across
  S3 and IAM. No persistence or exfiltration detected yet.

MITRE ATT&CK COVERAGE:
  ■ Initial Access    □ Execution    □ Persistence    □ Priv Esc
  □ Defense Evasion   ■ Discovery    □ Lateral Move   ■ Collection
  □ Exfiltration      □ Impact

RECOMMENDED ACTION:
  Investigate the unknown source IP in Session 2. I can generate
  a containment script to restrict this role's permissions.

  What format? terraform | cloudformation | cli | instructions
═══════════════════════════════════════════════════════════════════
```

[Full Documentation →](skills/orca-investigate/)

</details>


<details>
<summary><strong><a id="orca-cloud-cost-optimizer"></a>orca-cloud-cost-optimizer</strong></summary>

**"Where are we overspending and what should we fix first?"**

Analyzes all cloud assets via Orca Security MCP data to identify actionable cost reduction opportunities across compute, databases, storage, networking, and serverless resources. Delivers a dual-audience report: an executive summary with total savings range, and a per-asset action plan with Orca platform links, cloud console links, CLI commands, and projected monthly savings per item.

**Features:**
- 10 optimization patterns: idle resources, rightsizing, generation upgrades, reserved instances, spot migration, database sizing, Multi-AZ in non-prod, EBS gp2→gp3, S3/object tiering, networking cleanup
- Dual-audience output — executive summary (top and bottom of report) plus engineer-ready implementation steps
- Every recommendation includes Orca platform deep-links and cloud provider console URLs as evidence
- Parallel Phase 1 asset discovery across all resource categories (EC2, EBS, S3, RDS, Lambda, NAT Gateways, EIPs, load balancers)
- Implementation roadmap in 3 phases: zero-downtime quick wins, maintenance-window changes, financial commitments
- Live pricing lookups (web search) with fallback to training data when unavailable

**Usage:**
```bash
# Run a cost optimization report
/orca-cloud-cost-optimizer

# Or use natural language
give me a cost optimization report
where are we wasting money on cloud?
how do we cut our AWS bill?
find unused resources
what can we rightsize?
```

**Example output:**
```
# ☁️ Cloud Cost Optimization Report

Generated: 2026-05-01
Environment: AWS (us-east-1, us-east-2, eu-central-1) | Azure (eastus)
Assets analyzed: 450 across 5 AWS accounts

## 📊 Executive Summary

| | |
|---|---|
| Total assets analyzed | 450 |
| Assets with savings opportunities | 150 (33%) |
| Estimated monthly savings | $2,100 – $3,400/month |
| Estimated annual savings | $25,200 – $40,800/year |
| Immediate low-risk savings (this week) | $800/month |

🏆 Top 5 Quick Wins:
1. EBS gp2→gp3 migration (124 volumes) — $430/month — Very Low Risk
2. Disable Multi-AZ on staging RDS (analytics-db-staging) — $438/month — Low Risk
3. m4.2xlarge→m6i.2xlarge generation upgrade (api-staging-01) — $291/month — Low Risk
4. Release idle Elastic IPs (3 unassociated) — $10/month — Very Low Risk
5. S3 lifecycle policies (cloudtrail + log buckets) — $120/month — Very Low Risk
```

[Full Documentation →](skills/orca-cloud-cost-optimizer/)

</details>


## Testing

All skills include automated evaluations using [Promptfoo](https://www.promptfoo.dev/).

### Run Tests Locally

```bash
# Install Promptfoo
npm install -g promptfoo

# Set your API key
export ANTHROPIC_API_KEY="your-key"

# Run all tests
promptfoo eval

# View results
promptfoo view
```

See [EVALS.md](EVALS.md) for detailed testing guide, including:
- Test coverage per skill
- Adding new test cases
- CI/CD integration
- Debugging failed tests

**Test suite includes ~30 test cases covering:**
- Skill triggering from natural language
- Output format validation
- Error handling
- Cross-model compatibility
- Proactive remediation behavior

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding a New Skill

1. Create `skills/your-skill/SKILL.md`
2. Follow the [skill template](docs/skill-template.md)
3. Add tests if applicable
4. Update this README
5. Submit a pull request

## Support

- **Issues:** https://github.com/orcasecurity/orca-skills/issues
- **Documentation:** https://docs.orcasecurity.io
- **MCP Setup:** https://docs.orcasecurity.io/docs/mcp-integration

## License

MIT License - see [LICENSE](LICENSE) file

## Credits

Built by the Orca Security team and community contributors.
