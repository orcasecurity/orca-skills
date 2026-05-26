# Orca Skills Test Data

This directory contains **realistic but completely fabricated** sample data for testing Orca Security skills in CI/CD pipelines.

## ⚠️ Important Notice

**ALL DATA IN THIS DIRECTORY IS FAKE:**
- No real AWS account IDs, ARNs, or resource identifiers
- No actual customer information or PII
- No real API keys, access keys, or credentials
- No production configuration data

**DO NOT** use this data to make decisions about real infrastructure.

## Purpose

These samples enable **Layer 1 Testing** (analysis logic + formatting) in CI without requiring:
- Live Orca MCP server connection
- Orca API credentials
- Access to real cloud infrastructure

Layer 1 tests verify:
- ✅ Skills correctly parse JSON structures
- ✅ Calculations (percentages, aggregations, rankings) are accurate
- ✅ Output formatting matches expected structure
- ✅ Edge cases (missing fields, empty arrays, nulls) are handled

**Layer 2 Testing** (live MCP integration) happens when users run skills in Claude Code with their own Orca environment.

## Sample Files

### `sample-orca-triage.json`
**What it represents:** Alert details from Orca Anomaly Detection

Used by: `orca-triage` skill

Structure:
- Alert metadata (ID, severity, risk score, category)
- Asset information (EC2 instance with IAM role)
- Anomaly details (data access spike, 3650% above baseline)
- Timeline of events
- Related alerts

Edge cases included:
- Timeline with multiple event types
- Related alerts (both open and closed)

**Key fabricated values:**
- Alert ID: `orca-3636513`
- Account ID: `123456789012`
- Instance ID: `i-abc123xyz`
- All IP addresses, ARNs, and resource names

---

### `sample-orca-impact.json`
**What it represents:** Impact analysis for remediating an alert

Used by: `orca-impact-analysis` skill

Structure:
- Root alert (unencrypted RDS instance)
- Related alerts (5 total, 3 will close if remediated, 2 won't)
- Blast radius metrics
- Compliance impact
- Remediation effort estimate

Edge cases included:
- Mix of alerts that will/won't close
- Multiple dependency types (same_asset, dependent_resource)
- Compliance framework mapping

---

### `sample-orca-config-origin.json`
**What it represents:** Configuration origin and deployment history

Used by: `orca-config-origin` skill

Structure:
- Alert for S3 bucket misconfiguration
- Terraform deployment metadata
- Timeline of deployment events
- Git commit information
- Similar configurations in other environments

Edge cases included:
- Terraform-detected changes
- CloudTrail correlation
- Change ticket tracking

**Key fabricated values:**
- Git commit SHA: `a1b2c3d4...`
- JIRA ticket: `JIRA-1234`
- GitHub repo: `github.com/example-corp/terraform-infrastructure`
- Email: `sarah@example-corp.com`

---

### `sample-orca-briefing.json`
**What it represents:** Daily security briefing summary

Used by: `orca-morning-briefing` skill

Structure:
- Alert summary (24-hour window)
- Compliance status across frameworks (PCI DSS, SOC 2, HIPAA)
- Exposure metrics (internet-facing assets, attack paths)
- Data security findings
- Identity posture
- CDR activity highlights
- Top priorities

Edge cases included:
- Trending indicators (up/down categories)
- Multiple compliance frameworks
- Zero findings in some categories

---

### `sample-orca-asset.json`
**What it represents:** Complete security profile for a single asset

Used by: `orca-asset-profile` skill

Structure:
- Asset metadata (bastion host)
- Configuration details
- Security posture (risk score, crown jewel status)
- Open alerts (5 of varying severity)
- Attack paths (3 paths, one targeting crown jewel)
- IAM permissions (overprivileged admin role)
- Network exposure (SSH from 0.0.0.0/0)
- Compliance violations
- Activity summary

Edge cases included:
- Asset marked as crown jewel
- Multiple attack paths with different risk levels
- Overprivileged IAM role with unused permissions
- Suspicious IP in connection history

---

### `sample-orca-compliance.json`
**What it represents:** Compliance gap analysis for PCI DSS framework

Used by: `orca-compliance-gap` skill

Structure:
- Framework overview (PCI DSS 4.0)
- Overall score and trend
- Requirements breakdown (7 requirements)
- Failing controls (5 critical/high failures)
- Gap analysis summary
- Remediation recommendations

Edge cases included:
- Mix of passing/failing requirements
- Multiple assets per control failure
- Estimated effort hours for remediation

---

### `sample-orca-data-exposure.json`
**What it represents:** DSPM (Data Security Posture Management) findings

Used by: `orca-data-exposure` skill

Structure:
- Summary (342 findings across 5 data types)
- PII locations (187 findings, some publicly exposed)
- Secrets (AWS keys, database passwords, SSH keys, API tokens)
- Credentials (hardcoded passwords, API tokens)
- API keys (Stripe, SendGrid, Google Maps, Twilio)
- Payment data (PCI-classified data stores)
- Exposure breakdown (public, shared externally, internal only)
- Top risks (4 critical exposures)
- Compliance impact

Edge cases included:
- Public S3 bucket with PII (risk score: 92)
- Unencrypted database with payment data
- API keys in various locations (source code, config files, logs)
- Zero HIPAA violations

---

### `sample-orca-exposure.json`
**What it represents:** External attack surface mapping

Used by: `orca-exposure-map` skill

Structure:
- Summary (156 internet-facing assets)
- Breakdown by asset type (load balancers, EC2, S3, RDS, API gateways)
- Attack surface analysis (5 paths to crown jewels)
- Geographic distribution
- Trending (new/closed exposures)
- Remediation recommendations

Edge cases included:
- RDS instance publicly accessible (critical risk)
- API gateway with no authentication
- Mix of acceptable exposure (static assets) and critical (databases)

---

### `sample-orca-identity.json`
**What it represents:** IAM identity review and privilege analysis

Used by: `orca-identity-review` skill

Structure:
- Identity metadata (IAM user "anika")
- Access summary (console + programmatic, no MFA)
- Permissions (AdministratorAccess + PowerUserAccess + inline policies)
- Usage analysis (90 days, 47 unique actions out of 9547 granted)
- Privilege assessment (95% overprivilege score)
- Security findings (5 findings: no MFA, old keys, overprivileged)
- Activity timeline
- Remediation plan

Edge cases included:
- Multiple overlapping high-privilege policies
- 99.5% unused permissions
- Inactive access key not deleted
- No MFA on admin account

---

### `sample-orca-cdr.json`
**What it represents:** Cloud Detection & Response (CDR) event investigation

Used by: `orca-investigate` skill

Structure:
- Investigation scope (IAM role activity over 24 hours)
- Summary (1456 events, 12 actions, 4 services)
- Event timeline (sts:AssumeRole, s3:GetObject burst, IAM/EC2 discovery)
- Grouped actions (s3:GetObject = 450 events in 5 minutes)
- Session clustering (3 sessions: 2 normal, 1 suspicious)
- MITRE ATT&CK mapping (Initial Access, Discovery, Collection)
- Blast radius assessment (MODERATE scope)
- Verdict (SUSPICIOUS - 78% confidence)
- IOCs (suspicious IP: 203.0.113.99)

Edge cases included:
- Data exfiltration pattern (450 S3 GetObject in 5 minutes)
- New external IP performing reconnaissance
- Mix of normal and suspicious sessions
- MITRE ATT&CK kill chain coverage

---

### `sample-orca-cost-optimizer.json`
**What it represents:** Cloud asset inventory with pricing data for cost optimization analysis

Used by: `orca-cloud-cost-optimizer` skill

Structure:
- EC2 instances (mix of t2 old-gen, m4 old-gen, stopped temp instances)
- EBS volumes (gp2 in-use, gp2 unattached, gp3 in-use)
- RDS instances (prod with Multi-AZ, staging with Multi-AZ that should be disabled)
- S3 buckets (log/archive buckets without lifecycle policies)
- Elastic IPs (one unassociated)
- NAT Gateways (one idle dev gateway, one active prod gateway)
- Optimization summary with calculated savings per pattern
- Pricing reference table (AWS EC2, EBS, RDS, S3, networking)

Edge cases included:
- Stopped EC2 instance still incurring EBS costs
- Unattached EBS volume (idle spend)
- Staging RDS with Multi-AZ enabled (should be disabled)
- S3 buckets with no lifecycle policy (log accumulation)

**Key fabricated values:**
- All asset IDs prefixed with `cost-test-` (clearly fake)
- Account ID: `123456789012`
- All resource names, ARNs, and IPs are fabricated
- Savings numbers chosen to exercise specific calculations (e.g., 800 GB gp2 = exactly $16/month savings)

---

### `sample-orca-custom-framework.json`
**What it represents:** Data for building a custom compliance framework from existing controls

Used by: `orca-custom-framework` skill

Structure:
- Enabled frameworks list (5 frameworks with scores)
- Framework controls grouped by section (5 sections, 12 rules total)
- Each control has: rule_id, description, category, result, origin_framework_id, alert counts
- Creation API response (framework ID 3104)
- Post-creation score (28%)
- Coverage gaps (5 gaps for custom alert suggestions)

Edge cases included:
- Mix of pass/fail controls
- Controls from multiple source frameworks
- Coverage gaps with no matching existing rules
- Varying alert severity distributions per control

**Key fabricated values:**
- Framework ID: `3104`
- Account ID: `123456789012`
- All rule_ids reference real Orca rule ID format (`r` prefix + hex)
- Score and asset counts are fabricated

---

## How to Use in Tests

### Pattern Matching (Recommended)

Test for **structure and formatting**, not exact values:

```yaml
# ✅ Good: Tests output structure
assert:
  - type: javascript
    value: |
      const hasVerdict = output.includes('VERDICT:');
      const hasRiskScore = /risk score[:\s]+\d+/i.test(output);
      return hasVerdict && hasRiskScore;

# ❌ Bad: Tests exact values
assert:
  - type: contains
    value: "Risk Score: 85"
```

### Schema Validation

Verify JSON parsing and field presence:

```yaml
assert:
  - type: javascript
    value: |
      // Parse skill output as JSON
      const result = JSON.parse(output);
      
      // Verify required fields exist
      return result.alert_id &&
             result.risk_score &&
             result.severity &&
             Array.isArray(result.timeline);
```

### Calculation Testing

Use known relationships in sample data:

```yaml
# sample-orca-impact.json has 5 related alerts: 3 will close, 2 won't
assert:
  - type: javascript
    value: |
      // Skill should calculate: 3/5 = 60%
      const closureMatch = output.match(/(\d+)%.*close/i);
      return closureMatch && parseInt(closureMatch[1]) === 60;
```

### Edge Case Testing

Sample data includes deliberate edge cases:

- **Empty arrays:** `sample-orca-briefing.json` has zero findings in some categories
- **Null values:** Some optional fields are null
- **Missing fields:** Test graceful degradation when expected fields absent

---

## Sample Data Origins

Each sample was created by:

1. **Studying real Orca API response schemas** (via MCP tool documentation)
2. **Anonymizing structure** (removing all real identifiers)
3. **Fabricating realistic values** (plausible ARNs, metrics, timestamps)
4. **Adding edge cases** (empty lists, null values, unusual patterns)

**No real Orca data was copied or derived from production systems.**

---

## Updating Sample Data

When adding new skills or test cases:

1. **Create new sample file:** `sample-orca-<skill-name>.json`
2. **Follow naming convention:** Use skill name without `orca-` prefix
3. **Include edge cases:** Empty arrays, nulls, boundary conditions
4. **Fabricate all values:** No real IDs, emails, credentials
5. **Document structure:** Add section to this README
6. **Update tests:** Reference new sample in `promptfooconfig.yaml`

---

## License

These sample files are part of the Orca Skills project and are licensed under Apache 2.0.

They are provided "AS IS" for testing purposes only.
