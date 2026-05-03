# Orca Skills Evaluation Guide

This repo includes automated tests for all 10 Orca Security skills using [Promptfoo](https://www.promptfoo.dev/).

## Testing Strategy: Layer 1 vs Layer 2

Orca Skills uses a **two-layer testing approach** to balance CI automation with real-world validation:

### Layer 1: Analysis Logic & Formatting (CI)

**What it tests:**
- ✅ Skills correctly parse JSON data structures
- ✅ Calculations are accurate (percentages, aggregations, rankings)
- ✅ Output formatting matches expected structure (sections, fields, types)
- ✅ Edge cases are handled (empty arrays, missing fields, null values)

**What it DOES NOT test:**
- ❌ Live MCP server connectivity
- ❌ Real Orca API authentication
- ❌ Actual cloud infrastructure data accuracy

**How it works:**
- Uses **fabricated but realistic** sample data (see `test-data/`)
- Runs in CI/CD without credentials
- Fast, safe, repeatable

**Run Layer 1 tests:**
```bash
promptfoo eval
```

### Layer 2: Live MCP Integration (User Validation)

**What it tests:**
- ✅ Skills trigger correctly in Claude Code
- ✅ MCP tools are called with correct parameters
- ✅ Real Orca data is fetched and processed
- ✅ End-to-end workflow with actual infrastructure

**What it requires:**
- Orca MCP server configured
- `ORCA_API_TOKEN` set
- Claude Code CLI installed
- Access to real Orca environment

**Run Layer 2 tests:**
```bash
# In Claude Code with MCP configured
claude code
> triage alert orca-<real-alert-id>
> morning briefing
> investigate <real-actor-arn>
```

---

## Why This Separation?

| Concern | Layer 1 (CI) | Layer 2 (User) |
|---------|-------------|----------------|
| **Credentials** | None needed | Requires Orca API token |
| **Speed** | Fast (~2 mins) | Slower (live API calls) |
| **Cost** | Minimal (LLM only) | Higher (LLM + Orca API) |
| **Scope** | Logic & format | Full integration |
| **When** | Every PR | Before release / manual |

**Layer 1** catches logic bugs, formatting issues, and calculation errors early in CI.

**Layer 2** validates real-world behavior with live data—done by maintainers or users before deployment.

---

## Prerequisites

Install Promptfoo:
```bash
npm install -g promptfoo
```

Set your Anthropic API key:
```bash
export ANTHROPIC_API_KEY="your-key-here"
```

---

## Running Layer 1 Evals (CI)

### Run all tests:
```bash
promptfoo eval
```

### View results in browser:
```bash
promptfoo view
```

### Run tests for specific skill:
```bash
promptfoo eval -t "orca-alert-triage"
```

### Test across multiple models:
Edit `promptfooconfig.yaml` and uncomment:
```yaml
providers:
  - anthropic:claude-sonnet-4
  - anthropic:claude-opus-4    # Uncomment this
  - anthropic:claude-haiku-4   # Uncomment this
```

---

## Test Coverage (Layer 1)

Each skill has 2-4 test cases covering:

| Skill | Tests |
|-------|-------|
| **orca-alert-triage** | Alert parsing, timeline formatting, anomaly calculation |
| **orca-impact-analysis** | Blast radius calculation, closure percentage |
| **orca-config-origin** | Deployment method detection, timeline parsing |
| **orca-morning-briefing** | Multi-metric aggregation, trend analysis, prioritization |
| **orca-asset-profile** | Crown jewel detection, attack path counting, permission analysis |
| **orca-compliance-gap** | Score calculation, gap prioritization |
| **orca-data-exposure** | Finding summation, risk ranking |
| **orca-exposure-map** | Asset counting, high-risk identification |
| **orca-identity-review** | Overprivilege calculation, finding count |
| **orca-investigate** | Event rate analysis, session clustering, MITRE mapping |

**Cross-cutting:**
- Edge case handling (empty arrays, missing fields)
- Output structure validation

**Total: ~30 test cases**

---

## Test Data (Layer 1)

All test data is in `test-data/` directory:

- **✅ Realistic structure:** Matches real Orca API responses
- **✅ Fabricated values:** No real account IDs, emails, credentials, or sensitive data
- **✅ Edge cases included:** Empty lists, null values, boundary conditions

See [`test-data/README.md`](test-data/README.md) for detailed documentation.

---

## Understanding Results

After running `promptfoo eval`, you'll see:

```
✓ [orca-alert-triage] Parse alert JSON and calculate risk metrics
✓ [orca-impact-analysis] Calculate alert closure percentage
✗ [orca-compliance] Calculate overall compliance score
  Expected output to contain "78" but got: "77"
```

- **Green ✓** = Test passed
- **Red ✗** = Test failed (with explanation)

Run `promptfoo view` to see:
- Full output for each test
- Side-by-side comparison
- Performance metrics

---

## Assertion Types

Layer 1 tests use **pattern matching and calculations**, not exact string matches:

| Type | Purpose | Example |
|------|---------|---------|
| `contains` | Exact string match | `value: "orca-3636513"` |
| `icontains` | Case-insensitive match | `value: "verdict"` |
| `javascript` | Custom validation logic | Check calculations, structure, format |

### Examples

**✅ Good: Tests structure and logic**
```yaml
assert:
  - type: javascript
    value: |
      // Verify percentage calculation: 3/5 = 60%
      return output.includes('60%');
```

**❌ Bad: Tests exact wording**
```yaml
assert:
  - type: contains
    value: "Fixing this alert will close 3 related alerts"  # Too specific
```

---

## Adding New Tests

### 1. Create sample data

Add to `test-data/sample-orca-<skill>.json`:
- Use realistic JSON structure
- Fabricate all values (no real IDs, credentials)
- Include edge cases

### 2. Write test case

Add to `promptfooconfig.yaml`:
```yaml
- description: "[orca-<skill>] Test description"
  vars:
    data: file://test-data/sample-orca-<skill>.json
    task: "What to analyze or calculate"
  assert:
    - type: javascript
      value: |
        // Test logic here
        return output.includes('expected-value');
```

### 3. Run and verify

```bash
promptfoo eval -t "orca-<skill>"
```

---

## CI/CD Integration

### GitHub Actions

The repo includes `.github/workflows/test-skills.yml` that:
- ✅ Runs on every push/PR to `main`
- ✅ Tests with Claude Sonnet 4
- ✅ Uploads results as artifacts
- ✅ Fails PR if tests fail

**No credentials needed** - Layer 1 tests use mock data only.

---

## Running Layer 2 Tests (Live MCP)

Layer 2 tests validate skills with **real Orca data** and **live MCP integration**.

### Prerequisites

1. **Claude Code installed:**
   ```bash
   claude code --version
   ```

2. **Orca MCP server configured** in `~/.claude/mcp.json`:
   ```json
   {
     "orca-security": {
       "url": "https://api.orcasecurity.io/mcp/v1",
       "token": "your-orca-api-token"
     }
   }
   ```

3. **Orca API token** set:
   ```bash
   export ORCA_API_TOKEN="your-token-here"
   ```

### Run Live Tests

Start Claude Code:
```bash
claude code
```

Test each skill with **real data**:

```
> triage alert orca-<real-alert-id>
> what's the impact of fixing orca-<real-alert-id>
> who deployed orca-<real-alert-id>
> morning briefing
> asset profile for <real-asset-name>
> compliance gaps for PCI DSS
> data exposure report
> exposure map
> identity review for <real-identity-name>
> investigate <real-actor-arn>
```

### Validation Checklist

For each skill, verify:

- [ ] Skill triggers correctly from natural language
- [ ] MCP tools are called (check Claude Code debug output)
- [ ] Real data is fetched from Orca API
- [ ] Output includes all expected sections
- [ ] Calculations are accurate (spot-check)
- [ ] Formatting is clear and readable
- [ ] Error handling works (try invalid IDs)

---

## Debugging Failed Tests

### Layer 1 (CI) Failures

**View full output:**
```bash
promptfoo view
# Click on failed test to see complete output
```

**Run single test with verbose output:**
```bash
promptfoo eval --verbose -t "test-name"
```

**Common issues:**
- Sample data structure changed but tests not updated
- Calculation logic error (check expected vs actual values)
- Output format changed (update assertions to match new format)

### Layer 2 (Live MCP) Failures

**Debug MCP connection:**
```bash
# Check MCP config
cat ~/.claude/mcp.json

# Test MCP server manually
curl -H "Authorization: Bearer $ORCA_API_TOKEN" \
     https://api.orcasecurity.io/mcp/v1/health
```

**Common issues:**
- `ORCA_API_TOKEN` not set or expired
- MCP server URL incorrect
- API token lacks required permissions
- Skill not triggering (check description field in SKILL.md)

---

## Best Practices

### Layer 1 (CI) Tests

✅ **DO:**
- Test calculations and aggregations with known values
- Test output structure (sections, fields, formatting)
- Test edge cases (empty data, missing fields, nulls)
- Use pattern matching (regex, contains) instead of exact strings
- Keep tests fast (< 2 minutes total)

❌ **DON'T:**
- Test exact wording or phrasing (too brittle)
- Include real credentials or sensitive data in test files
- Skip testing after "small" changes (logic bugs hide there)
- Test things that require live MCP (that's Layer 2)

### Layer 2 (Live MCP) Tests

✅ **DO:**
- Test with real Orca data from test/staging environment
- Verify end-to-end workflow (trigger → MCP call → output)
- Test error handling with invalid IDs
- Validate against real production use cases
- Run before major releases

❌ **DON'T:**
- Automate Layer 2 tests in CI without sandboxing
- Use production Orca credentials for automated testing
- Skip Layer 1 and jump straight to Layer 2
- Test with real customer data (use test tenant)

---

## Troubleshooting

### "Provider not found"
```bash
# Make sure ANTHROPIC_API_KEY is set
export ANTHROPIC_API_KEY="sk-ant-..."
```

### "Cannot read file test-data/..."
```bash
# Run promptfoo from repo root directory
cd /path/to/orca-skills
promptfoo eval
```

### "Tests timing out"
Increase timeout in `promptfooconfig.yaml`:
```yaml
defaultTest:
  options:
    timeout: 60000  # 60 seconds
```

### "All tests failing"
Check sample data structure matches expected format:
```bash
# Validate JSON syntax
jq . test-data/sample-orca-triage.json
```

---

## Cost Estimates

### Layer 1 (CI)
- **Per test run:** ~30 tests × Claude Sonnet 4
- **Cost:** ~$0.30-0.50 per run
- **Frequency:** Every PR (10-20 runs/day typical)
- **Monthly:** ~$150-300 for active repo

### Layer 2 (Live MCP)
- **Per test run:** ~10 skills × (Claude + Orca API calls)
- **Cost:** ~$2-5 per full validation
- **Frequency:** Manual, before releases (5-10 runs/month)
- **Monthly:** ~$10-50

**Total estimated cost: $160-350/month for active development**

---

## Resources

- [Promptfoo Documentation](https://www.promptfoo.dev/docs/intro)
- [Assertion Types Reference](https://www.promptfoo.dev/docs/configuration/expected-outputs)
- [CI/CD Examples](https://www.promptfoo.dev/docs/integrations/github-action)
- [Test Data Documentation](test-data/README.md)
- [Orca Security MCP Server](https://docs.orcasecurity.io/docs/orca-security-mcp-server)

---

## Contributing

When adding new skills or features:

### For Layer 1 (CI)
1. Create sample data in `test-data/sample-orca-<skill>.json`
2. Write tests in `promptfooconfig.yaml`
3. Run `promptfoo eval` to verify they pass
4. Document sample data structure in `test-data/README.md`

### For Layer 2 (Live MCP)
1. Test skill in Claude Code with real Orca environment
2. Document expected behavior in skill's SKILL.md
3. Add validation checklist to this document
4. Note any MCP-specific requirements

### Commit Together
- Commit skill code + Layer 1 tests + sample data together
- Ensure CI passes before merging
- Document Layer 2 validation steps in PR description

---

## License

These evaluation materials are part of the Orca Skills project and are licensed under Apache 2.0.
