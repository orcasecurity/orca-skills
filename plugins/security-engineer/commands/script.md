---
description: Run the security engineer with explicit flags, taken exactly as typed — no interpretation
argument-hint: "[risk_levels,feature_types] [--scan] [--cve <id>] [--alert <id>] [--max N] [--dry-run] | --remote <owner/repo|all> [filters]"
allowed-tools: Bash
---

# Security Engineer — explicit flags

Flags are taken exactly as typed, with no interpretation. To describe what you
want in plain English instead, just say it — the `run` skill
(`/security-engineer:run`) translates intent into these same flags.

```bash
${CLAUDE_PLUGIN_ROOT}/bin/security-engineer $ARGUMENTS
```

Return the output verbatim. If the script exits with a non-zero exit code, print the error and STOP — do not retry, do not correct arguments, do not attempt to fix the command on the user's behalf.
