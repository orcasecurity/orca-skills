# security-engineer

A Claude Code plugin that autonomously remediates Orca security alerts — from
alert to reviewable pull request.

## What it does

Fetches open Orca alerts, then for each one: creates an isolated git worktree,
decides the fix target from advisory data where it can, invokes a Claude
subprocess to apply the change, runs it through five gates, assesses production
impact, opens a PR carrying that assessment, and notifies.

```
Orca alerts
    └─► [for each alert, up to 4 in parallel]
            isolated worktree
                └─► resolve target version (CVE only, from OSV + deps.dev)
                        └─► fix agent (Claude)
                                └─► gates: sanity → LLM → type verify
                                        └─► impact agent → commit → PR
                                                └─► gates: Orca check → CI
    └─► summary table, non-zero exit if anything failed
```

Nothing is merged automatically. Every run ends at an open PR with an impact
label, a version rationale, and a `needs-review` flag wherever a gate passed
without being able to confirm.

**How and why it holds together — the gates, the data sources, what fails open
and what fails closed: [`HARNESS.md`](HARNESS.md).**

## Installation

### Prerequisites

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) v1.0.33+
- [GitHub CLI](https://cli.github.com/) (`gh`) — authenticated
- Python 3.10+ (3.11+ for TOML manifests). Stdlib only, with one optional
  exception: [PyYAML](https://pyyaml.org/) is needed to read a
  `SECURITY_ENGINEER_CONFIG` file. Without it the orchestrator warns once and
  runs on built-in defaults.
- An [Orca Security](https://orca.security/) API token

### Install the plugin

```bash
curl -sL https://raw.githubusercontent.com/igorlopes-orca/security-engineer/main/install.sh | bash
```

Or manually:

```bash
claude plugin marketplace add igorlopes-orca/security-engineer
claude plugin install security-engineer@orca-security
```

### Set your Orca API token

```bash
export ORCA_API_TOKEN="<your-token>"
```

Optionally, for Slack/Teams notifications:

```bash
export NOTIFY_WEBHOOK_URL="https://hooks.slack.com/..."
```

## Usage

Three entry points, one flag grammar. Flags are the contract; English is a
convenience layer on top of them.

### Slash command — explicit flags, taken exactly as typed

```
# Fix mode — remediate alerts
/security-engineer:script                              → all fixable alerts
/security-engineer:script high,cve                     → high+ CVEs only
/security-engineer:script --alert orca-270453          → fix a single alert
/security-engineer:script --dry-run cve                → plan only, no git ops
/security-engineer:script --max 3 cve                  → cap at 3 CVE fixes
/security-engineer:script --remote owner/repo          → clone and fix a remote repo
/security-engineer:script --remote all                 → fix all Orca-discovered repos

# Scan mode — list risks without fixing
/security-engineer:script --scan                       → list all risks for current repo
/security-engineer:script --scan high                  → list high+ risks only
/security-engineer:script --scan --remote owner/repo   → list risks for a remote repo
/security-engineer:script --scan --remote all          → list risks across all repos
```

`--scan` is read-only and rejects `--dry-run`, `--alert` and `--max`.

### Shell — the same flags, outside Claude Code

Installing the plugin puts `security-engineer` on your `PATH`, so every example
above also works in a terminal, a Makefile, or CI:

```bash
security-engineer high,cve --max 3
security-engineer --scan --remote all
```

The exit code is meaningful: non-zero if any alert failed, timed out, or landed
with red CI.

### Plain English — translated to those same flags

Just describe what you want. The `/security-engineer:run` skill resolves the
intent, echoes the command it derived, and runs it once. You rarely type its
name — it fires on what you asked for:

```
"remediate alert-192901290"                 → security-engineer --alert alert-192901290
"remediate all high vulnerabilities, max of 3"
                                            → security-engineer high --max 3
"fix one SAST issue"                        → security-engineer sast --max 1
"show me what you'd do about the CVEs"      → security-engineer cve --dry-run
"what security risks does this repo have?"  → security-engineer --scan
```

Alert IDs are accepted however you write them — `alert-192901290`, `#192901290`,
or a bare `192901290` all resolve to Orca's `orca-192901290`. If a message
contains explicit flags, they are passed through untouched rather than
re-interpreted.

### Filters

A filter is one positional token: severity and type joined by a comma, no
spaces. Severity is cumulative (`high` means critical *and* high); type is
exact.

| | Tokens |
|---|---|
| **Severity** | `critical` · `high` · `medium` · `low` |
| **Type** | `cve` (package/dependency) · `sast` · `iac` · `secret` |

## Coverage

| Finding type | What the fix is | Post-fix check |
|---|---|---|
| `cve` | A manifest version bump, target resolved before the agent runs | Manifest pins the resolved version, lockfile agrees, applied version carries no known advisory, plus `go build` / `cargo metadata` where available |
| `sast` | A code change | Language build check |
| `iac` | Dockerfile / Kubernetes / Terraform change | `terraform validate`, or skipped |
| `secret` | Credential removed and externalised | Build check, plus a sanity gate rejecting any newly added secret-shaped line |

CVE ecosystems: PyPI, npm, Go, Maven, Cargo, RubyGems, NuGet.
Build checks: Go, JavaScript/TypeScript, Python, Terraform — a missing
toolchain skips the check rather than failing it.

`scm_posture` findings are reported as needing manual action and never fixed.

## CVE version decisions

For a package CVE the target version is resolved before the fix agent runs, from
[OSV.dev](https://osv.dev) advisory ranges plus the published version list from
[deps.dev](https://deps.dev) — both free, unauthenticated, and cached on disk. The
agent is told which version to apply rather than asked to find it.

Policy is **minimum safe at any distance**: the lowest published release that
clears every advisory affecting the installed version, queried package-wide so a
bump cannot land on a different known CVE. A major-version jump is not refused —
some packages have no safe release inside the current major — but the distance is
measured and passed to the production-impact assessment.

Inspect any decision without a token, an alert, or a pipeline run:

```bash
python3 skills/run/run_agent.py resolve-version pypi pillow 8.3.1
```

The same rationale, cleared advisories and reproduce command land in the PR body.
Details in [`HARNESS.md`](HARNESS.md#the-version-decision).

## Configuration

Secrets live in the environment:

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config). `ORCA_AUTH_TOKEN` is accepted as an alias |
| `NOTIFY_WEBHOOK_URL` | No | Webhook URL for Slack/Teams notifications |
| `SECURITY_ENGINEER_CONFIG` | No | Path to a YAML file overriding gate and data-layer settings |

Everything else — gate timeouts, retry policy, the Orca check name, the version
data cache, concurrency caps — is YAML. The keys and their defaults are tabled in
[`HARNESS.md`](HARNESS.md#configuration).

## Repository layout

```
.claude-plugin/              plugin manifest and marketplace definition
bin/security-engineer        CLI entry point (plugin bin/ is added to PATH)
commands/script.md           /security-engineer:script — flags, verbatim
skills/
  run/                       /security-engineer:run — the orchestrator lives here.
                             The directory name is the skill name.
    orchestrator.py            state machine: fetch → fix → gate → PR → notify
    validator.py               the gates
    pipelines/                 per-finding-type prepare()/verify() specialists
    impact_agent.py            production risk assessment
    notifier.py                console / NDJSON log / webhook backends
    run_agent.py               mechanical ops CLI (alerts, git, PR, resolve-version)
    fix-agents/                fix instructions per type, and per CVE ecosystem
    tests/                     unit suites
  lib/
    orca_client.py             Orca API client
    version_data.py            OSV + deps.dev version-decision layer
HARNESS.md                   how the harness works and why
.github/workflows/ci.yml     tests and lint on every pull request
tools/check_manifests.py     static checks on the plugin's own metadata
ruff.toml                    the lint ruleset CI enforces
devloop/                     live-run test harness — not shipped with the plugin
docs/                        design plans
```

## Developing

```bash
make test                              # 379 unit tests, no token or network
make lint                              # ruff, shellcheck, plugin metadata
make fast                              # test → install → reset sandbox → fix one alert → report
make loop ARGS="--dry-run cve"         # plan only, no writes
make loop ARGS="sast --max 2"          # any orchestrator filter
```

Unit tests cover argument parsing, version ordering, manifest parsing and gate
behaviour on mocked diffs. The pipeline that matters — worktree lifecycle, what
the gates actually see, whether the Orca check gate fires — only exists in a live
run, and `devloop/` makes that one command:

```bash
cp devloop/.env.example devloop/.env   # then fill in ORCA_API_TOKEN
```

`make fast` runs the orchestrator against a disposable sandbox repo and prints
per-alert state, PR URLs, Orca check conclusions, and the annotations behind any
failure. See [`devloop/README.md`](devloop/README.md).

New functions and behaviours need table-driven tests — a `CASES` list looped with
`self.subTest`, per [`CLAUDE.md`](CLAUDE.md).

### What CI checks

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every pull
request: `make test` across Python 3.10–3.14, then `make lint`. It runs the same
Make targets you do, so a green PR is predictable from your terminal rather than
discovered on the pull request.

```bash
pip install ruff==0.16.1 shellcheck-py==0.11.0.1 pyyaml==6.0.3   # what CI pins
```

Lint rules live in [`ruff.toml`](ruff.toml), selected explicitly so a ruff
release can't fail a PR that changed nothing. Formatting is not enforced.
`tools/check_manifests.py` covers what the Python suites can't see: version drift
between `plugin.json` and `marketplace.json`, a lost executable bit on
`bin/security-engineer`, missing skill or command frontmatter.

`make e2e` stays out of CI — it needs `ORCA_API_TOKEN`, and secrets aren't
available to pull requests from forks.

### Running your working tree as the plugin

The dev loop runs `orchestrator.py` from this repo; `/security-engineer:run`
runs the copy Claude Code made when the plugin was installed. Nothing refreshes
that copy on its own — `claude plugin update` short-circuits while the version
in `plugin.json` is unchanged — so the skill will keep running the commit it was
installed at until you say otherwise.

```bash
make install         # install this working tree as the plugin
make plugin-status   # is the installed plugin this code? names the files if not
make uninstall       # remove it; marketplace goes back to GitHub
```

`make loop` and `make fast` run `make install` as a step, so the skill and the
dev loop always test the same code. `make uninstall` then `./install.sh` gets
you back to the published version — worth doing before tagging a release.
