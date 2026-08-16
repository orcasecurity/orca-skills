---
name: run
description: Remediate Orca Security alerts end to end — fix, validate, assess production impact, open a PR, notify. Use whenever someone asks to fix, remediate, patch, triage, or scan security alerts, vulnerabilities, or findings, whether they name a severity ("remediate all high vulnerabilities", "patch the critical ones"), a type ("fix the SAST issues", "clean up the hardcoded secrets", "bump the vulnerable dependencies", "fix the Dockerfile findings"), a CVE or advisory id ("fix CVE-2020-7471", "are we exposed to log4shell", "patch GHSA-2p49-hgcm-8545", "where is CVE-2021-44228 open"), a count ("just one", "max of 3"), an alert ID ("remediate alert-192901290", "fix orca-4060720"), or a repo ("fix everything in owner/repo", "scan all our repos"). Also covers dry runs and read-only risk reports. Covers CVE/SCA, SAST, IaC, and secret findings.
argument-hint: "fix CVE-2020-7471 | remediate up to 3 high CVEs | what risks does this repo have? | patch the secrets in acme/api"
allowed-tools: Bash
---

# Security Engineer

A Python orchestrator does the remediation. Your job is narrow: **turn the
request into one command line, echo it, run it once, report what it printed.**
Never fix an alert yourself, and never run the command more than once.

## 0. Flags win over interpretation

There are two ways in, and they end at the same command:

| The user typed | What you do |
|---|---|
| Flags — `/security-engineer:script high,cve --max 3`, or any message containing `--scan`, `--dry-run`, `--alert`, `--cve`, `--max`, `--remote`, or a bare filter token like `high,cve` | **Pass them through verbatim.** Do not re-derive, reorder, add, or drop a single flag. |
| Plain English — "remediate all high vulnerabilities with max of 3" | Translate with the tables in §1. |

If a message mixes both — "fix the high CVEs, `--dry-run`" — the explicit flag is
authoritative and the English fills in only what no flag covers. Never override
something the user spelled out, and never silently add a flag they did not ask
for (especially `--max`, which would quietly shrink the run).

## 1. Build the command

```
security-engineer [FILTER] [FLAGS]
```

`security-engineer` is on `PATH` — Claude Code adds every installed plugin's
`bin/` directory. If the shell answers `command not found`, the plugin is not
installed: say so and stop. Do not go hunting for `orchestrator.py`.

It takes exactly the flags documented in the Usage Reference below, so anything
valid after `/security-engineer:script` is valid after `security-engineer`.

**FILTER** is a single positional token: severity and type joined by a comma,
no spaces (`high`, `cve`, `high,cve`, `critical,sast`). Severity is cumulative —
`high` means critical *and* high. Type is exact. Omit it for everything.

| Intent | Token |
|---|---|
| critical / high / medium / low | `critical` `high` `medium` `low` |
| CVEs, SCA, vulnerable dependencies, package/library versions | `cve` |
| SAST, source code vulnerabilities, insecure code | `sast` |
| IaC, Dockerfile, Kubernetes, Terraform | `iac` |
| hardcoded secrets, leaked credentials, exposed keys | `secret` |

**FLAGS**

| Intent | Flag |
|---|---|
| "just one", "a single", "only one" | `--max 1` |
| "max of 3", "up to 3", "at most three", "3 of them" | `--max 3` |
| "dry run", "plan it", "show me what it would do", "don't change anything" | `--dry-run` |
| "scan", "list the risks", "what's open", "report only, don't fix" | `--scan` |
| a specific alert | `--alert orca-4060720` |
| a named CVE or advisory — "fix CVE-2020-7471", "patch log4shell", "are we exposed to GHSA-2p49-hgcm-8545" | `--cve CVE-2020-7471` |
| "where is CVE-X open?", "which repos have it?" | `--scan --cve CVE-X --remote all` |
| "in owner/repo", "against owner/repo" | `--remote owner/repo` |
| "all our repos", "every repo", "org-wide" | `--remote all` |

### Worked examples

| Request | Command |
|---|---|
| "remediate alert-192901290" | `security-engineer --alert alert-192901290` |
| "fix CVE-2020-7471" | `security-engineer --cve CVE-2020-7471` |
| "is CVE-2021-44228 anywhere in our repos?" | `security-engineer --scan --cve CVE-2021-44228 --remote all` |
| "patch CVE-2020-7471 in acme/api" | `security-engineer --cve CVE-2020-7471 --remote acme/api` |
| "remediate all high vulnerabilities with max of 3" | `security-engineer high --max 3` |
| "fix one SAST issue" | `security-engineer sast --max 1` |
| "patch the critical CVEs" | `security-engineer critical,cve` |
| "clean up the hardcoded secrets" | `security-engineer secret` |
| "show me what you'd do about the CVEs" | `security-engineer cve --dry-run` |
| "what security risks does this repo have?" | `security-engineer --scan` |
| "list the high risks across all our repos" | `security-engineer --scan --remote all` |
| "fix at most two high CVEs in acme/api" | `security-engineer high,cve --remote acme/api --max 2` |

### Rules

- **Alert IDs pass through as the user typed them.** `alert-192901290`,
  `#192901290`, and a bare `192901290` are all normalized to Orca's canonical
  `orca-192901290` by the orchestrator. Do not rewrite them yourself, and do not
  ask the user to reformat.
- **"vulnerabilities" alone is not `cve`.** Used loosely it means all finding
  types — pass no type token. Only use `cve` when the request points at
  packages, dependencies, libraries, CVE numbers, or SCA.
- **A named advisory is `--cve`, not the `cve` filter token.** `cve` means "all
  package findings"; `--cve CVE-2020-7471` means that one advisory. Pass the id
  as the user wrote it — `cve-2020-7471` and `GHSA-...` are normalized by the
  orchestrator. A CVE with no repo named runs against the current repo, like
  every other filter; if it is not open here, the run says which repos do carry
  it. **Do not add `--remote all` unless the user asked to search everywhere.**
- **A named CVE is a scope, so it does not need confirming.** The unbounded-run
  rule below does not apply to `--cve`: it is as specific as `--alert`.
- **Never add `--remote` when the user is working in the current repo.** With no
  `--remote`, the orchestrator auto-detects the repo from the git remote.
- **`--scan` is read-only** and rejects `--dry-run`, `--alert`, and `--max`. If
  the user wants a report about one alert, drop `--scan`.
- **Ask first only when a *fix* run is completely unbounded** — no severity, no
  type, no count, no alert ID. That fixes every open alert in the repo and opens
  a PR per alert, so confirm scope before launching it. Anything narrower: run it.

## 2. Echo, then run

Print the resolved command before executing, so the user can see how their
words were read:

```
→ security-engineer high --max 3
```

Then run it exactly once, in the foreground. A full run takes minutes and prints
progress as it goes — that is expected, not a hang. Use a Bash timeout of at
least 30 minutes for a fix run.

## 3. Report

Return the orchestrator's output verbatim, including its summary table. If it
exits non-zero, print the error and **stop** — do not retry, do not adjust the
arguments, do not attempt the fix by hand. A non-zero exit means a gate did its
job; second-guessing it is how a bad fix reaches a PR.

---

## Usage Reference

Two modes: **fix** (default) and **scan** (`--scan`).

Three interchangeable entry points, one flag grammar — this reference applies to
all three:

```
/security-engineer:script high,cve --max 3     # slash command
security-engineer high,cve --max 3          # shell, or what this skill runs
"fix up to 3 high CVEs"                     # plain English, translated per §1
```

### Fix mode — remediate alerts

```
# Local mode — operates on the repo you're already inside
/security-engineer:script                             -> all fixable alerts, all severities
/security-engineer:script cve                         -> CVE alerts only, all severities
/security-engineer:script high                        -> high+ severity, all types
/security-engineer:script high,cve                    -> high+ severity AND CVE type only
/security-engineer:script critical,sast               -> critical+ AND SAST only
/security-engineer:script --dry-run cve               -> plan CVE fixes — read-only, no git ops
/security-engineer:script --dry-run high,sast         -> plan high+ SAST fixes — no edits
/security-engineer:script --alert orca-270453         -> fix one specific alert (live)
/security-engineer:script --alert orca-270453 --dry-run -> plan one specific alert
/security-engineer:script --max 3 cve                 -> cap at 3 CVE fixes
/security-engineer:script --cve CVE-2020-7471         -> fix whatever carries this advisory
/security-engineer:script --cve CVE-1,CVE-2           -> either advisory (also: repeat --cve)
/security-engineer:script CVE-2020-7471               -> same, as a bare positional

# Remote mode — clones repos, runs full pipeline, cleans up
/security-engineer:script --remote owner/repo              -> clone owner/repo, fix all alerts
/security-engineer:script --remote owner/repo high,cve     -> clone, fix high+ CVEs only
/security-engineer:script --remote --dry-run owner/repo    -> clone, plan only, no edits
/security-engineer:script --remote all                     -> all Orca-discovered repos (clone each)
/security-engineer:script --remote all high,cve            -> all repos, high+ CVEs only
/security-engineer:script --remote all --dry-run sast      -> plan SAST fixes across all repos
/security-engineer:script --remote all --max 2 cve         -> cap at 2 CVE fixes per repo
```

### Scan mode — list risks without fixing

```
/security-engineer:script --scan                           -> list all risks, local repo
/security-engineer:script --scan high                      -> list high+ risks only
/security-engineer:script --scan sast,iac                  -> list SAST and IaC risks
/security-engineer:script --scan --remote owner/repo       -> list risks for a remote repo
/security-engineer:script --scan --remote all              -> list risks across all repos
/security-engineer:script --scan --cve CVE-2020-7471       -> is this advisory open here?
/security-engineer:script --scan --cve CVE-2020-7471 --remote all
                                                           -> every repo carrying it
```

### Finding a CVE without a run

`find-cve` answers "where is this open?" on its own — one API query, no clone,
no git, no fix. It sits beside `orchestrator.py` in the plugin's `skills/run/`:

```bash
python3 run_agent.py find-cve CVE-2020-7471
{
  "cve_ids": ["CVE-2020-7471"],
  "repos": [{"repo": "acme/api", "alert_count": 2}],
  "total_alerts": 2
}
```

A `--cve` run that matches nothing in the current repo prints the same
information automatically, along with the command to fix it where it is.

## Flag Compatibility

| Flag | Fix mode | Scan mode | Notes |
|---|---|---|---|
| `filters` (positional) | Yes | Yes | `high,cve`, `sast`, etc. |
| `--dry-run` | Yes | **Error** | Scan is inherently read-only |
| `--alert <id>` | Yes | **Error** | Use `--alert` without `--scan` to fix it |
| `--cve <id>` | Yes | Yes | Narrows the list; conflicts with `--alert` |
| `--max N` | Yes | **Error** | No fixing = no cap needed |
| `--remote <repo\|all>` | Yes | Yes | In scan mode: API query only, no clone |

Invalid combinations produce a clear error:
```
Error: --scan and --dry-run cannot be combined. --scan already lists alerts without fixing.
Error: --scan and --alert cannot be combined. To fix a single alert, drop --scan.
Error: --scan and --max cannot be combined. --scan lists all matching alerts.
Error: --cve and --alert cannot be combined. Both choose which alerts to fix; pass one.
```

## Filter Rules

**Risk levels** (cumulative — specifying `high` includes `critical` too):
- `critical` -> critical only
- `high` -> critical + high
- `medium` -> critical + high + medium
- `low` -> everything except informational

**Feature types** (exact match — only alerts of those types):
- `cve` -> package/dependency CVEs (category "Vulnerabilities")
- `sast` -> source code vulnerabilities
- `iac` -> Dockerfiles, K8s YAML, Terraform
- `secret` -> hardcoded credentials

Combine with comma: `high,cve` = high+ severity AND CVE type. Both conditions must match.

**Advisory ids** (`--cve CVE-2020-7471`, or as a positional token) select the
alerts carrying that CVE or GHSA id, filtered server-side by Orca. Case does not
matter and the id is canonicalized before it is used. Composes with the tokens
above: `security-engineer high --cve CVE-2020-7471` is high+ severity *and* that
advisory.

**One alert is a whole package, not one CVE.** Orca raises a package alert per
vulnerable dependency and lists every advisory against it — the django alert in
one sandbox repo carries 41. So a `--cve` run selects package alerts, and the
minimum-safe bump (see CVE Version Decisions) clears *all* of that package's
advisories, not only the one named. The plan output says how many, the PR body
names the requested one, and Phase 3 fails the fix if the applied version still
leaves the requested advisory open.

## --dry-run Guarantees

Three independent enforcement layers:
1. **Tool restriction** — claude subprocess receives `--allowedTools Read` only; Edit/Write/Bash are physically unavailable
2. **Orchestrator gate** — returns immediately after fix plan; validation, commit, and PR steps are never reached
3. **Commit guard** — `_commit_and_pr()` also checks dry_run as defense in depth

The unit suite at `skills/run/tests/test_orchestrator.py` (inside the
plugin directory) verifies all three layers.

## Pipeline (Live Mode)

### Local mode (default)

Operates on the repo you're already inside — no cloning.

Each finding type runs through a **FixPipeline** (`pipelines/`) that owns its
timeout, diff budget, pre-fix `prepare()` and post-fix `verify()`. `cve` has a
specialist; `sast`, `iac` and `secret` use the generic pipeline, which behaves
exactly as the orchestrator did before pipelines existed.

```
For each alert (up to 4 in parallel, isolated git worktree per alert):

  1. create_worktree        -> /tmp/orca-fix-<owner>-<repo>-<id>  (isolated branch)
                              clears leftovers from a crashed run; refuses to
                              delete a branch holding commits (skips instead)
  2. pipeline.prepare       -> Phase 0. CVE only: resolve the package and the
                              target version from OSV + deps.dev (see CVE
                              Version Decisions). A failure here is not fatal —
                              the fix proceeds unguided, flagged needs-review.
  3. invoke_fix_agent       -> claude subprocess, --allowedTools Read,Edit,Write,Bash
                              timeout from the pipeline (sast=180s,
                              iac/secret=120s, cve=240s)
                              prompt = fix-agents/<type>.md + prepare() directive
                              retries: up to 2 on json_parse / subprocess errors
  4. validate (Phase 1)     -> Python: diff non-empty, diff size, no new secrets,
                              and the agent's diff_summary must not name a
                              version its own diff never added
                              diff = `git add -A -N` + `git diff`, so created
                              files count; size limit from the pipeline
  5. validate (Phase 2)     -> LLM: does the fix address the vulnerability?
  6. pipeline.verify        -> Phase 3. CVE: the manifest actually pins the
                              resolved version, the lockfile agrees, the applied
                              version carries no known advisory, and — on a
                              --cve run — the requested advisory is genuinely
                              cleared by it.
                              Other types: local build (see Language Coverage)
  7. impact_agent           -> claude subprocess: diff + the resolved bump
                              distance -> production risk JSON
  8. git-commit             -> run_agent.py git-commit
  9. open-pr                -> run_agent.py open-pr (impact + version rationale
                              in the PR body)
 10. validate (Phase 4)     -> Orca check gate (see Orca Check Gate below)
 11. validate (Phase 5)     -> CI gate: gh pr checks --watch (timeout: 10min)
 12. notify                 -> console + log file (+ webhook if configured)
 13. remove_worktree        -> cleanup worktree + local branch (runs in a finally,
                              so it happens on every exit path incl. exceptions)
```

### Remote mode (`--remote owner/repo` or `--remote all`)

Adds a repo-level wrapper around the per-alert pipeline above.

```
--remote owner/repo:
  1. gh repo clone -> /tmp/orca-global-<owner>-<repo>/  (shallow, --depth=1)
  2. fetch alerts for that repo (via Orca API)
  3. per-alert pipeline (same 11 steps above, git ops run inside the clone)
  4. shutil.rmtree -> cleanup clone (always, even on failure)

--remote all:
  1. list_repositories(token)  -> Orca CodeRepository query -> list of repos with open alerts
  2. For each repo (up to 3 in parallel):
       same 4 steps as --remote owner/repo
  3. global summary table (per-repo breakdown + totals)

Max concurrent Claude subprocesses: 3 repos x 4 alerts = 12
```

## Orca Check Gate

Phase 4 runs **after the PR is opened**: it polls the Orca GitHub App check (default
`orca-security-us`) on the PR head commit via the `gh` CLI and treats new findings the
App reports as regressions introduced by the fix.

1. **Resolve** the PR head SHA (`gh pr view`)
2. **Find** the Orca check run among the commit's check-runs (case-insensitive name match)
3. **Poll** until the check completes or `timeout_sec` elapses
4. **On failure**, fetch the check annotations (file, line, message, severity) as findings

**Retry on failure:** when the check reports findings, the orchestrator reverts the fix,
re-invokes the fix agent with the annotations as feedback, re-validates locally
(sanity + build), and pushes the new fix to the same PR branch — up to `max_retries`
times. After retries are exhausted, behavior follows `on_failure` (`retry`/`fail`/`skip`).

**Pass conditions:**
- Check concludes `success` or `neutral`
- Check `skipped` or not found after the grace period → passes, flagged `needs-review`

**Configuration** (`orca_check:` section of `config.py`, overridable via
`SECURITY_ENGINEER_CONFIG` YAML — see also `version_data:` under CVE Version
Decisions):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Run the gate at all |
| `check_name` | `orca-security-us` | Substring matched against check-run names |
| `timeout_sec` | `600` | Max time to wait for the check to complete |
| `poll_interval_sec` | `15` | Delay between polls |
| `max_retries` | `1` | Fix-agent re-invocations on failure |
| `on_failure` | `retry` | `retry` \| `fail` \| `skip` after retries exhausted |
| `on_not_found` | `skip` | `skip` \| `fail` when the check never appears |

**Environment:** Relies on `gh` being authenticated for the target repo; no `orca-cli`
binary or API token is needed on the runner.

## CVE Version Decisions

For a package CVE, the target version is resolved **before** the fix agent runs,
by `skills/lib/version_data.py`. The agent is told which version to apply rather
than asked to work it out.

**Sources** (both free, unauthenticated, and cached on disk):

| Source | Supplies |
|---|---|
| OSV.dev `POST /v1/query` | advisory ranges — which versions each advisory affects |
| deps.dev v3 | which versions were actually published |

**Policy: minimum safe at any distance.** The target is the lowest published
release that clears *every* advisory affecting the installed version — queried
package-wide, not just for the alert's own CVE, so a bump cannot land on a
different known vulnerability. Crossing a major boundary is not refused, because
some packages have no safe release inside the current major; instead the distance
is classified (`bump_class`, `majors_crossed`) and handed to impact analysis.

This policy is what makes a `--cve` run go wider than the advisory named: the
target clears the requested CVE *and* the package's others. Phase 3 confirms the
requested one specifically, matching OSV aliases as well as ids — OSV collapses
the CVE and GHSA records for one flaw into a single id, so the requested CVE
often survives only as an alias.

**Ecosystems:** PyPI, npm, Go, Maven, Cargo, RubyGems, NuGet. The ecosystem comes
from the manifest filename in the alert's `source`; the package name is whichever
manifest entry the alert's prose names, cross-checked against the manifest, which
is the authority. Per-ecosystem agent instructions live in `fix-agents/cve/`.

**Inspect a decision by hand** — no Orca token or alert needed. `run_agent.py`
sits beside `orchestrator.py` in the plugin's `skills/run/`:

```bash
python3 run_agent.py resolve-version pypi pillow 8.3.1
python3 run_agent.py resolve-version ./app/requirements.txt requests 2.20.0
```

The same rationale, cleared advisories and reproduce command appear in the PR body.

**Configuration** (`version_data:` section):

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | `false` reverts CVEs to the generic pipeline entirely |
| `cache_dir` | `~/.cache/security-engineer/version-data` | On-disk cache location |
| `cache_ttl_sec` | `21600` (6h) | Cache lifetime; `0` forces a refetch |
| `timeout_sec` | `20` | Per-request HTTP timeout |
| `offline` | `false` | Serve from cache only; never call out |
| `osv_url` / `deps_dev_url` | upstream defaults | Override the endpoints |

**Degradation:** every failure — unknown ecosystem, unparsed manifest, API
outage, no safe version — leaves the fix running on the agent's own judgement
with the alert flagged `needs-review`. A data-layer problem costs determinism,
not the fix.

## Language Coverage

Phase 3 is the type's `pipeline.verify()`.

**CVE** does not use the build-command table below. A dependency bump touches
manifests and lockfiles, whose extensions (`.txt`, `.mod`, `.json`) never matched
any entry, so this table silently did nothing for CVE fixes. Instead the CVE
pipeline asserts the manifest pins the resolved version, that a lockfile beside it
agrees, and that the applied version carries no known advisory — then runs an
ecosystem resolve check where one is cheap and offline (`go build ./...` for Go,
`cargo metadata --locked` for Cargo). `pip install` / `npm install` / `mvn` are
deliberately not run: they are slow, need the network, and rewrite lockfiles,
which is the fix agent's job. CI covers what is left.

**sast / iac / secret** use the generic pipeline, which runs the language check
below. The build root is detected by walking up from the affected file — the path
comes from the Orca alert (`source` field), so monorepos and subdirectory apps are
handled correctly.

| Language | Detection | Build command | Notes |
|---|---|---|---|
| Go | nearest `go.mod` | `go build ./...` | Skipped if `go` not installed |
| JavaScript / TypeScript | nearest `package.json` | `npm run build --if-present` | Skipped if `npm` not installed; `--if-present` means no `build` script = pass |
| Python | per-file | `python3 -m py_compile <file>` | Syntax-only; no project root needed |
| Terraform | directory of `.tf` file | `terraform validate` | Skipped if `terraform` not installed |
| Dockerfile / YAML / other | — | skipped | No build check |

If the build tool is not installed, the check passes (skip, not fail) — the Orca
check and CI gates catch regressions.

## Notifications

Always active:
- Console output (`[OK]`, `[FAIL]`, `[TOUT]`, etc.)
- `security-engineer-run.json` — newline-delimited JSON log of all events

Opt-in:
- `NOTIFY_WEBHOOK_URL=https://...` -> HTTP POST on every event (Slack, Teams, etc.)
The impact assessment goes into the **PR body** at creation time (step 8), not a
separate comment — impact is computed before the PR is opened, so a comment could
only repeat it.

## Environment Variables

| Variable | Required | Purpose |
|---|---|---|
| `ORCA_API_TOKEN` | Yes | Orca API token (base64 string from Orca config) |
| `NOTIFY_WEBHOOK_URL` | No | Webhook for Slack/Teams notifications |
