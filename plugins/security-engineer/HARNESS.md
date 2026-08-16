# The harness

A model writes the fix. Everything else here decides what it is asked to do,
which facts it is handed, and what has to be true before its output reaches a
pull request. That scaffolding is the harness, and it is the part that makes an
autonomous remediation run something you can leave unattended.

Two properties hold it together:

- **Non-determinism is confined.** Four model calls exist in a run
  ([below](#the-four-model-calls)). Everything around them — alert selection,
  version choice, branch lifecycle, every gate, the PR body — is deterministic
  Python in `skills/run/`.
- **Nothing is taken on the model's word.** Every claim a model makes is checked
  against something outside it: the diff, the manifest, an advisory database, or
  GitHub. Where a check cannot run, the alert is labelled rather than passed
  silently.

---

## Shape of a run

```
security-engineer [filter] [flags]
   │
   ├─ Orca API ──► alerts for this repo, partitioned:
   │                 to-fix · branch-exists · scm_posture · unfixable
   │
   └─ for each alert (≤4 in parallel, ≤3 repos in parallel)
        │
        ├─ 0  worktree      isolated /tmp checkout on fix/orca-<id>, cut from main
        ├─ 1  prepare()     CVE: resolve package + target version from OSV/deps.dev
        ├─ 2  fix agent     claude subprocess, tools + timeout scoped to the type
        ├─ 3  GATE sanity   diff non-empty · within budget · no new secrets ·
        │                   summary matches the diff
        ├─ 4  GATE llm      does this diff address the vulnerability?
        ├─ 5  GATE verify   CVE: manifest pins the resolved version, lockfile
        │                   agrees, applied version carries no advisory
        │                   other: language build check
        ├─ 6  impact        production-risk JSON → PR body + label
        ├─ 7  commit + PR
        ├─ 8  GATE orca     poll the Orca GitHub App check on the PR head
        │                   on findings: revert → re-fix with the annotations →
        │                   re-gate → push to the same branch
        ├─ 9  GATE ci       gh pr checks --watch
        └─ 10 teardown      worktree + local branch removed in a `finally`
```

Terminal states: `DONE`, `FAILED`, `TIMED_OUT`, `CI_FAILED`, `SKIPPED`. The
process exits `1` if any alert ended in `FAILED`, `TIMED_OUT` or `CI_FAILED`, so
a `&&` chain or a CI wrapper cannot read a broken run as green.

---

## What the model is *not* asked to decide

The harness is mostly a list of decisions taken away from the model.

| Decision | Who makes it | Where |
|---|---|---|
| Which alerts are in scope | Orca query + filter tokens | `orca_client.fetch_alerts` |
| Whether an alert is fixable | `feature_type` / category rules | `orca_client.is_fixable` |
| Which package a CVE is about | the manifest, with the alert as a hint | `package_identity.identify_package` |
| Which version to bump to | OSV ranges + published version list | `version_data.resolve_bump` |
| Branch name, base, commit, push, PR | Python | `orchestrator`, `run_agent.py` |
| Whether a fix ships | the gates below | `validator`, `pipelines/` |

What is left to a model: writing the code change, judging whether a diff
addresses a vulnerability, judging production impact, and — only when the
manifest yields no match — picking a package name from a fixed list.

---

## Data sources

| Source | Auth | Supplies | If it is unavailable |
|---|---|---|---|
| **Orca serving-layer API** — `POST api.orcasecurity.io/api/serving-layer/query` | `ORCA_API_TOKEN` | Alerts (id, type, risk, category, source path, code snippet, description, recommendation, AI triage, labels) and the `CodeRepository` inventory behind `--remote all` | Run exits with a message; nothing is attempted |
| **OSV.dev** — `POST /v1/query` | none | Every advisory for a package, with the version ranges each one affects | CVE falls back to the agent's own judgement, alert flagged `needs-review` |
| **deps.dev v3** — `GET /systems/{eco}/packages/{pkg}` | none | The list of versions actually published | Same |
| **The repository** — manifests and lockfiles | git | The authority on what is installed. `requirements.txt`, `pyproject.toml`, `package.json`, `package-lock.json`, `go.mod`, `pom.xml`, `Cargo.toml`, `Gemfile(.lock)` | Package identification fails → unguided fix, `needs-review` |
| **GitHub** — via `gh` CLI | `gh auth` | PR head SHA, check-runs, **check annotations** (file, line, message), CI status | Gate passes and flags `needs-review` rather than blocking the PR |

The alert is a hint; the repository is the authority. A package named in an
alert title that does not appear in the manifest is not a match — inventing one
is how an agent edits something nobody asked it to touch.

OSV and deps.dev are cached on disk (`~/.cache/security-engineer/version-data`,
6h TTL, atomic write-then-rename). A `--remote all` run can have 12 fixes in
flight against two public APIs; the cache is also what makes the unit tests
hermetic, since they inject a fetcher backed by recorded fixtures.

### The version decision

Policy is **minimum safe at any distance**: the lowest published release that
clears *every* advisory affecting the installed version — queried package-wide,
not just for the alert's own CVE, so a bump cannot land on a different known
vulnerability. A major-version jump is not refused (some packages have no safe
release inside the current major); the distance is measured (`bump_class`,
`majors_crossed`) and handed to impact analysis instead.

The decision is auditable by construction. Target, rationale, advisories
cleared, advisories still open, advisories with no version range, and the
candidates passed over all travel into the PR body, and any of it can be
re-derived without a token, an alert, or a pipeline run:

```bash
python3 skills/run/run_agent.py resolve-version pypi pillow 8.3.1
```

---

## The gates

Every pre-PR gate reads the **same diff** — `git add -A -N` then `git diff`, so
untracked files the agent created are included and each gate judges exactly what
the commit will contain.

| # | Gate | Checks | On failure |
|---|---|---|---|
| 1 | **sanity** (`validator.sanity_check`) | Diff is non-empty; within the type's line budget (cve 200, sast 100, iac/secret 50); for `secret` findings, no added line matches a secret pattern; the agent's own `diff_summary` does not name a version its diff never added | `FAILED`, no PR |
| 2 | **llm** (`validator.llm_validate`) | A single-shot model call: does this diff address this alert? `pass` / `fail` / `uncertain` | `fail` → `FAILED`. `uncertain` → passes, PR labelled `needs-review` |
| 3 | **verify** (`pipeline.verify`) | **CVE:** the manifest still declares the package; it is no longer on the version the alert was raised against; if the agent chose a different version, that version carries no known advisory; a lockfile beside the manifest agrees; then `go build ./...` (Go) or `cargo metadata --locked` (Cargo). **Other types:** language build check (below) | `FAILED`, no PR |
| 4 | **orca** (`validator.orca_check_gate`) | Polls the Orca GitHub App check on the PR head SHA. On failure, pulls the check **annotations** — file, line, message | Reverts the worktree to the branch head, re-invokes the fix agent *with the annotations as feedback*, re-runs gates 1 and 3, and pushes a follow-up commit to the same PR branch. After `max_retries`, follows `on_failure` |
| 5 | **ci** (`validator.ci_gate`) | `gh pr checks --watch --fail-fast`, 10 min | `CI_FAILED`, PR labelled `ci-failed`, run exits non-zero. The PR stays open |

Gate 4 is the one that makes the loop closed rather than open: the security
scanner's own findings on the resulting PR are fed back to the agent as
structured evidence, not as "try again". Where a CVE decision exists, the retry
prompt also names the next safe published version, so a second attempt advances
through the candidate list instead of guessing.

### Language build check (gate 3, non-CVE types)

The build root is found by walking up from the affected file — the path comes
from the Orca alert, so monorepos and subdirectory apps resolve correctly.

| Language | Root detection | Command |
|---|---|---|
| Go | nearest `go.mod` | `go build ./...` |
| JavaScript / TypeScript | nearest `package.json` | `npm run build --if-present` |
| Python | per file | `python3 -m py_compile` |
| Terraform | directory of the `.tf` file | `terraform validate` |
| Dockerfile, YAML, other | — | skipped |

A missing toolchain skips the check rather than failing it — gates 4 and 5 catch
what a missing local compiler would have.

CVE fixes deliberately do **not** use this table. A dependency bump touches
`.txt`, `.mod` and `.json` files, none of which matched an entry, so for every
CVE fix this check was a silent no-op until `CvePipeline.verify` replaced it.
`pip install` / `npm install` / `mvn` are still not run: they are slow, need the
network, and rewrite lockfiles, which is the fix agent's job rather than the
gate's.

---

## Structural gates

Not phases, but the same job: constrain what can go wrong.

**Isolation.** Each alert gets its own git worktree at `/tmp/orca-fix-<repo>-<id>`
on its own branch cut from `main`. Teardown runs in a `finally`, so an unexpected
exception cannot leak a directory plus a branch — a leak used to be
self-perpetuating, because the leftover made the next run fail worktree creation,
which was then misreported as "branch already exists" and skipped forever. A
branch carrying commits `main` does not have is never deleted; the alert is
`SKIPPED` instead. `--remote` mode namespaces worktrees by repo so parallel runs
cannot collide.

**Tool scoping.** The fix agent gets `Read,Edit,Write,Bash` live and `Read` alone
in `--dry-run`. Dry-run is enforced three independent ways: the subprocess
physically has no write tools, the orchestrator returns before validation, and
`_commit_and_pr` re-checks the flag.

**Single-shot calls carry no tools at all.** LLM validation, impact analysis and
package identification are text-in / JSON-out, so they run with `--tools ""` and
`--max-turns 1`. `--allowedTools ""` looks equivalent and is not: it only
*denies* the calls, so the model still emits `tool_use`, gets refused, and
retries. Measured over five trials that cost exactly 3 turns every time and 6.2×
the money, with a tail that ran to 7 turns, blew the turn cap, and exited
`error_max_turns` with an empty stderr — at which point both callers took their
silent error path, passing everything as `needs_review` and labelling every PR
`impact:medium`. Removing the definitions makes one turn provably enough. Each
such prompt also ends with an explicit "you have no tools, the material above is
sufficient" contract, because a model that does not know its tools are gone will
otherwise spend its single turn saying it would like to look at the repo.

**Bounded prompts.** Alert passthrough fields are dropped above 4 KB, the diff is
truncated at 5 KB for validation and 6 KB for impact, and an unserializable
payload is replaced with a marker rather than raising inside the prompt builder.

**Retries are typed.** The fix agent is retried only on `json_parse_failure` and
`subprocess_error` — a transport problem. A fix that failed on its merits is not
retried by rerunning the same prompt; the only retry with new information is
gate 4's, which carries the annotations.

**Everything unproven is labelled.** `needs-review` on the PR whenever a gate
passed without being able to confirm; `impact:<level>` from the impact agent;
`ci-failed` when checks go red. Every state transition is emitted to the console,
to `security-engineer-run.json` as NDJSON, and to `NOTIFY_WEBHOOK_URL` if set.

**Concurrency is capped.** 4 alerts per repo, 3 repos — at most 12 concurrent
fix agents.

---

## Degradation policy

A harness that fails closed on every unknown never finishes; one that fails open
everywhere is decoration. The split here is deliberate: **fail closed on evidence
of a bad fix, fail open on absence of evidence — and say so.**

| Situation | Behaviour |
|---|---|
| Empty diff, oversized diff, secret in diff, summary contradicts diff | **Closed** — `FAILED` |
| LLM verdict `fail` | **Closed** — `FAILED` |
| Manifest untouched, dependency removed, lockfile disagrees, applied version still vulnerable | **Closed** — `FAILED` |
| Build command present and exits non-zero | **Closed** — `FAILED` |
| Orca check reports findings | **Closed after retries** — per `on_failure` |
| CI red | **Closed** — `CI_FAILED`, exit 1, PR labelled |
| Branch holds commits not in `main` | **Closed** — `SKIPPED`, work untouched |
| LLM validation times out / errors / returns unparseable output | Open + `needs-review` |
| Orca check absent after the grace period | Open + `needs-review` (`on_not_found: fail` inverts this) |
| PR has no CI configured, or `gh` is missing | Open + `needs-review` |
| Build toolchain not installed | Open — skipped |
| OSV / deps.dev unreachable, unknown ecosystem, unparsed manifest | Open — unguided fix + `needs-review` |
| Impact analysis fails | Open — recorded as `medium`, error kept in the event log |

The one asymmetry worth naming: the advisory lookup that judges an
agent-chosen version fails *open*, because an OSV outage should not turn into a
rejected fix. The "still on the original version" check sits in front of it
precisely so an outage cannot let an untouched manifest through.

---

## Configuration

Secrets stay in the environment. Everything else is a YAML file pointed at by
`SECURITY_ENGINEER_CONFIG`; without it, the built-in defaults apply.

| Section | Key | Default | Meaning |
|---|---|---|---|
| `orca_check` | `enabled` | `true` | Run gate 4 at all |
| | `check_name` | `orca-security-us` | Substring matched against check-run names |
| | `timeout_sec` / `poll_interval_sec` | `600` / `15` | How long, how often |
| | `max_retries` | `1` | Fix-agent re-invocations with annotation feedback |
| | `on_failure` | `retry` | `retry` \| `fail` \| `skip` once retries are spent |
| | `on_not_found` | `skip` | `skip` \| `fail` when the check never appears |
| `version_data` | `enabled` | `true` | `false` reverts CVEs to the generic pipeline |
| | `cache_dir` / `cache_ttl_sec` | `~/.cache/…` / `21600` | On-disk cache; `0` forces a refetch |
| | `timeout_sec` | `20` | Per-request HTTP timeout |
| | `offline` | `false` | Serve from cache only, never call out |
| | `osv_url` / `deps_dev_url` | upstream | Override endpoints |
| top level | `max_parallel_fixes` / `max_parallel_repos` | `4` / `3` | Concurrency caps |

Note the check-name default: the Orca App posts checks named
`Orca Security - SAST`, `… - Vulnerabilities`, `… - IaC`, `… - Secrets`. The
default matches none of them as a substring, which is why `devloop/orca-check.yaml`
overrides it — see below.

---

## Extending it

Specializing a finding type means adding a `FixPipeline`, not editing the
orchestrator. A pipeline owns its timeout, diff budget, `prepare()` (work out
what the agent should be *told* rather than left to decide) and `verify()` (the
post-fix check that actually matters for this type). `cve` has a specialist;
`sast`, `iac` and `secret` use the generic pipeline, which behaves exactly as
the orchestrator did before pipelines existed. Register it in
`skills/run/pipelines/__init__.py`.

Notification backends are the same shape: implement `send()`, register in
`build_notifiers()`.

---

## Proving the harness works

Two layers, because they catch different things.

**Unit tests** — 379 across seven suites, table-driven per `CLAUDE.md`, no token
and no network:

```bash
make test
```

They cover argument parsing, flag validation, version ordering and advisory
range logic, manifest parsing for every supported ecosystem, gate behaviour on
mocked diffs, and the dry-run guarantees.

**Static checks** — the linters, plus the plugin-metadata checks that no Python
suite can see (version drift between `plugin.json` and `marketplace.json`, a
lost executable bit, missing skill frontmatter):

```bash
make lint
```

Both run on every pull request via `.github/workflows/ci.yml`, `make test`
across Python 3.10–3.14. CI calls the same Make targets, so it cannot drift from
what you run locally.

**The dev loop** — the parts that only exist in a live run: worktree lifecycle,
whether the diff the gates judge is the diff that gets committed, whether gate 4
fires at all, whether annotation feedback reaches the agent on retry.

```bash
make fast                      # test → install → reset → fix one CVE → report
make loop ARGS="--dry-run cve" # plan only, no writes
```

`devloop/observe.py` joins the run's NDJSON event log with live GitHub state and
prints one verdict per alert plus the annotations behind any failure, with
meaningful exit codes (`0` all good, `1` failure or still running, `2` nothing
exercised — reset the sandbox). It imports nothing from `skills/`, so it keeps
working while the pipeline is being rewritten underneath it.

Full runbook, sandbox requirements and failure-signature table:
[`devloop/README.md`](devloop/README.md). Nothing in `devloop/` ships with the
plugin.

---

## What the harness does not do

Stated plainly, because a gate list reads as a guarantee otherwise.

- **It does not prove a fix is correct.** Gates 1–3 prove a change was made, is
  proportionate, matches its own description, and builds. Correctness beyond
  that rests on gate 2's judgement, gate 4's rescan, and a human reading the PR.
- **Nothing is merged.** Every run ends at an open PR with an impact assessment
  and labels. A person merges.
- **Runtime behaviour is untested.** No test suite is executed — only build and
  compile checks. A dependency bump that type-checks and breaks at runtime
  reaches the PR, which is why bump distance is measured and passed to impact
  analysis.
- **Gate 4 depends on an integration outside this repo.** If the Orca GitHub App
  is not posting checks, the strongest gate degrades to `needs-review`.
  `on_not_found: fail` makes that loud where silence is worse.
