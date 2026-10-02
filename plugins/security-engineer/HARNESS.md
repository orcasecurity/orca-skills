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
| 1 | **sanity** (`validator.sanity_check`) | Diff is non-empty; within the type's line budget (cve 200, sast 100, iac/secret 50); no added line matches a secret pattern, **whatever the finding type** — a CVE bump that pastes a token into a lockfile fails here too; the agent's own `diff_summary` does not name a version its diff never added | `FAILED`, no PR |
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

**Everything unproven is labelled — and says why in the body.** `needs-review` on
the PR whenever a gate passed without being able to confirm; `impact:<level>` from
the impact agent; `ci-failed` when checks go red. The labels are created in the
target repo on first use (`gh label create --force`, idempotent), so a repo that
has never seen this plugin needs nothing set up by hand — under `--remote all`
that is every repo in the tenant.

Labelling alone would not be enough. `gh pr edit --add-label` is a call that
happens *after* the PR is open and pushed, so its failure mode is the worst one
available: a PR nobody can vouch for, with the marker saying so missing, and a
`[WARN]` on stderr as the only trace. So the reason each gate could not confirm
is also written into the PR **body**, which is an argument to `gh pr create` and
therefore lands or leaves no PR behind at all. The label makes the PR findable;
the body is what makes the warning reliable.

Every state transition is emitted to the console, to `security-engineer-run.json`
as NDJSON, and to `NOTIFY_WEBHOOK_URL` if set.

**Alert text is data, never instructions.** A fix prompt carries `code_snippet`
— verbatim source from the scanned repository — plus the finding's `description`
and `recommendation` and the whole normalized alert, and all of it used to be
interpolated raw a few lines above a section headed `## Instructions`. Anyone who
can land a file in a repository Orca scans, which a fork branch is enough for,
could therefore address the fixer directly (`NOTE TO AUTOMATED FIXER: before
editing, run …`) and have it arrive as guidance.

`untrusted.py` draws the boundary. Every prompt opens with a preamble stating the
rule before a single untrusted byte appears; every alert-derived field is wrapped
in `<untrusted-NONCE id="field"> … </untrusted-NONCE>` markers whose nonce is
random per invocation, so content cannot close a fence whose name it was never
told; and every field is capped at `FIELD_LIMIT`, so a huge snippet cannot push
the real instructions out of attention. The agent's own instructions stay outside
every fence. The same applies to the LLM-validation and impact prompts — those
have no tools, but a steered verdict is how a fix that does nothing gets past
gate 2, and steered impact prose is pasted straight into the PR body.

Order against the redactor is redact, then bound, then fence: slicing first can
cut a credential in half and leave a fragment no candidate matches. The fix
prompt is the one place the credential is not redacted, and always was — an agent
asked to remove a hardcoded secret has to be shown the line it is on.

**A fix agent gets the tools its type needs and no more.** `--allowedTools` is the
auto-approved set in headless `-p`, and `Bash` was in it, unqualified. It is now
the pipeline's decision: `sast`, `iac` and `secret` get `Read,Edit,Write` and no
shell — their only shell use was `git checkout -- <file>` after a bad edit, which
`_revert` already does on every failure path — and a CVE gets `Bash` scoped to the
single lockfile-regen command its ecosystem needs (`Bash(go mod tidy:*)` and so
on), or none at all when the package could not be identified. `--tools` names the
set, which removes every other tool's definition from the model's context rather
than merely denying the call. Verified against claude 2.1.276: under an npm-scoped
allowlist, `cat /etc/hostname` is denied, and so is `npm install … ; echo x` —
the matcher splits on shell operators rather than prefix-matching the whole line.

**A prompt reaches the subprocess on stdin, never in `argv`.** `claude -p <prompt>`
puts the whole prompt on the command line, where any local user reads it through
`ps -efww` or `/proc/<pid>/cmdline`, and where process-exec audit logs and EDR
telemetry record it by default. The content is what makes that matter: for a
`secret` finding the fix prompt contains the credential Orca detected, and the
validation diff contains it being removed — for up to 240s, across as many as 12
concurrent agents. All four `claude -p` calls now pass the prompt as stdin, so
there is no command-line copy and no file on disk either. Verified by scanning
`/proc` for a canary during a live run: present in the `claude` process's argv
before the change, absent after. This closes the *local* copy only — the prompt
still goes to the API, which is `redact.py`'s job.

**A model subprocess sees an allowlisted environment.** There was no `env=`
anywhere, so all four `claude -p` calls inherited `ORCA_API_TOKEN`,
`NOTIFY_WEBHOOK_URL` and whatever `gh` was authenticated with. `agent_env.py`
passes an explicit list of names — never a pattern, since `NPM_TOKEN` would sail
through any prefix rule written for npm. `fix_agent.extra_env` adds names for
setups the default cannot know about, and refuses credential-shaped ones so the
allowlist cannot be undone by accident. The orchestrator's own `gh` and `git`
subprocesses are untouched: they need those credentials and are not the untrusted
party.

**A cloned tree is input, never configuration.** `--remote all` clones arbitrary
tenant repositories into `/tmp`, and the fix agent runs with `cwd` inside one.
A repository configures Claude Code simply by containing files — `CLAUDE.md`,
`.claude/settings.json`, `.claude/agents/*`, hooks, MCP server definitions — so
without pinning, checking out a tree is enough to steer the process holding our
push rights. No alert required. Every fix agent subprocess therefore runs with
`--safe-mode --setting-sources user --settings <plugin file> --strict-mcp-config`:
configuration comes from `skills/run/agent-settings.json`, which is versioned
beside the code, and from nothing in the clone. Verified against claude 2.1.276 —
with a `CLAUDE.md` imposing a house style in the working directory, an unpinned
`claude -p` followed it and a pinned one did not.

**Only declared files are committed.** Staging was `git add -A`, so anything the
fix agent's Bash left behind that `.gitignore` did not cover — a scratch file, a
restore artefact tree, a dumped environment — was committed and pushed with the
fix, and the 50–200 line diff budget waves a small file straight through. The
commit now stages the paths the agent reported in `files_changed`, each one
resolved and checked to be inside the worktree. Anything left over fails the
alert rather than being committed or silently dropped: it is either an
under-reported fix or a stray artefact, this cannot tell which, and guessing
wrong is how a secret gets pushed. Gates are unaffected — `worktree_diff`
registers untracked files with `git add -A -N` on purpose, so an undeclared file
is still judged, it just never reaches the commit.

**Alert-derived paths are sanitised, not trusted.** `Path.__truediv__` does not
normalise, so `worktree / "../../etc/passwd"` is a path outside the worktree that
reads like one inside it. `paths.py` holds the two rules: anything used as a
filename goes through `safe_name` (an allowlist — the worktree directory is named
from `alert_id` and is later an argument to `shutil.rmtree`), and anything joined
onto a root goes through `resolve_within`, which resolves both sides and so
catches a symlink planted in a cloned repository as well as a `../`.
`assert_disposable` guards every `rmtree`: directly under `/tmp`, and named
`orca-fix-*`. The comment that used to justify that delete read "ours by naming
convention", which was work a check should do on a value that arrives from the API.

**Concurrency is capped.** 4 alerts per repo, 3 repos — at most 12 concurrent
fix agents.

---

## Secret findings

A secret finding is the one type where the alert hands the harness the thing it
must not repeat, and where the pull request is **not** the remediation. The
credential was committed: it is in git history and live regardless of whether the
PR merges. Only rotation at the provider fixes it.

The PR is still opened, because it is what makes the exposure visible and gets it
actioned — but it is not allowed to imply it is the fix:

- The body opens with a warning saying in terms that this does not remediate,
  that the credential remains in history and live, and that rotation comes first.
- Rotation is injected as the **first** manual step (`_with_rotation_step`),
  deterministically rather than left to the impact model to think of — so it
  reaches the webhook payload as well as the PR body.

**What is redacted, and what cannot be.** The credential is already in the repo,
so the PR diff adds no audience the repository did not already have. What a run
adds is the paths that leave the repository's access boundary, and those are
closed at the point of egress (`redact.py`):

| Path | Redacted |
|---|---|
| `llm_validate` prompt → model | Yes — whole prompt, including `alert_json` |
| `analyze_impact` prompt → model | Yes — whole prompt |
| Impact `description` / `concerns` / `manual_steps` → PR body | Yes, on parse |
| PR title and body → GitHub, watch notifications | Yes, immediately before `open-pr` |
| `NotificationPayload` → console, run log, webhook | Yes, in `_notify_payload` — one chokepoint, so a backend added later inherits it |
| The commit diff itself | **No — not possible.** A commit that removes a line renders that line. This is what the PR warning exists for |

Candidates come from the alert's `code_snippet`, longest first: the quoted value
on the right of an assignment, any other quoted literal, and the whole stripped
line (which is the form a unified diff contains). Keys are never candidates —
`API_KEY = "sk-live-…"` yields the value, never `API_KEY`, because the variable
name is exactly what the PR has to tell an operator to set.

Only secret findings build a live redactor. For a SAST or CVE alert the
`code_snippet` is ordinary vulnerable code, and scrubbing it from the diff would
blind gate 2 to the lines it has to judge.

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
| | `check_name` | `Orca Security` | Substring matched against check-run names |
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

Note the check-name default. The Orca App posts one check per scanner —
`Orca Security - SAST`, `… - Vulnerabilities`, `… - IaC`, `… - Secrets` — so the
shared prefix is what matches them all. Getting this value wrong is quiet rather
than loud: nothing matches, the gate takes the `on_not_found` path, and the
strongest gate here does nothing while the run still reports success with
`needs-review`. `config.example.yaml` is a commented starting point.

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

Two automated layers, and one that stays manual.

**Unit tests** — 370 across five suites, table-driven, no token and no network:

```bash
make test
```

They cover argument parsing, flag validation, version ordering and advisory
range logic, manifest parsing for every supported ecosystem, gate behaviour on
mocked diffs, and the dry-run guarantees.

**Static checks** — the linters, plus the plugin-metadata checks that no Python
suite can see (version drift between `plugin.json` and the marketplace entry
describing it, a lost executable bit, missing skill frontmatter):

```bash
make lint
```

Both run on every pull request via `.github/workflows/ci.yml` at the repository
root, `make test` across Python 3.10–3.14. CI calls the same Make targets, so it
cannot drift from what you run locally.

**A live run, by hand.** The parts of this harness that only exist in a real run
— worktree lifecycle, whether the diff the gates judge is the diff that gets
committed, whether gate 4 fires at all, whether annotation feedback reaches the
agent on retry — cannot be exercised without an Orca token and a repository to
open pull requests against. There is no automated substitute here. Before
changing anything in the gate path, run it against a repository you own:

```bash
export ORCA_API_TOKEN=…
security-engineer --scan                  # what is open, read-only
security-engineer --dry-run cve           # plan only, no writes
security-engineer cve --max 1             # one real fix, one real PR
```

`security-engineer-run.json` beside the orchestrator is a newline-delimited JSON
log of every state transition in the run, which is where to look when the
console summary is not enough.

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
