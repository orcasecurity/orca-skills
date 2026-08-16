# Contributing to Orca Skills

We welcome contributions from the community. This document explains the process and expectations for contributing — whether you're fixing a bug, proposing a new skill, or improving documentation.

## Table of Contents

- [What lives where](#what-lives-where)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)
- [Code of Conduct](#code-of-conduct)

---

## What lives where

This repository is a marketplace carrying two plugins, and they are contributed
to differently.

| Path | Plugin | Contributing to it means |
|---|---|---|
| `skills/orca-*/SKILL.md` | `orca-skills` | Writing Markdown. No build step, no runtime, no tests |
| `plugins/security-engineer/` | `security-engineer` | Writing Python, with unit tests and CI |

`.claude-plugin/marketplace.json` at the root describes both. Each plugin also
carries its own `plugin.json`, and the two must agree — `make lint` in the plugin
directory checks this for every entry.

---

## Reporting Bugs

If a skill produces unexpected output, fails to trigger, or behaves incorrectly:

1. **Search [existing issues](https://github.com/orcasecurity/orca-skills/issues)** before opening a new one.
2. **Open an issue** and include:
   - The skill name (e.g., `orca-alert-triage`)
   - The exact prompt or input you used
   - What you expected vs. what you got
   - Your Claude Code version (`claude --version`) and OS
   - Any error output or unexpected MCP behavior

> For security vulnerabilities, **do not open a public issue**. See [SECURITY.md](SECURITY.md).

---

## Feature Requests

Before writing code for a new skill or a significant change to an existing one:

1. **Open an issue** describing the use case — what problem does it solve, who would use it, and how it fits the project.
2. Wait for a maintainer to weigh in before investing time in implementation.
3. Once the direction is agreed on, proceed with a pull request.

This avoids wasted effort and keeps the repo focused.

---

## Development Setup

```bash
# Fork and clone
git clone https://github.com/<your-username>/orca-skills.git
cd orca-skills
```

Skills in the `orca-skills` plugin are plain Markdown files under
`skills/<skill-name>/SKILL.md` — no build step or runtime is required to author
or modify them. Install them via the Claude Code plugin marketplace (see
[README](README.md)) to try them locally.

**Note:** `.mcp.json` is gitignored. Never commit API tokens or credentials.

### The `security-engineer` plugin

`plugins/security-engineer/` is Python, and every target runs from that
directory:

```bash
cd plugins/security-engineer
pip install ruff==0.16.1 shellcheck-py==0.11.0.1 pyyaml==6.0.3   # what CI pins
make test     # 370 unit tests — no API token, no network
make lint     # ruff, shellcheck, marketplace metadata
make install  # install your working tree as the plugin, to try the skill
```

Three things to know before you send a PR here:

- **Every new function or behaviour needs a unit test**, table-driven: a `CASES`
  list of `(description, input, expected)` looped with `self.subTest`. See
  [`CLAUDE.md`](CLAUDE.md).
- **`make install` after every edit you want the skill to see.** `/security-engineer:run`
  executes the copy Claude Code made at install time, and nothing refreshes it on
  its own — `claude plugin update` short-circuits while the version in
  `plugin.json` is unchanged, and installing over an existing install is a no-op.
  `make install` uninstalls first, which is what defeats that.
- **CI runs only on changes under `plugins/security-engineer/**`**, across Python
  3.10–3.14. It invokes the same `make` targets you do, so a green pull request
  is predictable from your terminal.

The live pipeline — worktree lifecycle, what the gates actually see, whether the
Orca check gate fires — has no automated coverage; it needs a token and a
repository to open pull requests against. Exercise it by hand against a repo you
own before changing anything in the gate path, and say in the PR that you did.

---

## Pull Request Process

1. **Branch off `main`** with a descriptive name:
   ```bash
   git checkout -b fix/alert-triage-timeline
   git checkout -b add/orca-new-skill
   git checkout -b docs/update-readme
   ```

2. **Make your changes.** Edit or add `SKILL.md` files under `skills/<skill-name>/`, or work inside `plugins/security-engineer/`.

3. **Keep PRs focused.** One bug fix or one new skill per PR. Do not bundle unrelated changes.

4. **PR titles** should follow this format:
   - `add: orca-new-skill — one-line description`
   - `fix: orca-alert-triage — describe what was broken`
   - `docs: what was updated`
   - `refactor: what changed and why`

5. **PR description** must include:
   - What changed and why
   - A link to the related issue (if applicable)
   - For new skills: a brief validation note (did you test with a real Orca environment?)

6. **One approving review** from a maintainer is required to merge.

---

## Style Guide

**Skill files (`SKILL.md`), in either plugin:**
- The `name` field must be kebab-case and match the directory name.
- The `description` field is used for AI trigger matching — write it as a complete sentence and include example phrases users might say.
- Instructions should be written in clear, imperative language.
- Each skill should do one thing well — avoid scope creep.

**Markdown:**
- ATX-style headings (`##`, not underlines).
- Code in fenced blocks with a language tag.
- No trailing whitespace.

**Commits:** Use the same prefix format as PR titles (`add:`, `fix:`, `docs:`, `refactor:`).

---

## Code of Conduct

Be respectful and constructive in all interactions — issues, PRs, and review comments. Contributions of all experience levels are welcome. Maintainers may close issues or PRs that are off-topic or that don't meet the project's standards.
