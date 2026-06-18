# Contributing to Orca Skills

We welcome contributions from the community. This document explains the process and expectations for contributing — whether you're fixing a bug, proposing a new skill, or improving documentation.

## Table of Contents

- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Style Guide](#style-guide)
- [Code of Conduct](#code-of-conduct)

---

## Reporting Bugs

If a skill produces unexpected output, fails to trigger, or behaves incorrectly:

1. **Search [existing issues](https://github.com/orcasecurity/orca-skills/issues)** before opening a new one.
2. **Open an issue** and include:
   - The skill name (e.g., `orca-alert-triage`)
   - The exact prompt or input you used
   - What you expected vs. what you got
   - Your client and version (`claude --version` or `codex --version`) and OS
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

**Prerequisites:** Node.js 20+.

```bash
# 1. Fork and clone
git clone https://github.com/<your-username>/orca-skills.git
cd orca-skills

# 2. Verify repository packaging and docs
npm test
```

This validates the Claude, Cursor, and Codex plugin manifests, confirms all 12 skill folders are present, and checks that the Codex plugin package stays synchronized with the root skill files.

**Note:** `.mcp.json` is gitignored. Never commit API tokens or credentials.

---

## Pull Request Process

1. **Branch off `main`** with a descriptive name:
   ```bash
   git checkout -b fix/alert-triage-timeline
   git checkout -b add/orca-new-skill
   git checkout -b docs/update-readme
   ```

2. **Make your changes.** For new or modified skills, update both the root `skills/` tree and the Codex package under `plugins/orca-skills/skills/`. The validation command checks that these copies stay identical.

3. **Run repository validation locally** before pushing:
   ```bash
   npm test
   ```

4. **Keep PRs focused.** One bug fix or one new skill per PR. Do not bundle unrelated changes.

5. **PR titles** should follow this format:
   - `add: orca-new-skill — one-line description`
   - `fix: orca-alert-triage — describe what was broken`
   - `docs: what was updated`
   - `refactor: what changed and why`

6. **PR description** must include:
   - What changed and why
   - A link to the related issue (if applicable)
   - Confirmation that `npm test` passes locally
   - For new skills: a brief validation note for Claude and/or Codex, including whether you tested with a real Orca environment

7. **Maintainer checks must pass.** Maintainers may run the documented Claude and Codex smoke tests before merging.

8. **One approving review** from a maintainer is required to merge.

---

## Style Guide

**Skill files (`SKILL.md`):**
- The `name` field must be kebab-case and match the directory name.
- The `description` field is used for AI trigger matching — write it as a complete sentence and include example phrases users might say.
- Instructions should be written in clear, imperative language.
- Each skill should do one thing well — avoid scope creep.

**Validation:**
- Keep root skills and the Codex plugin copy synchronized.
- Keep examples fabricated. Do not commit real account IDs, emails, alert IDs, or credentials.
- For behavior changes, include a short manual validation note in the PR.

**Markdown:**
- ATX-style headings (`##`, not underlines).
- Code in fenced blocks with a language tag.
- No trailing whitespace.

**Commits:** Use the same prefix format as PR titles (`add:`, `fix:`, `docs:`, `refactor:`).

---

## Code of Conduct

Be respectful and constructive in all interactions — issues, PRs, and review comments. Contributions of all experience levels are welcome. Maintainers may close issues or PRs that are off-topic or that don't meet the project's standards.
