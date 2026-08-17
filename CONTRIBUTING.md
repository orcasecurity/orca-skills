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

Skills are plain Markdown files under `skills/<skill-name>/SKILL.md` — no build step or runtime is required to author or modify them. Install them via the Claude Code plugin marketplace (see [README](README.md)) to try them locally.

**Note:** `.mcp.json` is gitignored. Never commit API tokens or credentials.

---

## Pull Request Process

1. **Branch off `main`** with a descriptive name:
   ```bash
   git checkout -b fix/alert-triage-timeline
   git checkout -b add/orca-new-skill
   git checkout -b docs/update-readme
   ```

2. **Make your changes.** Edit or add `SKILL.md` files under `skills/<skill-name>/`.

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

**Skill files (`SKILL.md`):**
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
