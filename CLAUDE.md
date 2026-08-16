# Working in this repository

This is a Claude Code plugin marketplace carrying two plugins, contributed to in
two different ways. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

## `skills/orca-*/` — the `orca-skills` plugin

Plain Markdown. One directory per skill, `SKILL.md` inside it, the directory name
matching the `name:` in its frontmatter. No build step, no runtime, no tests.
Match the structure of the neighbouring skills rather than inventing a new one.

## `plugins/security-engineer/` — the `security-engineer` plugin

Python. Every `make` target runs from that directory, not the repository root.

Every new function or behaviour must have unit tests. Use table-driven tests:
define a `CASES` list of `(description, input, expected)` tuples and loop with
`self.subTest(description)`.

```bash
cd plugins/security-engineer
make test    # 370 unit tests, no API token, no network
make lint    # ruff, shellcheck, marketplace metadata
```

After editing anything the `/security-engineer:run` skill executes, run
`make install` — the skill runs the copy Claude Code made at install time, and
nothing refreshes that copy on its own.
