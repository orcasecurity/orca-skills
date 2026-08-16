#!/usr/bin/env python3
"""Static checks on the plugin's own metadata — the breakages unit tests can't see.

The unit suites exercise Python behaviour. Nothing in them reads
`.claude-plugin/`, so the failures that only surface at install time have no
gate at all:

  version drift   `plugin.json` and `marketplace.json` both carry a version, and
                  the Makefile reads the one in plugin.json. When they disagree,
                  `claude plugin install` resolves the marketplace's number and
                  the tree you installed is not the tree you thought.
  lost +x         `bin/security-engineer` is on PATH once the plugin is
                  installed. Strip its executable bit and the CLI stops being a
                  command, with nothing in Python to notice.
  frontmatter     A skill whose SKILL.md loses `name` or `description` silently
                  stops being discoverable, and a `name` that disagrees with its
                  directory resolves to a skill that isn't there.

Every check is a pure function over already-parsed data, returning a list of
human-readable problems, so each one is unit-testable without a filesystem
(tools/tests/test_check_manifests.py). Only `main` touches disk.

Run: python3 tools/check_manifests.py
"""
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Shell entry points that are invoked as commands rather than sourced or passed
# to an interpreter, so the executable bit is load-bearing.
EXECUTABLES = [
    "bin/security-engineer",
    "install.sh",
    "devloop/run.sh",
    "devloop/reset.sh",
    "devloop/config.sh",
]


def parse_frontmatter(text: str) -> dict:
    """Top-level `key: value` pairs from a leading `---` fenced block.

    Deliberately not a YAML parser: the keys these files carry are flat strings,
    and a stdlib-only checker cannot import PyYAML. Returns {} when the document
    has no frontmatter, which every caller reports as the error it is.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    fields = {}
    for line in lines[1:]:
        if line.strip() == "---":
            break
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line or line[0].isspace():
            # A continuation or nested line: only top-level keys are needed, and
            # guessing at the rest is how a hand-rolled parser starts lying.
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip().strip('"').strip("'")
    return fields


def check_manifest_agreement(plugin: dict, marketplace: dict) -> list:
    """plugin.json and the marketplace entry describing it must say the same thing."""
    problems = []
    name = plugin.get("name")
    if not name:
        return ["plugin.json: missing required key 'name'"]
    if not plugin.get("version"):
        problems.append("plugin.json: missing required key 'version'")

    entries = marketplace.get("plugins") or []
    matching = [e for e in entries if e.get("name") == name]
    if not matching:
        listed = ", ".join(sorted(str(e.get("name")) for e in entries)) or "none"
        return [
            *problems,
            f"marketplace.json: no plugin entry named '{name}' (found: {listed})",
        ]

    for entry in matching:
        for key in ("version", "description"):
            ours, theirs = plugin.get(key), entry.get(key)
            if ours != theirs:
                problems.append(
                    f"marketplace.json: '{name}' {key} is {theirs!r}, "
                    f"but plugin.json says {ours!r} — the installer resolves the "
                    f"marketplace value, so these must agree"
                )
    return problems


def check_skill_frontmatter(skills: list) -> list:
    """Each (directory_name, SKILL.md frontmatter) pair must be discoverable.

    A skill's directory name is its invocable name, so a `name:` that disagrees
    with the directory points at a skill that cannot be resolved.
    """
    problems = []
    for dir_name, fields in skills:
        if not fields:
            problems.append(f"skills/{dir_name}/SKILL.md: no frontmatter block")
            continue
        for key in ("name", "description"):
            if not fields.get(key):
                problems.append(f"skills/{dir_name}/SKILL.md: missing '{key}:'")
        declared = fields.get("name")
        if declared and declared != dir_name:
            problems.append(
                f"skills/{dir_name}/SKILL.md: name is '{declared}' but the "
                f"directory is '{dir_name}' — the directory name is the skill name"
            )
    return problems


def check_command_frontmatter(commands: list) -> list:
    """Each (relative_path, frontmatter) pair needs a description to render in the menu."""
    problems = []
    for path, fields in commands:
        if not fields:
            problems.append(f"{path}: no frontmatter block")
        elif not fields.get("description"):
            problems.append(f"{path}: missing 'description:'")
    return problems


def check_executable_bits(modes: list) -> list:
    """Each (relative_path, is_executable) pair for a file meant to be run."""
    return [
        f"{path}: not executable — `chmod +x {path}` (it is invoked as a command)"
        for path, executable in modes
        if not executable
    ]


def _read_json(path: Path) -> tuple:
    """(parsed, problems). A parse failure is reported, never raised."""
    try:
        return json.loads(path.read_text()), []
    except FileNotFoundError:
        return {}, [f"{path.relative_to(REPO_ROOT)}: missing"]
    except json.JSONDecodeError as e:
        return {}, [f"{path.relative_to(REPO_ROOT)}: invalid JSON — {e}"]


def main() -> int:
    problems = []

    plugin, errs = _read_json(REPO_ROOT / ".claude-plugin" / "plugin.json")
    problems += errs
    marketplace, errs = _read_json(REPO_ROOT / ".claude-plugin" / "marketplace.json")
    problems += errs
    if not problems:
        problems += check_manifest_agreement(plugin, marketplace)

    # Every other tracked JSON file only has to parse. Fixtures included: a
    # truncated fixture fails the suite that reads it with a confusing error.
    for path in sorted(REPO_ROOT.glob("**/*.json")):
        if ".claude-plugin" in path.parts or "__pycache__" in path.parts:
            continue
        if any(part in (".git", "runs", ".claude", "node_modules") for part in path.parts):
            continue
        problems += _read_json(path)[1]

    skills_dir = REPO_ROOT / "skills"
    skills = [
        (d.name, parse_frontmatter((d / "SKILL.md").read_text()))
        for d in sorted(skills_dir.iterdir())
        if d.is_dir() and (d / "SKILL.md").exists()
    ]
    if not skills:
        problems.append("skills/: no SKILL.md found — the plugin exposes no skills")
    problems += check_skill_frontmatter(skills)

    commands = [
        (str(p.relative_to(REPO_ROOT)), parse_frontmatter(p.read_text()))
        for p in sorted((REPO_ROOT / "commands").glob("*.md"))
    ]
    problems += check_command_frontmatter(commands)

    problems += check_executable_bits([
        (rel, os.access(REPO_ROOT / rel, os.X_OK))
        for rel in EXECUTABLES
        if (REPO_ROOT / rel).exists()
    ])

    if problems:
        print(f"{len(problems)} problem(s) in the plugin metadata:\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"Plugin metadata OK — v{plugin.get('version')}, "
          f"{len(skills)} skill(s), {len(commands)} command(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
