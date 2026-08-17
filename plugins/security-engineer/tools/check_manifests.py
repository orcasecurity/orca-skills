#!/usr/bin/env python3
"""Static checks on the marketplace's metadata — the breakages unit tests can't see.

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

This repository is a marketplace carrying more than one plugin, and the two
manifests no longer sit side by side: `marketplace.json` is at the repository
root, `plugin.json` under the plugin it describes. So the checks read the
marketplace at the root but scope everything else to *this* plugin — its own
entry, its own skills, its own commands. The other plugins in this marketplace
are not this file's business.

Every check is a pure function over already-parsed data, returning a list of
human-readable problems, so each one is unit-testable without a filesystem
(tools/tests/test_check_manifests.py). Only `main` touches disk.

Run: python3 tools/check_manifests.py
"""
import json
import os
import sys
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent   # plugins/security-engineer
MARKETPLACE_ROOT = PLUGIN_ROOT.parents[1]              # the repository root

# Shell entry points that are invoked as commands rather than sourced or passed
# to an interpreter, so the executable bit is load-bearing. Relative to
# PLUGIN_ROOT — no other plugin in this marketplace ships an executable.
EXECUTABLES = [
    "bin/security-engineer",
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


def check_entry_sources(entries: list) -> list:
    """Each marketplace entry needs a name and a source that stays in the tree.

    `source` is the path to the plugin root relative to the marketplace root, so
    an absolute path or one climbing out with `..` resolves somewhere the
    installer will not follow.
    """
    problems = []
    for index, entry in enumerate(entries):
        entry = entry or {}
        name = entry.get("name") or f"plugins[{index}]"
        source = entry.get("source")
        if not source:
            problems.append(f"marketplace.json: '{name}' has no 'source'")
            continue
        if not isinstance(source, str):
            # A non-string source is one of the remote forms (github, git-subdir,
            # npm...). Nothing on disk to check, and not this repo's shape.
            continue
        if source.startswith("/") or ".." in Path(source).parts:
            problems.append(
                f"marketplace.json: '{name}' source {source!r} must be a "
                f"relative path inside the marketplace"
            )
    return problems


def check_skill_frontmatter(skills: list) -> list:
    """Each (skill_directory, SKILL.md frontmatter) pair must be discoverable.

    A skill's directory name is its invocable name, so a `name:` that disagrees
    with the directory points at a skill that cannot be resolved. The directory
    is passed as a path so the message locates the file in a repository holding
    several plugins; only its last segment is the skill name.
    """
    problems = []
    for skill_dir, fields in skills:
        dir_name = Path(skill_dir).name
        if not fields:
            problems.append(f"{skill_dir}/SKILL.md: no frontmatter block")
            continue
        for key in ("name", "description"):
            if not fields.get(key):
                problems.append(f"{skill_dir}/SKILL.md: missing '{key}:'")
        declared = fields.get("name")
        if declared and declared != dir_name:
            problems.append(
                f"{skill_dir}/SKILL.md: name is '{declared}' but the "
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


def _rel(path: Path) -> str:
    """Repository-relative display path, or the absolute one if it escapes."""
    try:
        return str(path.relative_to(MARKETPLACE_ROOT))
    except ValueError:
        return str(path)


def _read_json(path: Path) -> tuple:
    """(parsed, problems). A parse failure is reported, never raised."""
    try:
        return json.loads(path.read_text()), []
    except FileNotFoundError:
        return {}, [f"{_rel(path)}: missing"]
    except json.JSONDecodeError as e:
        return {}, [f"{_rel(path)}: invalid JSON — {e}"]


def _collect_plugin(root: Path) -> tuple:
    """(skills, commands, problems) for one plugin directory.

    Skills are (repository-relative directory, frontmatter) pairs; commands the
    same shape for their files. A plugin with no skills at all is reported —
    that is a plugin the marketplace lists and Claude Code has nothing to load
    from.
    """
    problems = []

    skills_dir = root / "skills"
    skills = [
        (_rel(d), parse_frontmatter((d / "SKILL.md").read_text()))
        for d in sorted(skills_dir.iterdir())
        if d.is_dir() and (d / "SKILL.md").exists()
    ] if skills_dir.is_dir() else []
    if not skills:
        problems.append(f"{_rel(skills_dir)}: no SKILL.md found — this plugin exposes no skills")

    commands = [
        (_rel(p), parse_frontmatter(p.read_text()))
        for p in sorted((root / "commands").glob("*.md"))
    ]
    return skills, commands, problems


def main() -> int:
    problems = []

    plugin, errs = _read_json(PLUGIN_ROOT / ".claude-plugin" / "plugin.json")
    problems += errs
    marketplace, errs = _read_json(
        MARKETPLACE_ROOT / ".claude-plugin" / "marketplace.json")
    problems += errs

    name = plugin.get("name")
    if not problems:
        problems += check_manifest_agreement(plugin, marketplace)
        # Only this plugin's own entry. The marketplace carries others, and
        # whether they agree with their manifests is their business, not a
        # reason to fail this plugin's lint.
        ours = [e for e in (marketplace.get("plugins") or [])
                if (e or {}).get("name") == name]
        problems += check_entry_sources(ours)

    skills, commands, errs = _collect_plugin(PLUGIN_ROOT)
    problems += errs
    problems += check_skill_frontmatter(skills)
    problems += check_command_frontmatter(commands)

    # Every other JSON file under this plugin only has to parse. Fixtures
    # included: a truncated fixture fails the suite that reads it with a
    # confusing error.
    for path in sorted(PLUGIN_ROOT.glob("**/*.json")):
        if ".claude-plugin" in path.parts or "__pycache__" in path.parts:
            continue
        problems += _read_json(path)[1]

    problems += check_executable_bits([
        (_rel(PLUGIN_ROOT / rel), os.access(PLUGIN_ROOT / rel, os.X_OK))
        for rel in EXECUTABLES
        if (PLUGIN_ROOT / rel).exists()
    ])

    if problems:
        print(f"{len(problems)} problem(s) in the plugin metadata:\n")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"Plugin metadata OK — {name} v{plugin.get('version')}, "
          f"{len(skills)} skill(s), {len(commands)} command(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
