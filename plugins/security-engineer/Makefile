VERSION     := $(shell python3 -c "import json; print(json.load(open('.claude-plugin/plugin.json'))['version'])")
MARKETPLACE := orcasecurity
PLUGIN      := security-engineer@$(MARKETPLACE)
ORIGIN      := orcasecurity/orca-skills
# The marketplace root is the repository root — the directory holding
# .claude-plugin/marketplace.json — not this plugin directory.
MARKET_ROOT := $(abspath $(CURDIR)/../..)
PLUGIN_CACHE := $(HOME)/.claude/plugins/cache/$(MARKETPLACE)/security-engineer/$(VERSION)

.PHONY: test lint e2e all install uninstall validate

# Unit tests — no API token needed, no network, pure Python
test:
	python3 skills/run/tests/test_orchestrator.py
	python3 skills/run/tests/test_version_data.py
	python3 skills/run/tests/test_package_identity.py
	python3 skills/run/tests/test_pipelines.py
	python3 tools/tests/test_check_manifests.py

# Static checks. CI (.github/workflows/ci.yml at the repository root) runs this
# exact target, so a green PR is predictable from here rather than discovered on
# the pull request.
#
# Needs the two linters on PATH; CI pins the same versions:
#   pip install ruff==0.16.1 shellcheck-py==0.11.0.1
lint:
	ruff check .
	shellcheck bin/security-engineer
	python3 tools/check_manifests.py

# Integration tests — requires ORCA_API_TOKEN
e2e:
	python3 skills/run/tests/test_e2e_orca.py

# Run both
all: test e2e

# Install this working tree as the plugin, so /security-engineer:run executes
# the code you are editing.
#
# Without this the two diverge: the skill runs the copy Claude Code made when
# the plugin was installed, and nothing refreshes that copy on its own.
# `claude plugin update` short-circuits while plugin.json's version is
# unchanged, and installing over an existing install is a no-op. So the skill
# keeps running the commit it was installed at until you say otherwise — run
# this after every edit you want the skill to see.
#
# Three steps, none of them optional:
#   marketplace add  points the orcasecurity marketplace at THIS repository
#                    instead of GitHub, so "install" means "install what I have
#                    here" rather than "download origin/main"
#   uninstall        the no-op-on-reinstall rule means the old copy has to go
#                    first, or nothing is refreshed. Ignored if not installed.
#   install          copies the plugin directory into the plugin cache
#
# `make uninstall` puts the marketplace back on GitHub.
install:
	@claude plugin marketplace add "$(MARKET_ROOT)" --scope user >/dev/null
	@claude plugin uninstall $(PLUGIN) --scope user >/dev/null 2>&1 || true
	@claude plugin install $(PLUGIN) --scope user
	@echo "Installed v$(VERSION) from $(CURDIR)."
	@echo "SKILL.md or frontmatter changes need a Claude Code restart to re-register."

# Remove the plugin and put the marketplace back on GitHub.
#
# Uninstall also leaves the copied files behind, hence the rm.
#
# Only user scope is touched. A project-scoped entry is visible to `claude
# plugin uninstall` only when the command runs from the directory it was
# installed from; if you installed this plugin into a project scope, uninstall
# it from there before running this, or the registry keeps an entry pointing at
# the cache directory this target deletes.
uninstall:
	-@claude plugin uninstall $(PLUGIN) --scope user
	@rm -rf "$(HOME)/.claude/plugins/cache/$(MARKETPLACE)/security-engineer"
	-@claude plugin marketplace add $(ORIGIN) --scope user >/dev/null
	@echo "Removed $(PLUGIN); marketplace restored to $(ORIGIN)."
	@echo "Reinstall the published version from the marketplace, or this tree with 'make install'."

# Verify cached plugin is valid
validate:
	claude plugin validate "$(PLUGIN_CACHE)"
