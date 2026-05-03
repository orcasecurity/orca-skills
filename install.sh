#!/usr/bin/env bash
#
# Orca Skills Installer
# Installs Orca Security skills for Claude Code, Claude Desktop, Cursor, and Codex
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  Orca Security Skills Installer${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo

# Check if skills directory exists
if [ ! -d "$SCRIPT_DIR/skills" ]; then
    echo -e "${RED}✗ Error: skills/ directory not found in $SCRIPT_DIR${NC}"
    echo "  Please run this script from the orca-skills directory"
    exit 1
fi

# Count available skills
SKILL_COUNT=$(find "$SCRIPT_DIR/skills" -name "SKILL.md" | wc -l | tr -d ' ')
echo -e "${GREEN}Found $SKILL_COUNT skill(s) to install${NC}"
echo

# Install for Claude Code (Plugin Method)
echo -e "${BLUE}[1/5] Claude Code (Plugin)${NC}"
CLAUDE_PLUGIN_DIR="$HOME/.claude/plugins/marketplaces/orca-security/plugins/orca-skills"
mkdir -p "$CLAUDE_PLUGIN_DIR"
if cp -rf "$SCRIPT_DIR/.claude-plugin" "$CLAUDE_PLUGIN_DIR/" 2>/dev/null && \
   cp -rf "$SCRIPT_DIR/skills" "$CLAUDE_PLUGIN_DIR/" 2>/dev/null && \
   cp -f "$SCRIPT_DIR/package.json" "$CLAUDE_PLUGIN_DIR/" 2>/dev/null; then
    echo -e "${GREEN}✓ Installed Claude Code plugin to: $CLAUDE_PLUGIN_DIR${NC}"
    echo "      Skills available:"
    find "$SCRIPT_DIR/skills" -name "SKILL.md" -exec dirname {} \; | xargs -I {} basename {} | sed 's/^/        - /'
else
    echo -e "${RED}✗ Failed to install Claude Code plugin${NC}"
fi

# Create marketplace.json
MARKETPLACE_DIR="$HOME/.claude/plugins/marketplaces/orca-security"
if [ ! -f "$MARKETPLACE_DIR/marketplace.json" ]; then
    cat > "$MARKETPLACE_DIR/marketplace.json" << 'EOF'
{
  "name": "orca-security",
  "description": "Orca Security plugins for Claude Code",
  "owner": {
    "name": "Orca Security",
    "email": "support@orca.security"
  }
}
EOF
    echo -e "${GREEN}✓ Created marketplace metadata${NC}"
fi

# Install for Claude Code/Desktop (Skills Directory)
echo
echo -e "${BLUE}[2/5] Claude Code/Desktop (Skills Directory)${NC}"
for skill_dir in "$SCRIPT_DIR/skills"/*; do
    if [ -d "$skill_dir" ] && [ -f "$skill_dir/SKILL.md" ]; then
        skill_name=$(basename "$skill_dir")
        mkdir -p "$HOME/.claude/skills/$skill_name"
        if cp -f "$skill_dir/SKILL.md" "$HOME/.claude/skills/$skill_name/" 2>/dev/null; then
            echo -e "${GREEN}✓ Installed: $skill_name${NC}"
        fi
    fi
done

# Install for Cursor
echo
echo -e "${BLUE}[3/5] Cursor${NC}"
if [ -d "$HOME/.cursor" ]; then
    mkdir -p "$HOME/.cursor/plugins/orca-skills/skills"
    if cp -rf "$SCRIPT_DIR/.cursor-plugin" "$HOME/.cursor/plugins/orca-skills/" 2>/dev/null && \
       cp -rf "$SCRIPT_DIR/skills" "$HOME/.cursor/plugins/orca-skills/" 2>/dev/null && \
       cp -f "$SCRIPT_DIR/package.json" "$HOME/.cursor/plugins/orca-skills/" 2>/dev/null; then
        echo -e "${GREEN}✓ Installed to: $HOME/.cursor/plugins/orca-skills${NC}"
        echo -e "${YELLOW}      Note: Restart Cursor to activate${NC}"
    else
        echo -e "${YELLOW}⚠ Cursor directory found but installation failed${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Cursor not detected (skip)${NC}"
fi

# Install for Codex
echo
echo -e "${BLUE}[4/5] Codex / OpenCode${NC}"
if [ -d "$HOME/.codex" ] || [ -d "$HOME/.opencode" ]; then
    CODEX_DIR="${HOME}/.codex"
    [ -d "$HOME/.opencode" ] && CODEX_DIR="${HOME}/.opencode"

    mkdir -p "$CODEX_DIR/plugins/orca-skills/skills"
    if cp -rf "$SCRIPT_DIR/.codex" "$CODEX_DIR/plugins/orca-skills/" 2>/dev/null && \
       cp -rf "$SCRIPT_DIR/skills" "$CODEX_DIR/plugins/orca-skills/" 2>/dev/null && \
       cp -f "$SCRIPT_DIR/package.json" "$CODEX_DIR/plugins/orca-skills/" 2>/dev/null; then
        echo -e "${GREEN}✓ Installed to: $CODEX_DIR/plugins/orca-skills${NC}"
        echo -e "${YELLOW}      Note: Restart Codex to activate${NC}"
    else
        echo -e "${YELLOW}⚠ Codex directory found but installation failed${NC}"
    fi
else
    echo -e "${YELLOW}⚠ Codex not detected (skip)${NC}"
fi

# MCP Configuration Check
echo
echo -e "${BLUE}[5/5] MCP Configuration${NC}"
if [ -f ".mcp.json" ]; then
    if grep -q "orca-security" ".mcp.json"; then
        echo -e "${GREEN}✓ Orca Security MCP server configured in .mcp.json${NC}"
    else
        echo -e "${YELLOW}⚠ .mcp.json found but orca-security not configured${NC}"
    fi
else
    echo -e "${YELLOW}⚠ .mcp.json not found in current directory${NC}"
    echo "  Create .mcp.json with Orca Security MCP configuration"
fi

# Summary
echo
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Installation complete!${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo
echo "Next steps:"
echo "  1. Configure Orca Security MCP server (if not done):"
echo "     Create .mcp.json with your Orca API token"
echo
echo "  2. Test the skills:"
echo "     claude code"
echo "     /orca-triage orca-3636513"
echo
echo "  3. Available commands:"
for skill_dir in "$SCRIPT_DIR/skills"/*; do
    if [ -d "$skill_dir" ] && [ -f "$skill_dir/SKILL.md" ]; then
        skill_name=$(basename "$skill_dir")
        echo "     /orca-$skill_name"
    fi
done
echo
echo "For detailed documentation, see: $SCRIPT_DIR/README.md"
echo

# Verify Claude Code installation
if command -v claude &> /dev/null; then
    echo -e "${GREEN}✓ Claude Code CLI detected${NC}"
else
    echo -e "${YELLOW}⚠ Claude Code CLI not found${NC}"
    echo "  Install: https://claude.ai/download"
fi

if [ -d "$HOME/.claude/plugins/marketplaces/orca-security" ]; then
    echo -e "${GREEN}✓ Claude Code Marketplace Plugin installed${NC}"
fi

echo
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
