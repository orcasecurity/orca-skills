import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const errors = [];

function fail(message) {
  errors.push(message);
}

function expect(condition, message) {
  if (!condition) fail(message);
}

function readJson(relativePath) {
  const absolutePath = path.join(root, relativePath);
  try {
    return JSON.parse(fs.readFileSync(absolutePath, "utf8"));
  } catch (error) {
    fail(`${relativePath} must be valid JSON: ${error.message}`);
    return {};
  }
}

function expectPackageManifest(relativePath) {
  const manifest = readJson(relativePath);
  expect(manifest.name === "orca-skills", `${relativePath} must use name "orca-skills"`);
  expect(manifest.version === "2.0.0", `${relativePath} must use version "2.0.0"`);
  expect(
    manifest.repository === "https://github.com/orcasecurity/orca-skills" ||
      manifest.repository?.url === "https://github.com/orcasecurity/orca-skills.git",
    `${relativePath} must point at the orcasecurity/orca-skills repository`,
  );
  expect(manifest.skills === "./skills/", `${relativePath} must expose ./skills/`);
  return manifest;
}

function validateSkillFolders() {
  const skillsRoot = path.join(root, "skills");
  const skillNames = fs
    .readdirSync(skillsRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  expect(skillNames.length === 12, `expected 12 skill folders, found ${skillNames.length}`);

  for (const skillName of skillNames) {
    const skillPath = path.join(skillsRoot, skillName, "SKILL.md");
    expect(fs.existsSync(skillPath), `${skillName} must include SKILL.md`);
  }

  const codexSkillsRoot = path.join(root, "plugins", "orca-skills", "skills");
  expect(fs.existsSync(codexSkillsRoot), "Codex plugin must include plugins/orca-skills/skills");

  for (const skillName of skillNames) {
    const sourcePath = path.join(skillsRoot, skillName, "SKILL.md");
    const codexPath = path.join(codexSkillsRoot, skillName, "SKILL.md");
    expect(fs.existsSync(codexPath), `Codex plugin copy must include ${skillName}/SKILL.md`);
    if (fs.existsSync(codexPath)) {
      expect(
        fs.readFileSync(codexPath, "utf8") === fs.readFileSync(sourcePath, "utf8"),
        `Codex plugin copy of ${skillName}/SKILL.md must match root skills/${skillName}/SKILL.md`,
      );
    }
  }
}

function validateCodexPluginManifest(relativePath) {
  const manifest = expectPackageManifest(relativePath);
  expect(typeof manifest.author?.name === "string", `${relativePath} must include author.name`);
  expect(manifest.interface?.displayName === "Orca Security Skills", `${relativePath} must include Codex interface metadata`);
  expect(
    Array.isArray(manifest.interface?.defaultPrompt) && manifest.interface.defaultPrompt.length > 0,
    `${relativePath} must include at least one defaultPrompt`,
  );
  expect(!("mcpServers" in manifest), `${relativePath} should not reference .mcp.json unless the file is committed`);
}

function validateCodexPluginCopy() {
  const rootManifestPath = path.join(root, ".codex-plugin", "plugin.json");
  const packagedManifestPath = path.join(root, "plugins", "orca-skills", ".codex-plugin", "plugin.json");

  if (!fs.existsSync(rootManifestPath) || !fs.existsSync(packagedManifestPath)) return;

  expect(
    fs.readFileSync(rootManifestPath, "utf8") === fs.readFileSync(packagedManifestPath, "utf8"),
    "plugins/orca-skills/.codex-plugin/plugin.json must match .codex-plugin/plugin.json",
  );
}

function validateCodexMarketplace() {
  const marketplace = readJson(".agents/plugins/marketplace.json");
  const plugin = marketplace.plugins?.find((entry) => entry.name === "orca-skills");

  expect(marketplace.name === "orcasecurity", ".agents/plugins/marketplace.json must be named orcasecurity");
  expect(marketplace.interface?.displayName === "Orca Security", ".agents/plugins/marketplace.json must include displayName");
  expect(plugin, ".agents/plugins/marketplace.json must include an orca-skills plugin entry");

  if (!plugin) return;

  expect(plugin.source?.source === "local", "Codex marketplace entry must use local source");
  expect(plugin.source?.path === "./plugins/orca-skills", "Codex marketplace entry must point to the Codex plugin folder");
  expect(plugin.policy?.installation === "AVAILABLE", "Codex marketplace installation policy must be AVAILABLE");
  expect(plugin.policy?.authentication === "ON_INSTALL", "Codex marketplace authentication policy must be ON_INSTALL");
  expect(plugin.category === "Security", "Codex marketplace category must be Security");
}

function validateReadme() {
  const readme = fs.readFileSync(path.join(root, "README.md"), "utf8");
  expect(readme.includes("### Claude Code CLI"), "README must document Claude Code installation");
  expect(readme.includes("### Codex CLI"), "README must document Codex CLI installation");
  expect(readme.includes("codex mcp add orca-security"), "README must document Codex MCP setup");
  expect(readme.includes("Claude examples use slash commands"), "README must explain Claude slash commands vs Codex natural language");
}

function validateContributorDocs() {
  const contributing = fs.readFileSync(path.join(root, "CONTRIBUTING.md"), "utf8");
  expect(contributing.includes("npm test"), "CONTRIBUTING must document the repository validation command");
  for (const staleReference of ["EVALS.md", "promptfoo", "promptfooconfig.yaml", "test-data/"]) {
    expect(!contributing.includes(staleReference), `CONTRIBUTING must not reference missing ${staleReference}`);
  }
}

validateSkillFolders();
expectPackageManifest(".claude-plugin/plugin.json");
expectPackageManifest(".cursor-plugin/plugin.json");
expectPackageManifest(".codex/plugin.json");
validateCodexPluginManifest(".codex-plugin/plugin.json");
validateCodexPluginManifest("plugins/orca-skills/.codex-plugin/plugin.json");
validateCodexPluginCopy();
validateCodexMarketplace();
validateReadme();
validateContributorDocs();

if (errors.length > 0) {
  console.error("Packaging validation failed:");
  for (const error of errors) {
    console.error(`- ${error}`);
  }
  process.exit(1);
}

console.log("Packaging validation passed.");
