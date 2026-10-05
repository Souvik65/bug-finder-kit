#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SKILLS_DIR = path.join(__dirname, "..", "skills");
const home = os.homedir();
const cwd = process.cwd();

// Install targets. Verify each path in the editor's docs before adding more.
const TARGETS = {
  // default: workspace .agents/skills (Antigravity default)
  agents: {
    project: path.join(cwd, ".agents", "skills"),
    global: path.join(home, ".gemini", "antigravity", "skills"),
  },
  // older Antigravity workspace path
  agent: {
    project: path.join(cwd, ".agent", "skills"),
    global: path.join(home, ".gemini", "antigravity", "skills"),
  },
  claude: {
    project: path.join(cwd, ".claude", "skills"),
    global: path.join(home, ".claude", "skills"),
  },
};

const args = process.argv.slice(2);
const cmd = args[0];
const has = (...f) => f.some((x) => args.includes(x));
const valueOf = (flag) => {
  const i = args.indexOf(flag);
  return i > -1 ? args[i + 1] : undefined;
};

const isGlobal = has("-g", "--global");
const force = has("-f", "--force");
const targetName = valueOf("--target") || "agents";
const customDir = valueOf("--dir");

function allSkills() {
  return fs
    .readdirSync(SKILLS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(SKILLS_DIR, d.name, "SKILL.md")))
    .map((d) => d.name);
}

function destination() {
  if (customDir) return path.resolve(customDir);
  const t = TARGETS[targetName];
  if (!t) {
    console.error(`Unknown target "${targetName}". Available: ${Object.keys(TARGETS).join(", ")} (or use --dir)`);
    process.exit(1);
  }
  return isGlobal ? t.global : t.project;
}

function init() {
  const dest = destination();
  fs.mkdirSync(dest, { recursive: true });
  for (const name of allSkills()) {
    const out = path.join(dest, name);
    if (fs.existsSync(out) && !force) {
      console.log(`• ${name} already installed at ${out} (use --force to overwrite)`);
      continue;
    }
    fs.cpSync(path.join(SKILLS_DIR, name), out, { recursive: true });
    console.log(`✓ Installed ${name} → ${out}`);
  }
  console.log("\nDone. Restart your editor's agent session so it detects the skill.");
}

function help() {
  console.log(`bug-finder-kit

Usage:
  bug-finder init [options]
  bug-finder list

Options:
  -g, --global        install for all projects instead of the current one
  --target <name>     agents (default) | agent | claude
  --dir <path>        install to any custom skills folder
  -f, --force         overwrite an existing install

Examples:
  bug-finder init                       -> ./.agents/skills/bug-finder
  bug-finder init --target claude       -> ./.claude/skills/bug-finder
  bug-finder init -g                    -> ~/.gemini/antigravity/skills/bug-finder`);
}

if (cmd === "init") init();
else if (cmd === "list") allSkills().forEach((s) => console.log(s));
else help();