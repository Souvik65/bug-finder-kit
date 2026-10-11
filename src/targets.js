import path from "node:path";
import os from "node:os";

const home = os.homedir();

// Verify each path in the editor's docs before adding more.
export const TARGETS = {
  agents: {
    label: "Google Antigravity / Gemini (.agents)",
    project: ".agents/skills",
    global: path.join(home, ".gemini", "config", "skills"),
  },
  agent: {
    label: "Legacy Agent (.agent)",
    project: ".agent/skills",
    global: path.join(home, ".gemini", "antigravity", "skills"),
  },
  claude: {
    label: "Claude Code (.claude)",
    project: ".claude/skills",
    global: path.join(home, ".claude", "skills"),
  },
  cursor: {
    label: "Cursor IDE (.cursor)",
    project: ".cursor/skills",
    global: path.join(home, ".cursor", "skills"),
  },
  windsurf: {
    label: "Windsurf IDE (.windsurf)",
    project: ".windsurf/skills",
    global: path.join(home, ".windsurf", "skills"),
  },
  cline: {
    label: "Cline / Roo Code (.cline)",
    project: ".cline/skills",
    global: path.join(home, ".cline", "skills"),
  },
  vscode: {
    label: "VS Code / GitHub Copilot (.github)",
    project: ".github/skills",
    global: path.join(home, ".copilot", "skills"),
  },
};

export function resolveDir(key, scope, customDir) {
  if (customDir) {
    return path.isAbsolute(customDir) ? customDir : path.join(process.cwd(), customDir);
  }
  const t = TARGETS[key];
  if (!t) return path.join(process.cwd(), ".skills");
  return scope === "global" ? t.global : path.join(process.cwd(), t.project);
}