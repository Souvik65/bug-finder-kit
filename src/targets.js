import path from "node:path";
import os from "node:os";

const home = os.homedir();

// Verify each path in the editor's docs before adding more.
export const TARGETS = {
  agents: {
    label: "Antigravity / .agents",
    project: ".agents/skills",
    global: path.join(home, ".gemini", "antigravity", "skills"),
  },
  agent: {
    label: "Legacy .agent",
    project: ".agent/skills",
    global: path.join(home, ".gemini", "antigravity", "skills"),
  },
  claude: {
    label: "Claude Code",
    project: ".claude/skills",
    global: path.join(home, ".claude", "skills"),
  },
};

export function resolveDir(key, scope) {
  const t = TARGETS[key];
  return scope === "global" ? t.global : path.join(process.cwd(), t.project);
}