import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const SKILLS_ROOT = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
  "skills"
);

const NAME_RE = /^[a-z0-9][a-z0-9-]*$/;

export function listSkills() {
  return fs
    .readdirSync(SKILLS_ROOT, { withFileTypes: true })
    .filter((d) => d.isDirectory() && fs.existsSync(path.join(SKILLS_ROOT, d.name, "SKILL.md")))
    .map((d) => {
      const text = fs.readFileSync(path.join(SKILLS_ROOT, d.name, "SKILL.md"), "utf8");
      const m = text.match(/^description:\s*(.+)$/m);
      return { name: d.name, description: m ? m[1].trim() : "" };
    });
}

export const isValidName = (n) => NAME_RE.test(n);