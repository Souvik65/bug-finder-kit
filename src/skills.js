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
      let desc = "";
      const mMulti = text.match(/^description:\s*[>|]?\r?\n\s+([^\r\n]+)/m);
      const mSingle = text.match(/^description:\s*([^\r\n>|]+)$/m);
      if (mMulti && mMulti[1]) {
        desc = mMulti[1].trim();
      } else if (mSingle && mSingle[1]) {
        desc = mSingle[1].trim();
      }
      return { name: d.name, description: desc };
    });
}

export const isValidName = (n) => NAME_RE.test(n);