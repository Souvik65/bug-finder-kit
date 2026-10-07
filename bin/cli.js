#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import * as p from "@clack/prompts";
import { TARGETS, resolveDir } from "../src/targets.js";
import { listSkills, isValidName, SKILLS_ROOT } from "../src/skills.js";

const pkg = JSON.parse(
  fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "package.json"), "utf8")
);

const { values: f, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    global: { type: "boolean", short: "g" },
    target: { type: "string", short: "t", multiple: true },
    skill: { type: "string", short: "s", multiple: true },
    yes: { type: "boolean", short: "y" },
    force: { type: "boolean", short: "f" },
    help: { type: "boolean", short: "h" },
    version: { type: "boolean", short: "v" },
  },
});

const [cmd, ...rest] = positionals;
const available = listSkills();
const interactive = !f.yes && process.stdin.isTTY && process.stdout.isTTY;

const bail = (v) => {
  if (p.isCancel(v)) {
    p.cancel("Cancelled.");
    process.exit(0);
  }
  return v;
};

function help() {
  console.log(`${pkg.name} v${pkg.version}

Usage:
  bug-finder init                 interactive install
  bug-finder add <skill...>       install specific skills
  bug-finder remove <skill...>    uninstall skills
  bug-finder list                 show available skills

Options:
  -s, --skill <name>   skill to install (repeatable)
  -t, --target <name>  ${Object.keys(TARGETS).join(" | ")} (repeatable, default: agents)
  -g, --global         install for all projects
  -y, --yes            no prompts, use defaults
  -f, --force          overwrite existing
  -h, --help   -v, --version`);
}

function validate(names) {
  for (const n of names) {
    if (!isValidName(n) || !available.some((s) => s.name === n)) {
      p.log.error(`Unknown skill: ${n}. Run "list" to see options.`);
      process.exit(1);
    }
  }
  for (const t of f.target || []) {
    if (!TARGETS[t]) {
      p.log.error(`Unknown target: ${t}. Options: ${Object.keys(TARGETS).join(", ")}`);
      process.exit(1);
    }
  }
}

async function choose(initialSkills) {
  let skills = initialSkills.length ? initialSkills : f.skill || [];
  let targets = f.target || [];
  let scope = f.global ? "global" : "project";

  if (interactive) {
    if (!skills.length) {
      skills =
        available.length === 1
          ? [available[0].name]
          : bail(
              await p.multiselect({
                message: "Which skills do you want to install?",
                options: available.map((s) => ({ value: s.name, label: s.name, hint: s.description.slice(0, 60) })),
                required: true,
              })
            );
    }
    if (!targets.length) {
      targets = bail(
        await p.multiselect({
          message: "Which editors/agents?",
          options: Object.entries(TARGETS).map(([k, t]) => ({ value: k, label: t.label, hint: t.project })),
          initialValues: ["agents"],
          required: true,
        })
      );
    }
    if (!f.global) {
      scope = bail(
        await p.select({
          message: "Install where?",
          options: [
            { value: "project", label: "This project" },
            { value: "global", label: "Globally (all projects)" },
          ],
        })
      );
    }
  } else {
    if (!skills.length) skills = available.map((s) => s.name);
    if (!targets.length) targets = ["agents"];
  }
  return { skills, targets, scope };
}

function install({ skills, targets, scope }) {
  for (const t of targets) {
    const dest = resolveDir(t, scope);
    fs.mkdirSync(dest, { recursive: true });
    for (const name of skills) {
      const out = path.join(dest, name);
      if (fs.existsSync(out) && !f.force) {
        p.log.warn(`${name} already exists in ${out} (use --force)`);
        continue;
      }
      fs.rmSync(out, { recursive: true, force: true });
      fs.cpSync(path.join(SKILLS_ROOT, name), out, { recursive: true });
      p.log.success(`${name} → ${out}`);
    }
  }
}

async function main() {
  if (f.version) return console.log(pkg.version);
  if (f.help || !cmd) return help();

  if (cmd === "list") {
    for (const s of available) console.log(`${s.name}\n  ${s.description}\n`);
    return;
  }

  if (cmd === "init" || cmd === "add") {
    p.intro(`${pkg.name}`);
    validate(rest.concat(f.skill || []));
    install(await choose(rest));
    p.outro("Done. Restart your editor's agent session so it picks up the skills.");
    return;
  }

  if (cmd === "remove") {
    if (!rest.length) return p.log.error("Specify skills to remove.");
    validate(rest);
    const targets = f.target?.length ? f.target : ["agents"];
    for (const t of targets) {
      for (const name of rest) {
        const out = path.join(resolveDir(t, f.global ? "global" : "project"), name);
        if (fs.existsSync(out)) {
          fs.rmSync(out, { recursive: true, force: true });
          p.log.success(`Removed ${out}`);
        } else p.log.warn(`Not installed: ${out}`);
      }
    }
    return;
  }

  help();
  process.exit(1);
}

main();