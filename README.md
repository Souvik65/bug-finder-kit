## Install

npx @souvik/bug-finder-kit init

Or globally:

npm install -g @souvik/bug-finder-kit
bug-finder init

Installs to `.agents/skills/bug-finder` in your current project.

### Options
| Flag | Meaning |
|---|---|
| `-g` | Install for all projects |
| `--target claude` | Install to `.claude/skills/` |
| `--target agent` | Install to the older `.agent/skills/` |
| `--dir <path>` | Install to any folder |
| `-f` | Overwrite existing |