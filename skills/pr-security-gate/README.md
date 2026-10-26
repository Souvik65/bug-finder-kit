# pr-security-gate

> Automated pull request security review and approval gate skill for the **bug-finder-kit**.
> Enforces pre-merge security checklists, diff classification, risk-scoring heuristics,
> and automated CI/CD gating before code merges into protected branches.

---

## What This Skill Covers

| Audit Area | Review Focus |
|---|---|
| **Diff Risk Classification** | Tier 1 (Critical) to Tier 4 (Low) risk weighting for pull requests |
| **Automatic Merge Blockers** | Hardcoded secrets, disabled TLS/cert checks, raw SQL injection, auth bypasses |
| **New API Routes** | Authentication gates, schema validation, rate limiting, IDOR/BOLA tenancy checks |
| **Auth & Session Changes** | Session fixation defense, JWT lifecycle, fail-closed authorization logic |
| **Cryptographic Updates** | Cipher strength, secure password hashing (Argon2/bcrypt), timing-safe comparisons |
| **Sensitive Data & Logging** | PII leak prevention, database migration safety, export bounds |
| **Dependency Changes** | Lockfile synchronization, unpinned version checks, automated CVE audits |
| **CI/CD Integration** | GitHub Actions and GitLab CI automated diff-scanning scripts |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `code-review-security` | General code review guidelines and secure coding standards |
| `security-audit` | Broad whole-codebase repository penetration testing and posture review |
| **`pr-security-gate`** | Focused git diff analysis, pre-merge gate criteria, pass/fail gating, and PR comment sign-off workflows |

---

## Trigger Phrases

Activate this skill by asking:
- `"PR security review"`, `"pull request security checklist"`
- `"PR security gate"`, `"pre-merge security check"`
- `"diff security scan"`, `"audit PR for security"`
- `"endpoint change review"`, `"auth change review"`
- `"code review security checklist"`, `"merge approval checklist"`

---

## Directory Structure

```
skills/pr-security-gate/
├── SKILL.md              — Core audit guide (Phases 1–8, risk matrix, blocker rules, diff scanner)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — GitHub Actions workflow integration, automated diff parsing,
                            branch protection rules, and sign-off policies
```
