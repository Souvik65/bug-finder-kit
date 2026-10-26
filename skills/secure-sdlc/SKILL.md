---
name: secure-sdlc
description: Build the security process layer of a software development lifecycle - risk-tiered security gates, lightweight threat modeling, security/abuse user stories, security acceptance criteria, and PR security checklists. Use whenever the user wants to shift security left, add security to sprint planning, grooming, design review, or code review, write a threat model for a feature, turn a feature ticket into security stories, create a PR template or security review checklist, define "security definition of done", set up a security champions or AppSec intake process, or asks "what security work should this feature need?" - even if they never say "SDLC". Also use when reviewing a user story, design doc, or PR for missing security requirements.
---

# Secure SDLC

Most teams already have scanners (SAST, SCA, secrets detection). What they lack is the **process layer**: deciding *which* changes deserve security attention, *when* in the lifecycle it happens, *who* signs off, and *what artifact* proves it. This skill produces those artifacts and keeps the effort proportional to risk, because a process that taxes every ticket equally gets bypassed within a quarter.

## Core idea: risk-tier first, then pick gates

Never hand the user a one-size-fits-all checklist. Classify the change, then apply only the gates that tier requires.

| Tier | Typical change | Security effort |
|------|----------------|-----------------|
| **T0 - Routine** | Copy edits, internal refactor, UI styling, no new data/inputs/trust boundary | Default PR checklist only (3 questions) |
| **T1 - Standard** | New endpoint/feature on an existing pattern, new form field, new dependency | Security acceptance criteria + full PR checklist |
| **T2 - Elevated** | New auth/authz logic, handling PII/payment/secrets, file upload, new external integration, multi-tenant boundary, LLM/agent feature | Security stories + lightweight threat model + champion review |
| **T3 - Critical** | New trust boundary or architecture, crypto, identity/session changes, admin/privileged paths, cross-tenant data access, anything internet-exposed that is new | Full threat model gate + AppSec sign-off + pre-release verification |

**Escalation triggers** (bump up one tier if any apply): handles regulated data, previously caused an incident, touches code with no tests, ships to many customers at once, or the author is unsure. Explain the tier you chose in one sentence so the user can overrule it.

If the user gives an ambiguous change, make a best-guess tier and state the assumption rather than interrogating them.

## Workflow

1. **Triage** - Determine the tier from the user's description (use the table + triggers). Output: tier and a one-line rationale.
2. **Locate the lifecycle phase** - Where is the user? Idea/grooming, design, implementation, PR/review, pre-release, or post-release. Produce the artifact for *that* phase first, then note what the earlier/later phases would add.
3. **Generate the artifact(s)** using the matching reference:
   - Threat model gate -> `references/threat-modeling.md`
   - Security / abuse stories -> `references/security-stories.md`
   - Security acceptance criteria -> `references/acceptance-criteria.md`
   - PR checklist / template / CODEOWNERS routing -> `references/pr-checklist.md`
   - Gate definitions, exit criteria, risk-acceptance and exceptions -> `references/gates-and-exceptions.md`
4. **Tailor, don't paste** - Fill templates with the user's actual feature, components, and data. Generic output ("validate input") is the failure mode. Name the specific asset, actor, and control.
5. **Close with the gate verdict** - State what must be true before the work may advance (exit criteria) and who owns each item.

## Output principles

- **Testable over aspirational.** Every requirement should be verifiable by a test, a review step, or a tool result. "Be secure" is not a requirement; "Requests for another tenant's resource ID return 404 and are covered by an automated test" is.
- **Attach to the workflow they already use.** Jira/Linear tickets, GitHub/GitLab PR templates, Confluence/Notion design docs. Ask which only if it changes the output; otherwise default to Markdown that pastes anywhere.
- **Name an owner and a phase for every control.** Unowned controls don't happen.
- **Prefer secure defaults and paved roads** (shared auth middleware, vetted libraries) over per-feature custom controls. Flag when a paved road is missing - that is a platform backlog item, not a feature task.
- **Show the cost.** Estimate security work in the same units the team uses (points/hours) so it can be planned instead of surfacing as a release-week surprise.
- Do not invent compliance claims. Map to frameworks (OWASP ASVS, SAMM, NIST SSDF, ISO 27001, SOC 2) only when asked or clearly relevant, and say it is a mapping, not certification.

## Quick modes

- **"Review this story/design/PR for security gaps"** -> triage, then list missing items grouped as *Blocker / Should-fix / Nice-to-have*, each with the exact text to add.
- **"Set up secure SDLC for our team"** -> deliver a rollout plan: start with the PR template and T2/T3 triage (week 1), add stories and acceptance criteria to grooming (weeks 2-3), introduce the threat model gate and champions (month 2), then measure (see metrics in `references/gates-and-exceptions.md`).
- **"Threat model X"** -> use the lightweight format; cap at ~10 prioritized threats so it actually gets read.

## Handling pushback and reality

Teams will say it slows them down. Respond by showing the T0/T1 fast path, not by arguing. When a gate must be skipped, do not refuse - produce a time-boxed **risk acceptance record** (template in `references/gates-and-exceptions.md`) so the decision is visible and owned.
