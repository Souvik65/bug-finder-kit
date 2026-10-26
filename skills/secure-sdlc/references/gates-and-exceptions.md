# Gates, exit criteria, exceptions, and metrics

## Gate map across the lifecycle

| Phase | Gate | Applies | Exit criteria | Owner |
|-------|------|---------|---------------|-------|
| Idea / grooming | Triage | All | Tier assigned; data class and trust-boundary impact noted | PM + author |
| Refinement | Story readiness | T1+ | Security stories/acceptance criteria attached and estimated | Author + champion |
| Design | Threat model | T2/T3 | High threats mitigated or accepted; verification plan exists | Author + AppSec/champion |
| Implementation | Automated checks | All | SAST, SCA, secrets scan pass or findings triaged | CI (platform) |
| PR | Security checklist + review | All (depth by tier) | Checklist complete; code-owner approval for sensitive paths | Reviewer |
| Pre-release | Verification | T3 (T2 on request) | Targeted security test/pen test, no open High; rollback plan | AppSec |
| Post-release | Monitor & learn | T2/T3 | Alerts live; findings fed back to stories/library | Service owner |

Principle: gates should **block rarely but predictably**. A gate that fails randomly trains people to route around it.

## Severity and SLAs for findings (adapt to team)
| Severity | Release impact | Fix target |
|----------|----------------|------------|
| Critical | Blocks release | Immediately / before ship |
| High | Blocks release unless accepted | <= 14 days |
| Medium | Does not block | <= 60 days |
| Low | Backlog | Opportunistic |

## Risk acceptance record (when a gate or fix is skipped)
```
Risk acceptance: <title>
Requested by: <name>   Date: <date>   Expires: <date, max 90 days>
Gate/control skipped: <what>
Reason: <deadline / dependency / cost>
Risk description: <threat, asset, likelihood, impact>
Compensating controls: <monitoring, feature flag, limited rollout>
Approver: <business owner with authority over the risk>  AppSec consulted: <name>
Remediation plan: <ticket link + due date>
```
Rules: the approver must be someone who owns the risk (not the author); acceptances expire and must be renewed explicitly; keep a register and review it monthly.

## Security champions model (lightweight)
- One champion per team (~10-20% time), self-nominated, trained on the checklist and threat modeling.
- Champions triage tiers, run the T2 threat model, and escalate T3 to AppSec.
- AppSec's job shifts from reviewing everything to owning paved roads, T3 reviews, and tooling.

## Metrics (pick 4-5; avoid vanity counts)
- % of T2/T3 changes with a threat model before implementation began (leading)
- Median time from finding to fix by severity (lagging)
- % of PRs touching sensitive paths that got a code-owner review
- Defects found in design vs. pre-release vs. production (the shift-left curve)
- Number and age of open risk acceptances
- Gate friction: median added review time for T0/T1 (should be near zero)

## Rollout sequence
1. Week 1: adopt PR template + CODEOWNERS for 3-5 sensitive paths.
2. Weeks 2-3: tiering in grooming; security acceptance criteria on T1+ stories.
3. Month 2: threat model gate for T2/T3 and champion program.
4. Month 3: risk acceptance register, metrics review, retire checklist items that never catch anything.

## Framework mapping (only on request)
- OWASP SAMM: Design (Threat Assessment, Security Requirements), Implementation (Secure Build), Verification (Requirements-driven Testing)
- NIST SSDF (SP 800-218): PW.1 (design), PW.2 (design review), PW.7 (code review), RV (vulnerability response)
- OWASP ASVS: source for acceptance-criteria wording by level (L1/L2/L3)
