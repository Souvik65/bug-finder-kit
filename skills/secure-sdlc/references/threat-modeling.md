# Threat modeling gate (lightweight)

Goal: a 30-60 minute conversation that leaves behind a one-page artifact, not a 40-page document nobody reads. Run it at design time, before implementation starts, when changes are cheap.

## When the gate fires
Mandatory for T2/T3. Optional for T1 if the author is unsure. Re-trigger when the design changes materially (new data store, new external caller, new privilege level).

## Participants (keep it to 3-5)
Feature author, one engineer who knows the surrounding system, a security champion or AppSec engineer, optionally product for abuse-case realism.

## The four questions (Shostack-style)
1. What are we building? (data-flow sketch)
2. What can go wrong? (STRIDE per element)
3. What are we going to do about it? (mitigate / eliminate / transfer / accept)
4. Did we do a good job? (verification mapped to tests)

## Step-by-step
1. **Sketch the data flow.** Boxes: external actors, processes, data stores. Arrows: data flows. Draw **trust boundaries** as dashed lines (internet->app, app->DB, tenant A->tenant B, user->admin, app->third party). Keep to one screen.
2. **List assets.** What would hurt if stolen, altered, or unavailable? (credentials, PII, payment tokens, tenant data, audit logs, model prompts/keys.)
3. **Apply STRIDE to each element that crosses a boundary:**
   - **S**poofing - can someone pretend to be a user/service? -> authN
   - **T**ampering - can data be modified in transit/at rest? -> integrity
   - **R**epudiation - can an actor deny an action? -> audit logging
   - **I**nformation disclosure - can data leak? -> authZ, encryption, error handling
   - **D**enial of service - can it be exhausted? -> rate limits, quotas, timeouts
   - **E**levation of privilege - can someone gain access they shouldn't? -> authZ, least privilege
4. **Prioritize.** Score each threat Likelihood x Impact (Low/Med/High). Keep the top ~10. Discard theoretical threats that require an attacker who has already won.
5. **Decide the response** for each: Mitigate (name the control), Eliminate (remove the feature/data), Transfer (use a vetted service), or Accept (needs a risk acceptance record).
6. **Convert to work.** Every "Mitigate" becomes a security story or acceptance criterion with an owner. Every "Verify" becomes a test or review step.

## Add-on prompts by feature type
- **Multi-tenant**: what stops tenant A guessing tenant B's IDs? Where is tenant context set and can it be overridden by the client?
- **File upload**: type/size/content validation, storage location, malware scanning, who can fetch it, is it ever executed/rendered?
- **Third-party integration**: what do we trust from them, what do we send them, how are secrets stored/rotated, what if they are compromised or slow?
- **LLM/agent features**: untrusted content in prompts (prompt injection), tool permission scope, data exfiltration via outputs/links, cross-user context leakage, cost abuse.
- **Background jobs/webhooks**: replay, signature verification, idempotency, who can enqueue.
- **Admin paths**: separate authN strength, audit trail, impersonation controls.

## Artifact template (Markdown)

```
# Threat model: <feature> - <date>
Tier: T<n>   Owner: <name>   Reviewers: <names>   Status: Draft | Approved

## Scope & data flow
<diagram or bullet flow; list trust boundaries>

## Assets
- ...

## Threats
| # | Element | STRIDE | Threat | L | I | Response | Control / Story ref | Owner |
|---|---------|--------|--------|---|---|----------|---------------------|-------|

## Assumptions & out of scope
- ...

## Verification plan
- <threat #> -> <test / review / tool>

## Open questions & accepted risks
- <link to risk acceptance record if any>
```

## Exit criteria
- Data flow and trust boundaries agreed by author and reviewer.
- Every High threat has a mitigation story or an approved risk acceptance.
- Verification plan exists for each mitigation.
- Artifact stored next to the design doc (not in someone's laptop).
