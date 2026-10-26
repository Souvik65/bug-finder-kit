# Security and abuse stories

Two flavors, use both:
- **Security story** - a positive requirement written in the team's normal format.
- **Abuse (misuse) story** - the attacker's perspective, which exposes cases normal stories miss.

## Formats

**Security story**
> As a <role/system owner>, I need <control> so that <risk is reduced>.
> Acceptance: see criteria. Estimate: <points>. Owner: <team>.

**Abuse story**
> As an attacker with <capability>, I want to <malicious action> so that <harm>.
> Mitigation stories: <links>. Detection: <log/alert>.

Always include the **capability** of the attacker (anonymous, authenticated low-privilege user, malicious tenant admin, compromised dependency, insider). The same flaw has different severity at different capability levels.

## Procedure to generate stories from a feature ticket
1. Read the feature and underline the nouns that are *data* and the verbs that are *actions on data*.
2. For each action, ask: who is allowed, who is not, what if input is hostile, what if it is repeated or concurrent, what is logged?
3. Write 1 abuse story per realistic attacker goal (aim for 2-5, not 20).
4. Write the security stories that neutralize them; reuse paved-road stories where they exist ("use shared authz middleware") rather than inventing new controls.
5. Split anything over ~3 points; attach to the parent feature so it cannot be silently dropped from the sprint.

## Story library (adapt, don't paste)

| Feature type | Abuse story | Security story |
|--------------|-------------|----------------|
| Login / sessions | Attacker with leaked password list credential-stuffs accounts | Throttle by account+IP, breach-password check, alert on anomalous login |
| Password reset | Attacker takes over account via guessable/long-lived token | Single-use, short-lived, high-entropy tokens; uniform responses; notify user |
| Object access by ID (IDOR) | Authenticated user changes ID to read another user's/tenant's record | Authorize every object access server-side against owner/tenant; deny with 404 |
| Search / filters | Attacker injects query syntax to dump data | Parameterized queries / allow-listed fields; row-level scoping |
| File upload | Attacker uploads script or oversized/polyglot file | Allow-list types by content, size caps, store outside web root, scan, serve with safe headers |
| Public API | Scraper or abuser exhausts resources | Per-key rate limits, pagination caps, timeouts, request size limits |
| Webhooks | Attacker replays or forges events | Verify signatures, timestamp window, idempotency keys |
| Admin / support tooling | Support user views data beyond need or impersonates silently | Role-scoped access, reason capture, immutable audit log, impersonation banner |
| Export / reporting | Insider bulk-exports sensitive data | Permission check on export, volume alerts, watermark/audit |
| Third-party SDK/dependency | Compromised package runs in build or prod | Pin and verify versions, SCA gate, least-privilege CI tokens, SBOM |
| Secrets in config | Key leaked via repo/logs | Secret manager, no secrets in code/logs, rotation story, pre-commit scanning |
| LLM feature | Injected content causes tool misuse or data leak | Scope tool permissions, treat model output as untrusted, isolate per-user context, output/link filtering, spend limits |

## Definition of Ready (security addendum)
A T2/T3 story is not ready for sprint until: data classification noted, trust boundary impact stated, security stories linked, and owner for the security review named.
