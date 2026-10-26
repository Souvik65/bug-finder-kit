# Security acceptance criteria

Write criteria that a tester or reviewer can mark pass/fail. Prefer Given/When/Then so they convert directly into automated tests. Select only the categories that apply to the feature and tier; a T1 story typically needs 3-6 criteria.

## Pattern
> **Given** <actor/state> **When** <action> **Then** <observable secure outcome> **And** <logged/alerted/rate-limited>.

## Criteria by category

### Authentication
- Given an unauthenticated request, when it calls `<endpoint>`, then it receives 401 and no resource data.
- Given 10 failed logins in 5 minutes, then further attempts are throttled and an event is logged.
- Given a session older than `<N>` minutes idle, then it is invalidated server-side.

### Authorization
- Given user A, when requesting user B's `<resource>` by ID, then the response is 404/403 and the attempt is logged. *(automated test required)*
- Given a user without role `<R>`, when calling `<privileged action>`, then it is denied even if the UI hides the control.
- Authorization is enforced in the service layer via `<shared mechanism>`, not only in the controller or client.

### Input handling
- Given input exceeding `<limit>` or containing unexpected types, then it is rejected with a generic 400 and not logged raw.
- Database access uses parameterized queries; no string-built SQL/commands.
- Given user content rendered in HTML, then it is output-encoded for its context.

### Data protection
- `<data class>` is encrypted in transit (TLS 1.2+) and at rest using `<managed mechanism>`.
- Sensitive fields (`<list>`) never appear in logs, URLs, analytics, or error messages.
- Data retention: records are deleted/anonymized after `<period>`; deletion tested.

### Secrets and config
- No credentials in source, images, or CI logs; secrets retrieved from `<secret manager>` at runtime.
- Rotation of `<secret>` can be done without code change or downtime.

### Error handling and logging
- Errors return generic messages; stack traces never reach clients.
- Security-relevant events (auth, authz denial, privilege change, export) are logged with actor, action, target, time - and are tamper-resistant.

### Availability and abuse
- Endpoint enforces `<rate>` per `<key>`; pagination capped at `<n>`; downstream calls have timeouts and circuit breaking.

### Third-party and supply chain
- New dependency is from an approved source, version-pinned, with no known critical/high vulnerabilities at merge.
- Webhook payloads are verified by signature and timestamp before processing.

### Privacy
- Only fields needed for `<purpose>` are collected; consent/notice updated if purpose changes.

## Tier mapping
| Tier | Expected criteria |
|------|-------------------|
| T0 | None beyond default PR checklist |
| T1 | AuthZ + input + logging, plus any category the feature touches |
| T2 | All applicable categories, each tied to an automated test or named review step |
| T3 | All applicable + independent verification (pen test, targeted security review) before release |

## Anti-patterns to rewrite
- "System must be secure" -> specify the control and test.
- "Follow OWASP Top 10" -> name the relevant risks and the controls.
- Criteria that only check the happy path -> add the negative case (wrong user, malformed input, replay).
