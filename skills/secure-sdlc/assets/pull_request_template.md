## What & why
<!-- Summary and linked ticket -->

## Risk tier
- [ ] T0 Routine  - [ ] T1 Standard  - [ ] T2 Elevated  - [ ] T3 Critical
<!-- Unsure? Pick higher and ask in #security-champions -->

## Security check (3 questions)
- [ ] Touches authN/authZ, secrets, crypto, user input, or data storage? -> complete relevant section
- [ ] New dependency, external call, or permission? -> complete "Supply chain"
- [ ] Could sensitive data be logged/exposed/persisted in a new place?

<details><summary>AuthN / AuthZ</summary>

- [ ] Server-side authN + object-level authZ on every new endpoint
- [ ] Negative test (wrong user/tenant/role)
- [ ] No client-trusted role/tenant/user ID
</details>

<details><summary>Input / output</summary>

- [ ] Allow-list validation; parameterized queries
- [ ] Context-appropriate output encoding
- [ ] Path traversal / SSRF considered
</details>

<details><summary>Data & secrets</summary>

- [ ] No secrets/PII in code, logs, errors, fixtures
- [ ] Encryption and retention considered
</details>

<details><summary>Supply chain / integrations</summary>

- [ ] Dependency reviewed and pinned
- [ ] Timeouts and least-privilege credentials
- [ ] Inbound events verified (signature/replay)
</details>

<details><summary>T2/T3 only</summary>

- Threat model / security stories: <link>
- Security reviewer: @
- Pre-release verification (T3): <link>
</details>
