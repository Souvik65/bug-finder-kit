# Security Code Review Checklist

## Data flow
- [ ] Trace external input to parsing, storage, rendering, and execution.
- [ ] Review data in transit and at rest.
- [ ] Review client-side presentation and DOM handling.
- [ ] Review server-side processing and persistence.

## Identity and privilege
- [ ] Authentication is explicit and consistently enforced.
- [ ] Authorization is checked server-side at the relevant resource/function boundary.
- [ ] Modules do not receive unnecessary privileges.
- [ ] Sensitive operations do not rely on client-side trust.

## Injection and execution
- [ ] Database operations use structured/parameterized mechanisms.
- [ ] OS/CLI calls constrain commands and arguments.
- [ ] Parsers are configured safely.
- [ ] User-controlled content is handled according to its output context.

## Anti-patterns
- [ ] No unsafe blacklist-only control where allowlisting is feasible.
- [ ] Default/boilerplate configuration has been reviewed and hardened.
- [ ] Trust-by-default permissions are avoided.
- [ ] Client/server responsibilities are appropriately separated.

## Testing
- [ ] Static analysis where appropriate.
- [ ] Dynamic testing where appropriate.
- [ ] Regression test exists for every fixed security defect.
