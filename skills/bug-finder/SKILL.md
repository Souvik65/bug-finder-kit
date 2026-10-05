---
name: bug-finder
description: Systematically finds and diagnoses bugs in code. Use when the user reports an error, a failing test, unexpected behavior, a crash, or asks to debug, review for bugs, or find the root cause.
---

# Bug Finder

## Process
1. Reproduce: get the exact error, input, and environment. If unclear, ask.
2. Locate: trace from the symptom (stack trace, failing line) back to the source.
3. Form hypotheses: list 2-3 likely causes, ranked by probability.
4. Verify: confirm each hypothesis by reading code, adding logs, or running a test. Never guess.
5. Fix: make the smallest change that fixes the root cause.
6. Prevent: add a regression test.

## Checklist of common causes
- Off-by-one and boundary conditions
- Null/undefined handling
- Async/race conditions and missing `await`
- Wrong types or implicit conversions
- State mutated unexpectedly
- Environment/config differences

For language-specific patterns, see `references/common-bugs.md`.

## Output format
- **Root cause:** one sentence
- **Evidence:** file:line and why
- **Fix:** the diff
- **Test:** how to confirm it's fixed

## Rules
- Do not refactor unrelated code.
- State clearly when a cause is unconfirmed.