---
name: bug-finder
description: >
  Universal bug-finding and root-cause analysis skill. Activate whenever a user
  reports an error, exception, crash, failing test, unexpected output, regression,
  performance degradation, data corruption, or asks to "debug", "fix", "investigate",
  or "find the root cause" — regardless of language, framework, or platform.
triggers:
  - "error"
  - "exception"
  - "bug"
  - "crash"
  - "not working"
  - "failing test"
  - "unexpected behavior"
  - "debug"
  - "root cause"
  - "why is this happening"
version: 2.0.0
author: bug-finder-kit
---

# Bug Finder — Universal Root-Cause Analysis

> A systematic, evidence-driven debugging framework applicable to any language,
> framework, or runtime. Follow every phase in order. Do not skip steps.

---

## Phase 0 — Triage (Before Touching Any Code)

Before writing or changing a single line, gather enough context to work efficiently.

### Required information
| Item | How to get it |
|---|---|
| **Exact error message / stack trace** | Ask the user to paste it verbatim |
| **Minimal reproduction steps** | What exact input, action, or state triggers the bug? |
| **Expected vs. actual behavior** | One sentence each |
| **Environment** | Language version, OS, runtime, dependencies, env vars |
| **When it started** | Always worked? Broke after a specific commit / deploy? |

> **Rule:** If any of the above is missing and cannot be inferred from the code,
> ask for it explicitly. Do not speculate on ambiguous information.

---

## Phase 1 — Understand the Symptom

1. **Read the full stack trace** top-to-bottom. Identify:
   - The exception type / error code
   - The first frame in *user code* (not library code)
   - Any chained / wrapped causes (`caused by`, `inner exception`, `source error`)

2. **Classify the bug type** to narrow the search space:

   | Category | Signals |
   |---|---|
   | **Logic error** | Wrong output, off-by-one, incorrect formula |
   | **Null / undefined dereference** | NullPointerException, TypeError, segfault |
   | **Type mismatch** | Implicit coercion, wrong cast, schema mismatch |
   | **Async / concurrency** | Race condition, deadlock, missing `await`, stale closure |
   | **State corruption** | Works first run, fails on second; mutation side effects |
   | **Resource / lifecycle** | Memory leak, file handle not closed, connection pool exhausted |
   | **Configuration / env** | Works locally, fails in CI/staging/prod |
   | **Dependency / version** | Broke after upgrade; peer dependency conflict |
   | **Integration / contract** | API changed, wrong payload shape, auth token expired |
   | **Performance regression** | Correct output but too slow or OOM |

---

## Phase 2 — Locate the Source

Work **backwards** from the symptom to the cause. Use these techniques in order:

1. **Trace the call stack** — follow the chain of function calls to the originating line.
2. **Bisect if needed** — if no stack trace, use binary search (git bisect, comment-out, dichotomy) to isolate the breaking change.
3. **Read the data, not the code** — print / log the actual values at each step. Do not assume what a variable contains.
4. **Check recent changes** — `git log --oneline -20`, `git diff HEAD~1`, changelogs.
5. **Search for similar issues** — error message in issues / PRs / known bug trackers.

> **Rule:** Cite every claim with a specific file, line number, and the exact value
> or code that supports it. Example: `src/parser.ts:42 — token is undefined when
> input string is empty`.

---

## Phase 3 — Form Hypotheses

List **2–4 candidate root causes**, ranked by probability. For each hypothesis:

```
Hypothesis N: <one-sentence description>
  Probability: High / Medium / Low
  Evidence for: <what in the code/trace supports this>
  Evidence against: <what contradicts or limits this>
  Test to confirm: <exact step that would prove or disprove it>
```

> **Rule:** Do not commit to a fix until at least one hypothesis is confirmed.
> State "unconfirmed" explicitly if you cannot verify without running the code.

---

## Phase 4 — Verify

For each top hypothesis, choose the appropriate verification method:

| Method | When to use |
|---|---|
| **Read the code** | Logic errors, type issues, missing guards |
| **Add targeted logging** | Runtime state unknown; cannot reproduce locally |
| **Write a failing test** | Regression; isolate the exact failing condition |
| **Inspect live state** | Debugger breakpoint, REPL, `console.log` / `print` / `dbg!` |
| **Check external state** | DB query, API response, file contents, env var value |
| **Reproduce in isolation** | Extract the minimal failing snippet |

Confirm or rule out each hypothesis before proceeding to the fix.

---

## Phase 5 — Fix

### Principles
- Make the **smallest possible change** that addresses the root cause.
- Do **not** refactor unrelated code in the same commit.
- Preserve existing behavior for all other inputs/paths.
- If the fix requires a larger structural change, note it separately as a follow-up.

### Fix checklist
- [ ] Root cause confirmed (not just symptom suppressed)
- [ ] Edge cases handled (null, empty, boundary, overflow, concurrent access)
- [ ] No new side effects introduced
- [ ] Error messages are clear and actionable for future debuggers
- [ ] Secrets / sensitive values not introduced or exposed

---

## Phase 6 — Prevent Regression

Every confirmed bug warrants a test that:
1. **Fails** on the unfixed code (proves it caught the bug)
2. **Passes** after the fix (proves the fix works)
3. Is placed in the appropriate test file / suite for the module

If a test is not feasible (e.g., infrastructure-level issue), document the detection
method (monitoring alert, log pattern, health check) instead.

---

## Common Bug Patterns — Quick Reference

### Null / Undefined
- Forgotten null check on optional function parameter
- API response field absent in certain edge cases
- Uninitialized variable used before assignment
- Optional chaining (`?.`) or null coalescing (`??`) not applied

### Async & Concurrency
- Missing `await` on a Promise-returning function
- Shared mutable state accessed from multiple goroutines/threads without a lock
- Event handler fires after component/resource is already destroyed
- Race between two concurrent writes to the same resource

### Off-by-One & Boundaries
- Loop iterates one too many / too few times (`<` vs `<=`)
- Array index starts at 0 but logic assumes 1
- Pagination: last page incomplete or skipped
- Date/time: exclusive vs. inclusive end bound

### Type & Coercion
- `==` vs `===` (JS), `is` vs `==` (Python), unintended implicit cast
- Integer overflow / underflow in fixed-width types
- String-to-number parse returning NaN / 0 silently
- JSON field typed as string when number expected (or vice versa)

### State & Mutation
- Object passed by reference and mutated by callee
- Global/module-level state carrying over between tests
- Cache returning stale data after an update
- Event handler registered multiple times → duplicate execution

### Environment & Configuration
- Hard-coded path that only exists on the developer's machine
- Missing or wrong environment variable in CI/staging
- Dependency version pinned locally but floating in CI
- Timezone assumption: UTC vs. local time

### Integration & API Contracts
- Breaking change in upstream API (new required field, renamed key)
- Auth token expired or rotated without updating the consumer
- Payload serialization mismatch (snake_case vs. camelCase, date format)
- Retry logic that re-sends non-idempotent requests

---

## Output Format

Respond with the following structure. Do not omit sections.

```
## Bug Report

### Root Cause
<One clear sentence stating the exact root cause.>

### Evidence
| File | Line | Finding |
|---|---|---|
| path/to/file.ext | 42 | <what the code does wrong> |

### Hypotheses Considered
1. <Hypothesis> — Confirmed / Ruled out (reason)
2. <Hypothesis> — Confirmed / Ruled out (reason)

### Fix
<Short explanation of what changes and why.>

--- diff ---
- old code
+ new code
--- end diff ---

### Regression Test
<Test name / location and what it asserts.>

### Follow-up (optional)
<Any related issues or refactors worth addressing separately.>
```

---

## Rules of Engagement

1. **Evidence before conclusions.** Every claim must cite a specific location in the code or runtime output.
2. **Smallest fix.** Never change more than what is necessary to fix the confirmed root cause.
3. **No silent failures.** If the cause cannot be confirmed without running the code, state this clearly.
4. **No refactoring in the same change.** Improvements go in a follow-up.
5. **Language agnostic.** Apply this process equally to Python, TypeScript, Go, Rust, Java, C/C++, Ruby, SQL, shell scripts, or any other language.
6. **Security-aware.** Flag any fix that could introduce or expose a security vulnerability.
7. **Test every fix.** A fix without a regression test is incomplete.