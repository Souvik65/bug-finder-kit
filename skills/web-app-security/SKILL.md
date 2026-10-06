---
name: web-app-security
version: 1.0.0
description: A source-grounded web application security assessment skill based on the supplied Web Application Security reference. Use it for authorized reconnaissance, architecture review, code review, vulnerability analysis, defensive guidance, and professional security findings.
---

# Web Application Security Skill

## Purpose

Use this skill to assess modern web applications through a repeatable security workflow inspired by the supplied reference. The workflow is organized around three complementary phases: Recon, Offense/validation, and Defense.

The skill is source-grounded: when a requested conclusion is not supported by the supplied reference, say so instead of presenting it as if it came from the reference.

## Authorization and safety boundary

Only perform active exploitation, payload deployment, destructive testing, credential testing, denial-of-service testing, or access-control bypass testing against systems the user owns or is explicitly authorized in writing to test. For unknown or third-party targets, limit work to passive analysis, defensive review, lab examples, or high-level guidance.

Prefer non-destructive validation. Do not intentionally exfiltrate real secrets, damage data, degrade availability, or persist access.

## Core workflow

### 1. Establish scope

Before testing, identify:
- Target applications, domains, APIs, environments, and accounts.
- Testing authorization and permitted techniques.
- Authentication levels available.
- Sensitive-data boundaries.
- Rate, availability, and data-handling constraints.

If scope is missing for an active test, stop before exploitation and request it.

### 2. Reconnaissance

Build an application model before attempting exploitation.

Map:
- Domains and subdomains.
- Web servers and application entry points.
- HTTP methods and request/response behavior.
- API endpoints and endpoint shapes.
- Authentication and authorization boundaries.
- Client-side frameworks and libraries.
- Server-side frameworks and databases where observable.
- Third-party integrations and dependency versions when discoverable.
- Data stores, trust boundaries, and important application flows.
- Architectural inconsistencies and security-control gaps.

Prioritize attack paths based on exposed functionality, trust boundaries, sensitive data, privileges, and business logic rather than scanning blindly.

### 3. Threat and attack-surface analysis

For every major feature ask:
1. What input does it accept?
2. Where does that input travel?
3. Where is it transformed, parsed, stored, rendered, or executed?
4. Which identity and permissions are in effect at each step?
5. Which external services or dependencies are involved?
6. What security control is expected to stop abuse?
7. Can the control be bypassed through an alternate path or representation?

Look for both common vulnerability archetypes and application-specific business-logic weaknesses.

### 4. Authorized validation

Where active testing is authorized, validate hypotheses against the smallest safe test case. Connect each test to a specific hypothesis and expected security boundary.

Primary vulnerability families from the reference include:
- XSS: stored, reflected, DOM-based, and mutation-oriented cases.
- CSRF and state-changing request abuse.
- XXE, including direct and indirect parser flows.
- SQL injection and other injection classes, including command/code injection.
- DoS classes such as regex/resource exhaustion and logical abuse.
- Third-party dependency weaknesses.

Do not assume a vulnerability exists merely because an input looks suspicious. Confirm impact and the violated security property.

### 5. Finding construction

For each confirmed issue record:
- Title.
- Affected asset/component.
- Preconditions and scope.
- Security property violated.
- Reproduction steps suitable for an authorized tester.
- Evidence.
- Impact and affected data/functionality.
- Likely root cause.
- Severity/risk rationale.
- Recommended remediation.
- Regression-test recommendation.

Separate observed facts from assumptions.

### 6. Vulnerability management

After discovery:
1. Reproduce the issue safely.
2. Assess risk using impact, exploit difficulty, affected data, contractual/business consequences, and existing mitigations.
3. Prioritize remediation.
4. Track the fix to completion.
5. Add monitoring/logging when a known issue could be abused while remediation is pending.
6. Add a regression test that demonstrates the vulnerability remains fixed.

CVSS may be used when a formal scoring system is requested, but do not fabricate vector components without sufficient evidence.

### 7. Defensive review

Review security at multiple layers:
- Architecture and data flow.
- Authentication and authorization.
- Transport security.
- Credential storage and hashing.
- Sensitive/PII/financial-data handling.
- Code-level controls.
- Static and dynamic testing.
- Regression testing.
- Dependency management.
- Logging and monitoring.
- Secure-by-default behavior.

Prefer broad, consistent controls at architectural boundaries instead of relying on scattered per-feature fixes.

## Code-review priorities

When reviewing code, trace data from source to sink and inspect:
- Network input.
- Parsing and deserialization.
- Database queries.
- OS/CLI execution.
- Template/HTML/DOM rendering.
- File access.
- Authentication and authorization checks.
- Privilege boundaries.
- Third-party calls.
- Logging and error handling.

Explicitly check for anti-patterns highlighted by the reference:
- Blacklist-only security controls where a positive allowlist is more appropriate.
- Unreviewed boilerplate/default configuration.
- Trust-by-default permissions.
- Excessive privilege shared by unrelated modules.
- Tight client/server coupling that expands parsing and trust complexity.

## Defensive families

### XSS
Use context-appropriate output handling and input validation/sanitization. Review DOM sinks, HTML, CSS, hyperlink handling, and browser execution contexts. Consider Content Security Policy as an additional mitigation, not a substitute for safe coding.

### CSRF
Protect state-changing operations with appropriate request-origin verification and CSRF defenses. Avoid state-changing GET behavior. Validate the actual application authentication model before choosing a mitigation.

### XXE
Review XML and XML-like parsing paths, including cases where the server constructs XML from user-controlled data. Harden parsers and avoid unsafe external-entity behavior.

### Injection
Prefer structured interfaces and parameterized/prepared database operations. Constrain command selection with positive allowlists where commands must be invoked. Apply least authority to processes and integrations.

### DoS
Review regex complexity, unbounded resource consumption, expensive application logic, and request/traffic amplification. For distributed traffic attacks, mitigations must account for legitimate-user behavior and availability requirements.

### Dependencies
Inventory direct and transitive dependencies. Record versions and integration methods. Check known vulnerability sources when external research is permitted. Treat dependency trees as part of the application's attack surface.

## Output modes

When the user asks for an audit, default to:
1. Executive summary.
2. Scope and assumptions.
3. Attack-surface/recon summary.
4. Findings ordered by risk.
5. Evidence and validation.
6. Root cause.
7. Remediation.
8. Regression tests.
9. Residual risk and next steps.

When the user asks to learn, teach the reasoning first and avoid dumping unexplained commands or payloads.

## Source fidelity

This skill is an original operational synthesis of the supplied reference, not a reproduction of the book. Use the source map in `references/source-map.md` to connect workflow areas to the reference's chapter structure.
