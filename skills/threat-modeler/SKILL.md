---
name: threat-modeler
description: >
  STRIDE threat modeling skill for software systems. Systematically identifies
  Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and
  Elevation of Privilege threats across trust boundaries, data flows, and system
  components. Produces structured threat models with mitigations, DREAD scoring,
  and attack trees. Activate when the user asks to "threat model", "STRIDE analysis",
  "identify threats", "attack surface analysis", "trust boundary review", or "model threats".
triggers:
  - "threat model"
  - "STRIDE analysis"
  - "identify threats"
  - "attack surface analysis"
  - "trust boundary review"
  - "model threats"
  - "attack tree"
  - "threat assessment"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# Threat Modeler — STRIDE Threat Modeling

> Systematic threat identification using STRIDE methodology, trust boundary analysis,
> data flow decomposition, and attack tree generation. Produces actionable threat
> models with mitigation strategies and priority scoring.

---

## Methodology Overview

```
1. Decompose the System  → Components, data flows, trust boundaries
2. Apply STRIDE          → 6 threat categories per component/flow
3. Score with DREAD      → Prioritize by risk
4. Generate Attack Trees → Visualize attack paths
5. Propose Mitigations   → Map to security controls
6. Produce Report        → Structured threat model document
```

---

## Phase 1 — System Decomposition

### Gather System Information

Ask the user (or infer from the codebase):

1. **What does this system do?** (One paragraph description)
2. **Who are the actors?** (Users, admins, external services, internal services)
3. **What data flows through the system?** (PII, financial, auth tokens, files)
4. **What are the trust boundaries?** (Internet/DMZ, DMZ/internal, service-to-service)
5. **What are the external dependencies?** (DBs, APIs, queues, CDNs)

### System Component Inventory

Map these elements:

| Element Type | Examples |
|---|---|
| **External Entities** | Browser, Mobile App, External API, Third-party service |
| **Processes** | Web server, API server, Background worker, Auth service |
| **Data Stores** | SQL DB, NoSQL DB, File storage, Cache, Message queue |
| **Data Flows** | HTTP requests, DB queries, File reads, Queue messages |
| **Trust Boundaries** | Internet ↔ DMZ, DMZ ↔ Internal, Service ↔ Service |

### Trust Boundary Map

```
[Internet]
    |
    | HTTPS (TLS 1.2+)
    |
[Load Balancer] ←——— Trust Boundary 1: Internet ↔ DMZ
    |
    | HTTP (internal)
    |
[Web App / API Server]
    |        |
    |        | TLS + mTLS ←— Trust Boundary 2: Service ↔ DB
    |        |
    |    [Database]
    |
    | Internal network ←— Trust Boundary 3: Service ↔ Service
    |
[Background Workers / Queues]
```

---

## Phase 2 — STRIDE Threat Analysis

Apply STRIDE according to element type using the standard Microsoft STRIDE-per-element mapping (or STRIDE-per-interaction):

| DFD Element Type | Spoofing (S) | Tampering (T) | Repudiation (R) | Info Disclosure (I) | Denial of Service (D) | Elevation of Privilege (E) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **External Entity** | ✓ | | ✓ | | | |
| **Process / Service** | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Data Flow** | | ✓ | | ✓ | ✓ | |
| **Data Store** | | ✓ | ✓ | ✓ | ✓ | |

### S — Spoofing (Authentication threats)

> An attacker pretends to be someone/something they're not.

**Questions to ask:**
- Can an attacker impersonate a user or service?
- Is authentication enforced at every trust boundary crossing?
- Can session tokens be stolen or forged?

**Common threats:**
```
SPOOF-001: Token theft via XSS → attacker uses victim's JWT
SPOOF-002: API key compromise → attacker calls API as legitimate client
SPOOF-003: Man-in-the-middle → attacker intercepts unencrypted service-to-service
SPOOF-004: Credential stuffing → compromised credentials from other breaches
SPOOF-005: Phishing → attacker captures credentials via fake login page
SPOOF-006: Service impersonation → attacker stands up fake service at spoofed endpoint
```

**For each process/service:**
- How does it verify the identity of its callers?
- Is mutual TLS used for service-to-service?
- How are credentials protected?

### T — Tampering (Integrity threats)

> An attacker modifies data or code to achieve unauthorized goals.

**Questions to ask:**
- Can an attacker modify data in transit?
- Can stored data be altered without detection?
- Can inputs be crafted to change system behavior?

**Common threats:**
```
TAMPER-001: Parameter tampering → modifying price, quantity, user ID in requests
TAMPER-002: Database record modification → unauthorized UPDATE/DELETE
TAMPER-003: Man-in-the-middle data modification → tampering with unencrypted traffic
TAMPER-004: Log tampering → attacker erases audit trail
TAMPER-005: Dependency tampering → malicious package in supply chain
TAMPER-006: Configuration modification → changing security-relevant settings
```

**For each data flow and store:**
- Is data integrity protected (HMAC, digital signature, checksums)?
- Are database write operations authorized and audited?
- Is the code deployment pipeline integrity-verified?

### R — Repudiation (Non-repudiation threats)

> An attacker denies performing an action (or a legitimate action can't be proven).

**Questions to ask:**
- Can a user deny performing a sensitive action?
- Are all security-relevant events logged with sufficient context?
- Can logs be deleted or altered?

**Common threats:**
```
REPUD-001: Missing audit logs → admin actions not recorded
REPUD-002: Log deletion → attacker covers tracks
REPUD-003: Insufficient log detail → "something happened" but no user/action context
REPUD-004: Shared credentials → can't attribute action to specific user
REPUD-005: No timestamps or unreliable timestamps → events can't be ordered
```

**For each privileged operation:**
- Who performed it? (user ID, service name)
- What did they do? (action, resource, before/after values)
- When? (reliable timestamp with timezone)
- From where? (IP address, device fingerprint)

### I — Information Disclosure (Confidentiality threats)

> Sensitive information is exposed to unauthorized parties.

**Questions to ask:**
- What sensitive data exists, and who should have access to it?
- Can an attacker extract data they shouldn't see?
- Is sensitive data leaked in error messages, logs, or responses?

**Common threats:**
```
INFODIS-001: SQL/NoSQL injection → attacker dumps database
INFODIS-002: IDOR → user accesses another user's resources
INFODIS-003: Verbose error messages → stack traces expose internal paths, dependencies
INFODIS-004: Log PII exposure → passwords, tokens, PII written to logs
INFODIS-005: Insecure direct file access → reading arbitrary files via path traversal
INFODIS-006: API over-fetching → response includes more data than the caller should see
INFODIS-007: Cache poisoning → cached response contains another user's data
INFODIS-008: Backup exposure → unencrypted backups accessible
INFODIS-009: Traffic analysis → metadata leaks info even with encrypted payloads
```

### D — Denial of Service (Availability threats)

> An attacker disrupts service availability for legitimate users.

**Questions to ask:**
- What inputs can cause the system to consume excessive resources?
- Are there single points of failure?
- Is the system protected against volumetric attacks?

**Common threats:**
```
DOS-001: Unbounded queries → user-controlled LIMIT causes DB overload
DOS-002: File upload → large files exhaust disk/memory
DOS-003: ReDoS → regex with catastrophic backtracking on user input
DOS-004: Amplification → one request triggers many downstream requests
DOS-005: GraphQL DoS → deeply nested queries, no depth/complexity limit
DOS-006: Resource exhaustion → thread pool, connection pool, memory exhaustion
DOS-007: Slow loris → many slow connections held open
DOS-008: Account lockout abuse → lock out legitimate users by triggering failed auth
```

### E — Elevation of Privilege (Authorization threats)

> An attacker gains more permissions than they should have.

**Questions to ask:**
- Can a user access resources or perform actions beyond their role?
- Can privileges be escalated without proper authorization?
- Are there hidden admin functions?

**Common threats:**
```
ELEVPRIV-001: IDOR → user accesses/modifies another user's data
ELEVPRIV-002: Mass assignment → user sets own role via API body
ELEVPRIV-003: JWT role manipulation → if role is in JWT payload, user edits it
ELEVPRIV-004: Path traversal to admin → accessing admin endpoints via URL tricks
ELEVPRIV-005: Function-level auth bypass → admin endpoints not role-checked
ELEVPRIV-006: SQL injection to admin → injecting to get admin record
ELEVPRIV-007: Race condition privilege → concurrent request bypasses privilege check
ELEVPRIV-008: Insecure deserialization → escalate via crafted serialized object
```

---

## Phase 3 — DREAD Scoring

Score each threat to prioritize mitigations:

| Dimension | 1 (Low) | 2 (Medium) | 3 (High) |
|---|---|---|---|
| **D**amage | Minor inconvenience | Data of subset of users | Complete data loss, RCE |
| **R**eproducibility | Very difficult | Sometimes | Always, easily reproduced |
| **E**xploitability | Expert attacker | Skilled attacker | Script kiddie, automated |
| **A**ffected users | Individual | Group | All users |
| **D**iscoverability | Very hard to find | Requires analysis | Obvious, in documentation |

**DREAD Score** = (D + R + E + A + D) / 5

| Score | Risk Level |
|---|---|
| 2.5 – 3.0 | CRITICAL |
| 2.0 – 2.4 | HIGH |
| 1.5 – 1.9 | MEDIUM |
| 1.0 – 1.4 | LOW |

---

## Phase 4 — Attack Tree Generation

For the highest-risk threats, generate attack trees:

```
Attack Goal: Gain unauthorized admin access

OR
├── Steal admin credentials
│   OR
│   ├── Phishing attack on admin user
│   └── Credential stuffing (leaked password from other breach)
│
├── Exploit authentication bypass
│   OR
│   ├── SQLi on login form → admin record extraction
│   ├── JWT algorithm confusion (none/RS256→HS256)
│   └── Race condition in session creation
│
└── Escalate from user to admin
    OR
    ├── Mass assignment (PUT /profile body: {role: "admin"})
    ├── IDOR to admin-only resource
    └── Insecure deserialization → RCE → modify role in DB
```

Format attack tree as markdown nested list with OR/AND gates.

---

## Phase 5 — Mitigation Mapping

For each threat, map to a specific security control:

| Threat Category | Mitigation Category | Specific Controls |
|---|---|---|
| Spoofing | Authentication | MFA, strong password policy, certificate pinning |
| Tampering | Integrity | Digital signatures, HMAC, input validation, parameterized queries |
| Repudiation | Audit logging | Centralized logging, immutable log storage, tamper evidence |
| Information Disclosure | Confidentiality | Encryption at rest/transit, access control, output filtering |
| Denial of Service | Availability | Rate limiting, pagination, timeout, circuit breaker |
| Elevation of Privilege | Authorization | RBAC, least privilege, IDOR checks, deny by default |

---

## Phase 6 — Threat Model Report

### Report Structure

```markdown
# Threat Model: [System Name]

**Date:** YYYY-MM-DD
**Version:** 1.0
**Threat Modeler:** bug-finder-kit
**Methodology:** STRIDE + DREAD

## 1. System Overview

[One paragraph system description]

## 2. Assets and Trust Boundaries

### Assets
| Asset | Sensitivity | Owner |
|---|---|---|
| User PII | High | User |
| Authentication tokens | Critical | System |
| Financial records | High | Company |

### Trust Boundaries
[List and diagram of trust boundaries]

## 3. Threat Inventory

| ID | STRIDE Category | Description | DREAD Score | Risk | Status |
|---|---|---|---|---|---|
| TM-001 | Spoofing | JWT algorithm confusion | 2.4 | HIGH | OPEN |
| TM-002 | Tampering | SQL injection on search | 2.8 | CRITICAL | OPEN |
| TM-003 | Info Disclosure | Verbose error messages | 1.6 | MEDIUM | OPEN |

## 4. Detailed Threat Descriptions

### TM-001: JWT Algorithm Confusion

**STRIDE:** Spoofing
**Component:** Authentication service
**DREAD Score:** 2.4 (HIGH)

**Description:**
[Full threat description]

**Attack Scenario:**
[Step-by-step attack]

**Mitigation:**
[Specific fix with code example]

**Residual Risk:**
[After mitigation, what risk remains]

## 5. Attack Trees

[Attack trees for top 3 threats]

## 6. Mitigation Roadmap

### Immediate (Critical/High)
1. TM-XXX — [Fix] — Owner: Backend team — Effort: 2 hours

### Short-term (Medium)
1. TM-XXX — [Fix] — Owner: DevOps — Effort: 1 day

### Long-term (Low / Architecture)
1. TM-XXX — [Fix] — Owner: Architect — Effort: 1 sprint

## 7. Assumptions and Out of Scope

**Assumptions:**
- TLS is provided by infrastructure (not audited here)
- Physical security is assumed

**Out of Scope:**
- Client-side application security (separate review)
```

---

## Rules of Engagement

1. **Decompose before threatening** — understand the system before applying STRIDE.
2. **Every trust boundary crossing is a threat surface** — check each one.
3. **Apply relevant STRIDE categories per element** — evaluate STRIDE according to element type (Processes: S,T,R,I,D,E; Data Flows: T,I,D; Data Stores: T,I,D,R; External Entities: S,R) or STRIDE-per-interaction.
4. **DREAD scores are estimates** — calibrate with system owner knowledge.
5. **Attack trees for high/critical** — only build trees for highest-risk threats.
6. **Mitigations must be specific and bound to system configuration** — "add authentication" is not a mitigation; "verify JWT signatures allowing only the issuer's expected algorithm (e.g., `algorithms: ['RS256']` or `['ES256']`) and bind each key to exactly one algorithm per RFC 8725" is.
7. **Track threat status** — OPEN, MITIGATED, ACCEPTED, TRANSFERRED.
