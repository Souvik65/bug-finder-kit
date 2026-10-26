# supply-chain-security

> Software supply chain security review skill for the **bug-finder-kit**.
> Audits SBOM completeness, detects typosquatting & dependency confusion,
> verifies lock-file integrity, identifies CI/CD pipeline poisoning vectors,
> and validates artifact provenance.

---

## What This Skill Does

While `dependency-audit` checks *known-vulnerable package versions*,
`supply-chain-security` checks *how attackers get malicious code in* —
through typosquatting, pipeline injection, and provenance gaps.

| Area | What is reviewed |
|---|---|
| **SBOM** | Generation, completeness, signing, and distribution |
| **Typosquatting** | Look-alike package names, compromised maintainer accounts |
| **Dependency Confusion** | Internal packages leaking to public registries |
| **Lock-File Integrity** | Drift detection, hash pinning, CI enforcement |
| **CI/CD Poisoning** | Workflow injection, unpinned actions, `pull_request_target` misuse |
| **Provenance** | SLSA compliance, Sigstore / cosign, npm `--provenance` |

---

## Trigger Phrases

This skill activates on:
- `"supply chain security"`, `"check supply chain"`
- `"SBOM"`, `"software bill of materials"`
- `"typosquatting"`, `"dependency confusion"`
- `"lock-file integrity"`, `"pinned dependencies"`
- `"CI/CD poisoning"`, `"build pipeline security"`
- `"artifact provenance"`, `"SLSA compliance"`, `"sigstore"`

---

## Quick Usage

```
Review our supply chain security posture — focus on CI/CD pipeline risks.
```

```
Check our package.json and .github/workflows for dependency confusion and
unpinned actions.
```

```
We need SLSA Level 2 compliance. What do we need to do?
```

---

## Coverage Map

```
dependency-audit   → Are packages known-vulnerable? (CVE scanning)
supply-chain-security → How does malicious code enter in the first place?
                        ├── SBOM (what we have)
                        ├── Typosquatting (malicious look-alikes)
                        ├── Dependency confusion (public vs private)
                        ├── Lock-file tampering
                        ├── CI/CD pipeline injection
                        └── Artifact provenance (SLSA, Sigstore)
```

---

## Files

```
supply-chain-security/
├── SKILL.md              — Main skill (phases 1-6, all checks)
├── README.md             — This file
└── references/
    └── detailed-guide.md — Deep dives: SBOM formats, SLSA levels,
                            real-world attack case studies, checklists
```

---

## Installation

This skill lives in the `bug-finder-kit` repository at:
```
skills/supply-chain-security/
```

It is automatically available when bug-finder-kit is loaded as a skills provider.

---

## Author

`bug-finder-kit` — v1.0.0 — 2026-10-21
