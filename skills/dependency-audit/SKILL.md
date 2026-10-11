---
name: dependency-audit
description: >
  Supply chain and dependency vulnerability audit skill. Analyzes package manifests,
  lockfiles, and installed dependencies across npm, pip, cargo, go.mod, maven, gem,
  and composer for known CVEs, malicious packages, dependency confusion risks, and
  license compliance issues. Activate when the user asks to "audit dependencies",
  "check for vulnerable packages", "supply chain audit", "npm audit", "dependency CVE scan".
triggers:
  - "audit dependencies"
  - "check for vulnerable packages"
  - "supply chain audit"
  - "npm audit"
  - "dependency CVE"
  - "check packages"
  - "vulnerable dependencies"
  - "outdated packages"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# Dependency Audit — Supply Chain & Vulnerability Analysis

> Comprehensive analysis of project dependencies for known vulnerabilities, supply
> chain attack vectors, dependency confusion risks, and outdated packages.
> Covers all major package ecosystems and their security posture.

---

## Phase 1 — Ecosystem Detection

Identify all package managers and dependency files in the project:

```bash
# Detect package managers
ls package.json yarn.lock pnpm-lock.yaml package-lock.json 2>/dev/null  # Node.js
ls requirements.txt requirements/*.txt Pipfile Pipfile.lock pyproject.toml 2>/dev/null  # Python
ls go.mod go.sum 2>/dev/null  # Go
ls pom.xml build.gradle build.gradle.kts 2>/dev/null  # Java
ls Gemfile Gemfile.lock 2>/dev/null  # Ruby
ls composer.json composer.lock 2>/dev/null  # PHP
ls Cargo.toml Cargo.lock 2>/dev/null  # Rust
ls *.csproj packages.config nuget.config 2>/dev/null  # .NET
```

Build a dependency inventory:
| Ecosystem | Files Found | Total Packages | Direct | Transitive |
|---|---|---|---|---|

---

## Phase 2 — Automated Vulnerability Scan

Run the appropriate audit tool for each detected ecosystem:

### JavaScript / TypeScript (npm, yarn, pnpm)
```bash
# npm
npm audit --json 2>/dev/null | tee npm-audit-results.json

# yarn v1
yarn audit --json 2>/dev/null | tee yarn-audit-results.json

# yarn v2/v3
yarn npm audit --json 2>/dev/null | tee yarn-audit-results.json

# pnpm
pnpm audit --json 2>/dev/null | tee pnpm-audit-results.json

# Parse results: look for severity >= HIGH
```

### Python (pip, pipenv, poetry)
```bash
# pip-audit (recommended)
pip-audit --json 2>/dev/null | tee pip-audit-results.json

# safety (requires API key for full DB)
safety check --json 2>/dev/null | tee safety-results.json

# If tools unavailable, check requirements.txt against known vulnerability patterns manually
```

### Go
```bash
# govulncheck (official Go vulnerability checker)
govulncheck ./... 2>/dev/null | tee govulncheck-results.txt

# Nancy (for go.sum)
cat go.sum | nancy sleuth 2>/dev/null | tee nancy-results.txt
```

### Java (Maven, Gradle)
```bash
# OWASP Dependency Check (Maven)
mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7 2>/dev/null

# Gradle
./gradlew dependencyCheckAnalyze 2>/dev/null
```

### Ruby (Bundler)
```bash
bundle-audit update && bundle-audit check 2>/dev/null | tee bundler-audit-results.txt
```

### PHP (Composer)
```bash
composer audit 2>/dev/null | tee composer-audit-results.txt
```

### Rust (Cargo)
```bash
cargo audit 2>/dev/null | tee cargo-audit-results.txt
```

### .NET (NuGet)
```bash
dotnet list package --vulnerable 2>/dev/null | tee nuget-audit-results.txt
```

---

## Phase 3 — Lockfile Analysis

### Missing Lockfile Check

A missing lockfile is a security risk:

| Missing File | Risk | Impact |
|---|---|---|
| `package-lock.json` or `yarn.lock` | HIGH | Floating versions, reproducibility loss |
| `Pipfile.lock` or `poetry.lock` | HIGH | Different packages installed per environment |
| `go.sum` | MEDIUM | Module integrity not enforced |
| `Cargo.lock` (for binaries) | MEDIUM | Non-reproducible builds |
| `Gemfile.lock` | HIGH | Different gem versions per install |

### Lockfile Integrity
```bash
# Check if lockfile is out of sync with manifest
npm ci --dry-run 2>&1 | grep -i "error\|warn"   # npm
yarn install --frozen-lockfile 2>&1 | grep -i "error"  # yarn
pip-sync requirements.txt --dry-run 2>&1   # pip-tools

# Check if lockfile exists and is tracked in git index
git ls-files | grep -iE "(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)" || \
    echo "WARNING: No dependency lockfile is tracked in git repository!"
```

### Floating Version Detection

Flag wildcard or overly permissive version ranges:

```bash
# JavaScript — dangerous version specifiers
grep -E '"[^"]+": "\*"\|"[^"]+": ">=0\|"[^"]+": "latest"' package.json

# Python — missing version pins
grep -E "^[a-zA-Z]+=*$\|^[a-zA-Z]+=*>=" requirements.txt | grep -v "=="

# Check for ^ (major) and ~ (minor) ranges that allow unexpected upgrades
grep -E '"[^"]+": "\^[0-9]\|"[^"]+": "~[0-9]"' package.json
```

---

## Phase 4 — Dependency Confusion Attack Surface

Dependency confusion attacks occur when an attacker publishes a malicious package
to a public registry with the same name as an internal package.

### Internal Package Detection
```bash
# Check for private registry configuration
cat .npmrc 2>/dev/null | grep "registry\|scope"
cat pip.conf ~/.pip/pip.conf 2>/dev/null | grep "index-url\|extra-index-url"
cat ~/.config/pip/pip.conf 2>/dev/null | grep "index-url"

# List scoped packages (potential internal packages)
grep -E '"@[^/]+/[^"]+": ' package.json

# Check if internal packages exist on public registry
# (manual step — search npmjs.com for package names)
```

### Risk Factors
| Risk Factor | Check |
|---|---|
| Internal packages with generic names | Search public registry for the name |
| No `--registry` flag in install scripts | Scripts that use default public registry |
| Both public and private registry configured | Dependency resolution order matters |
| `always-auth=true` not set for private scope | Auth required for private packages |

---

## Phase 5 — Package Integrity Verification

### Checksum Verification
```bash
# npm — check package integrity
npm install --ignore-scripts  # avoid malicious postinstall scripts
cat package-lock.json | grep '"integrity"' | head -20   # verify hashes present

# pip — check hash verification
pip install --require-hashes -r requirements.txt  # requires hash in requirements.txt
# Example: package==1.0.0 --hash=sha256:abc123...

# Cargo — verify checksums
cargo verify-project  # checks Cargo.lock checksums
```

### Suspicious Package Patterns
Flag packages that exhibit these behaviors:

```bash
# Check for postinstall/preinstall scripts (potential malware vector)
cat package.json | grep -A 5 '"scripts"' | grep -E "postinstall|preinstall|install"

# Check what node_modules/PACKAGE/package.json scripts do
ls node_modules/*/package.json | xargs grep -l "postinstall\|preinstall" 2>/dev/null
```

---

## Phase 6 — Outdated & EOL Package Detection

### Version Currency Check
```bash
# npm — check outdated
npm outdated --json 2>/dev/null

# pip
pip list --outdated --format json 2>/dev/null

# Cargo
cargo outdated 2>/dev/null

# Ruby
bundle outdated 2>/dev/null
```

### End-of-Life Runtime Detection
Check if the runtime/language version itself is EOL against official lifecycles:

| Runtime | Official Lifecycle / Status | Minimum Supported Version |
|---|---|---|
| **Node.js** | Supported active/maintenance LTS schedule | `>= 20.x` (18.x reached EOL April 2025) |
| **Python** | Official CPython release lifecycle | `>= 3.10` (3.8 EOL Oct 2024, 3.9 EOL Oct 2025) |
| **Java** | Active OpenJDK LTS releases | `17` or `21` (8 and 11 past standard public OSS support) |
| **Ruby** | Official Ruby maintenance branches | `>= 3.2` (3.0 EOL April 2024, 3.1 EOL March 2025) |
| **PHP** | Official PHP release lifecycle | `>= 8.2` (8.0 EOL Nov 2023, 8.1 EOL Dec 2025) |

```bash
node --version && echo "Check: https://endoflife.date/nodejs"
python --version && echo "Check: https://endoflife.date/python"
java -version 2>&1 && echo "Check: https://endoflife.date/java"
ruby --version && echo "Check: https://endoflife.date/ruby"
php --version && echo "Check: https://endoflife.date/php"
```

---

## Phase 7 — License Compliance (Optional)

Identify packages with potentially problematic licenses:

```bash
# npm
npx license-checker --summary 2>/dev/null
npx license-checker --onlyAllow "MIT;ISC;BSD-2-Clause;BSD-3-Clause;Apache-2.0" 2>/dev/null

# Python
pip-licenses --format=json 2>/dev/null

# Go
go-licenses report ./... 2>/dev/null
```

### License Risk Levels
| License | Risk | Note |
|---|---|---|
| MIT, ISC, BSD, Apache 2.0 | Low | Permissive |
| LGPL v2/v3 | Medium | Copyleft — requires attribution |
| GPL v2/v3 | High | Copyleft — may require source disclosure |
| AGPL | HIGH | Network copyleft — strongest obligation |
| Commercial / Proprietary | Review | Check terms carefully |
| Unknown / Unlicensed | HIGH | No permission to use |

---

## Output Format

### Vulnerability Findings

```
## [SEVERITY] DA-[NNN]: [Package Name] @ [Version] — [CVE ID]

**Ecosystem:** npm | pip | cargo | go | maven | gem
**Package:** `package-name@1.2.3`
**CVE:** CVE-YYYY-XXXXX
**CVSS Score:** X.X ([CRITICAL/HIGH/MEDIUM/LOW])
**Direct/Transitive:** [Direct dependency OR transitive via package-chain]

### Vulnerability Description
[One paragraph: what the vulnerability is and how it can be triggered]

### Exploitation Context
- Is this package used in: frontend | backend | build-only | test-only?
- Attack surface: Is the vulnerable code path reachable from untrusted input?

### Remediation
- **Update to:** `package-name@X.Y.Z` (patched version)
- **Command:** `npm install package-name@X.Y.Z` / `pip install package-name==X.Y.Z`
- **If no patch available:** [workaround or alternative package]
- **Breaking changes:** [Yes/No — review changelog]

### References
- https://nvd.nist.gov/vuln/detail/CVE-YYYY-XXXXX
- [Package advisory URL]
```

### Summary Dashboard

```
## Dependency Audit Summary

**Project:** [name]  **Date:** YYYY-MM-DD  **Ecosystems:** npm, pip

### Vulnerability Overview
| Severity | Count | Patched Available |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 2 | 2 |
| MEDIUM | 5 | 3 |
| LOW | 8 | 6 |

### Top Priorities
1. [Package] @ [version] — CVE-XXXX-XXXX — CRITICAL — Update to [version]
2. ...

### Supply Chain Risks
- [X] Lockfile present and up-to-date
- [ ] Floating version ranges detected in package.json: [list]
- [ ] Dependency confusion risk: [list of internal-seeming packages]

### Outdated Packages (Security-Relevant)
| Package | Current | Latest | Versions Behind | Risk |
|---|---|---|---|---|
```

---

## Remediation Priority Guide

| Priority | Action |
|---|---|
| **Immediate** | CRITICAL CVEs with network-reachable exploit paths |
| **This sprint** | HIGH CVEs; any CVE in direct dependencies with patch available |
| **Next sprint** | MEDIUM CVEs; transitive-only HIGH CVEs |
| **Backlog** | LOW CVEs; outdated but no CVE; license issues |
| **Monitor** | No patch available — track for new releases |

---

## Rules of Engagement

1. **Triage by reachability** — a CVE in a build-only tool is lower priority than one in a runtime dependency.
2. **Check for patches first** — do not recommend removing a package if a patched version exists.
3. **Document breaking changes** — major version upgrades may require code changes.
4. **Test after updates** — recommend running the test suite after any dependency change.
5. **Don't ignore transitive** — attackers exploit transitive dependencies too.
6. **No version pinning to vulnerable** — `package@1.2.3` pinned to a vulnerable version is worse than a range.
