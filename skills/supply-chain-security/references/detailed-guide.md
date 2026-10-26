# Supply Chain Security — Detailed Reference Guide

## Understanding the Threat Landscape

### The SolarWinds Pattern
The 2020 SolarWinds attack is the canonical supply chain compromise: attackers
inserted malicious code into the build pipeline *after* developers committed
clean code. The compiled artifact was compromised, not the source. This is why
source code scanning alone is insufficient.

### The npm Ecosystem Attacks
- **event-stream (2018):** Malicious maintainer added cryptomining code to a
  widely-used npm package serving millions of projects.
- **ua-parser-js (2021):** Maintainer account hijacked; malware injected into
  three consecutive versions before detection.
- **node-ipc (2022):** Maintainer intentionally introduced destructive payload
  as protest.

### The PyPI Typosquatting Pattern
Attackers register packages such as `colourama` (vs `colorama`), `djago` (vs
`django`), `python-dateutil2` (vs `python-dateutil`). These packages execute
malware on install via `setup.py`.

---

## SBOM Deep Dive

### SPDX vs CycloneDX

| Feature | SPDX 2.3 | CycloneDX 1.5 |
|---|---|---|
| Primary use | License compliance | Security / vulnerability mgmt |
| Format | Tag-value, RDF, JSON | JSON, XML |
| Tooling | FOSSA, FOSSology | Dependency-Track, OWASP |
| NTIA minimum | ✅ | ✅ |
| VEX support | Partial | Full (CycloneDX VEX) |
| Recommended for security | Secondary | **Primary** |

### Attaching SBOM to GitHub Release

```yaml
# .github/workflows/release.yml
- name: Generate SBOM
  uses: anchore/sbom-action@<SHA>
  with:
    format: spdx-json
    output-file: sbom.spdx.json

- name: Attach SBOM to release
  uses: softprops/action-gh-release@<SHA>
  with:
    files: sbom.spdx.json
```

### Continuous SBOM Monitoring with Dependency-Track

Dependency-Track ingests SBOM files and provides:
- Continuous CVE monitoring against uploaded SBOMs
- Policy engine (block deploy if critical vuln found)
- VEX (Vulnerability Exploitability eXchange) support
- SBOM diff between versions

---

## Typosquatting Defences

### Automated Detection Tools

```bash
# pip: DepScan (formerly known as dep-scan)
pip install appthreat-depscan
depscan --src ./ --reports-dir reports/

# npm: Socket Security
npm install -g @socket/cli
socket check package.json

# All ecosystems: Phylum
phylum analyze package-lock.json

# OSS Index (free)
ossindex audit
```

### Internal Name Reservation

For organisations with private packages:
1. **Reserve the name on public registries** even if never published publicly.
   This blocks attackers from claiming `@mycompany/utils` on npm.
2. **Publish a honeypot package** that alerts on install (canary token inside
   `postinstall` script that fires an HTTP request to your monitoring).

---

## Lock-File Security Automation

### Pre-commit Hook: Lock-File Drift Detection

```bash
# .git/hooks/pre-commit
#!/bin/bash
if git diff --cached --name-only | grep -q "package.json\|requirements.in"; then
  if ! git diff --cached --name-only | grep -q "package-lock.json\|requirements.txt"; then
    echo "❌ Manifest changed but lock file not updated. Run npm install or pip-compile."
    exit 1
  fi
fi
```

### CI: Enforce Lock-File Install

```yaml
# GitHub Actions
- name: Install dependencies (locked)
  run: npm ci   # Fails if package-lock.json is out of sync

# Python equivalent
- run: pip install --require-hashes -r requirements.txt
```

### Dependabot for Automated Lock-File Updates

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
```

---

## CI/CD Poisoning: Deep Dive

### The `pull_request_target` Trap

`pull_request_target` runs in the context of the *base* branch (with secrets
access) but checks out the *PR branch* code. If the workflow file itself uses
`actions/checkout` with the PR ref and then runs that code, an attacker can
read all secrets.

```yaml
# VULNERABLE
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # attacker code
      - run: npm install && npm test  # attacker's package.json runs postinstall
```

```yaml
# SAFER — check out PR code but run only trusted code for privileged steps
on:
  pull_request_target:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<SHA>   # checkout base branch (trusted)
      - uses: actions/checkout@<SHA>   # checkout PR separately
        with:
          path: pr-code
          ref: ${{ github.event.pull_request.head.sha }}
      # Run static analysis on pr-code/ only, don't execute it
```

### GITHUB_TOKEN Minimum Permissions

```yaml
# Set at workflow level (default deny)
permissions:
  contents: read    # read source only

jobs:
  build:
    permissions:
      contents: read
      packages: write   # only the job that needs to publish
```

### OpenSSF Scorecard

Automate supply chain security scoring:

```yaml
# .github/workflows/scorecard.yml
on:
  schedule:
    - cron: '30 1 * * 6'

jobs:
  analysis:
    uses: ossf/scorecard-action@<SHA>
    with:
      results_file: results.sarif
      results_format: sarif
      publish_results: true
    permissions:
      id-token: write
      contents: read
      actions: read
      security-events: write
```

Scorecard checks include:
- Pinned dependencies (CI actions, Dockerfiles)
- Code review requirements
- Branch protection rules
- Vulnerability disclosure policy
- Token permissions
- Dangerous workflow patterns

---

## SLSA Level Progression

### Achieving SLSA Level 2 (Recommended Minimum)

1. Generate provenance using `slsa-github-generator`
2. Sign provenance with Sigstore (automatic in GitHub Actions)
3. Attach provenance to GitHub release
4. Add verification step to deployment workflow

```yaml
# Verification in deployment
- name: Verify SLSA provenance
  uses: slsa-framework/slsa-verifier/actions/installer@<SHA>
- run: |
    slsa-verifier verify-artifact artifact.tar.gz \
      --provenance-path artifact.tar.gz.intoto.jsonl \
      --source-uri github.com/org/repo \
      --source-tag v1.0.0
```

### SLSA Level 3: Isolated Build Environments

Use ephemeral, isolated build environments:
- GitHub-hosted runners (already ephemeral)
- Google Cloud Build with Cloud Build Service Account
- Tekton Chains for Kubernetes-native builds

---

## Checklist Summary

### SBOM
- [ ] SBOM generated at build time (not hand-maintained)
- [ ] Includes all transitive dependencies
- [ ] Uses PURL identifiers
- [ ] Includes hash/integrity for each component
- [ ] SBOM signed and attached to release

### Typosquatting
- [ ] New dependencies reviewed before addition
- [ ] Automated scanner in CI (Socket, Phylum, or OSS Index)
- [ ] Internal package names reserved on public registries
- [ ] Private registry scopes pinned in `.npmrc` / `pip.conf`

### Lock-File Integrity
- [ ] Lock file committed and not gitignored
- [ ] CI uses `npm ci` / `pip install --require-hashes`
- [ ] Lock file changes reviewed in PRs
- [ ] Automated update tool (Dependabot/Renovate) configured

### CI/CD Pipeline
- [ ] All GitHub Actions pinned to full SHA
- [ ] `pull_request_target` usage reviewed
- [ ] GITHUB_TOKEN permissions minimized
- [ ] No secrets in run step environment variables that get echoed
- [ ] Self-hosted runners are ephemeral
- [ ] OpenSSF Scorecard running in CI

### Provenance
- [ ] SLSA level documented
- [ ] Provenance generated in CI
- [ ] Provenance attached to releases
- [ ] Container images signed with cosign
- [ ] npm packages published with `--provenance`
