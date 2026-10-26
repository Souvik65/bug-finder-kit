# PR Security Gate — Technical Reference & CI/CD Integration

## 1. GitHub Actions Automated PR Security Gate Workflow

Add this GitHub Actions workflow to `.github/workflows/pr-security-gate.yml` to automatically
scan pull requests on creation and update:

```yaml
name: PR Security Gate

on:
  pull_request:
    branches: [main, master, develop]
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write

jobs:
  security-gate:
    name: Security Diff Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run Secret Scanning on PR Diff
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          GITLEAKS_ENABLE_UPLOAD_ARTIFACT: false

      - name: Run Dependency Audit
        run: |
          if [ -f "package.json" ]; then
            npm audit --audit-level=high || echo "::warning file=package.json::High/Critical npm vulnerabilities found"
          fi
          if [ -f "requirements.txt" ]; then
            pip install pip-audit && pip-audit -r requirements.txt || echo "::warning file=requirements.txt::Vulnerabilities found in Python dependencies"
          fi

      - name: Analyze Git Diff for Dangerous Patterns
        run: |
          echo "Scanning diff against target branch..."
          DIFF=$(git diff origin/${{ github.base_ref }}...HEAD)
          
          # Check for disabled TLS
          if echo "$DIFF" | grep -E "NODE_TLS_REJECT_UNAUTHORIZED.*0|verify\s*=\s*False"; then
            echo "::error::PR contains disabled TLS verification!"
            exit 1
          fi

          # Check for raw SQL injection patterns
          if echo "$DIFF" | grep -E "execute\s*\(\s*f['\"].*\{|query\s*\(\s*\`SELECT.*\$\{"; then
            echo "::error::PR contains raw SQL string interpolation!"
            exit 1
          fi

          echo "Diff security scan passed successfully."
```

---

## 2. GitHub Branch Protection & Required Review Policies

To enforce security gates effectively in repository settings:

1. **Require pull request reviews before merging:**
   - Set **Required approving reviews** to at least 1 (or 2 for Tier 1 repositories).
   - Enable **Dismiss stale pull request approvals when new commits are pushed**.
   - Enable **Require review from Code Owners** (with `CODEOWNERS` mapping security-sensitive paths to `@security-team`).
2. **Require status checks to pass before merging:**
   - Require `security-gate` CI job.
   - Require SAST linter job.
   - Require SonarCloud / Snyk / Gitleaks checks.
3. **Require signed commits:**
   - Enforce GPG/SSH commit signature verification.

### CODEOWNERS Path Mapping Example
```
# .github/CODEOWNERS
# Require security team sign-off on sensitive directories:
/src/auth/              @security-team
/src/crypto/            @security-team
/src/middleware/auth*   @security-team
/.github/workflows/     @devops-leads @security-team
/prisma/migrations/     @dba-team @security-team
```

---

## 3. High-Risk vs Standard Change Categorization

```
                  ┌─────────────────────────────┐
                  │      Pull Request Diff      │
                  └──────────────┬──────────────┘
                                 │
           Does the PR touch auth, crypto, DB schemas,
                  or introduce new endpoints?
                                 │
                   ┌─────────────┴─────────────┐
                  YES                          NO
                   │                           │
                   ▼                           ▼
        ┌──────────────────────┐    ┌──────────────────────┐
        │    Tier 1 / Tier 2   │    │    Tier 3 / Tier 4   │
        │   High-Risk Gate     │    │   Standard Flow      │
        ├──────────────────────┤    ├──────────────────────┤
        │ • 2 approvals        │    │ • 1 peer approval    │
        │ • Security team tag  │    │ • Standard CI linter │
        │ • Threat check passed│    │ • Unit test pass     │
        │ • Manual auth review │    │                      │
        └──────────────────────┘    └──────────────────────┘
```

---

## 4. Developer Experience: Soft Warnings vs Hard Blockers

To avoid developer fatigue and maintain rapid development cycles:

| Category | Policy | Behavior in CI |
|---|---|---|
| **Hardcoded API Secrets** | Hard Blocker | CI Fails immediately (`exit 1`); merge button disabled |
| **Disabled TLS / Cert Checks** | Hard Blocker | CI Fails immediately (`exit 1`) |
| **Direct SQL Interpolation** | Hard Blocker | CI Fails immediately (`exit 1`) |
| **New API Route Missing Auth** | Hard Blocker | Requires security sign-off |
| **Missing Pagination Bounds** | Soft Warning | PR Comment posted with warning; non-blocking |
| **Dependency CVE (Moderate)** | Soft Warning | Informational comment with upgrade recommendation |
