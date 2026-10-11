---
name: secrets-scanner
description: >
  Hardcoded secrets, credentials, and sensitive value detection skill. Scans source
  code, config files, commit history, environment files, and CI/CD configurations for
  exposed API keys, passwords, tokens, private keys, connection strings, and other
  sensitive values. Activate when the user asks to "scan for secrets", "find hardcoded
  credentials", "check for exposed keys", "leaked tokens", or "secrets audit".
triggers:
  - "scan for secrets"
  - "find hardcoded credentials"
  - "check for exposed keys"
  - "leaked tokens"
  - "secrets audit"
  - "find passwords in code"
  - "credential scan"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# Secrets Scanner — Hardcoded Credentials & Sensitive Value Detector

> Systematically hunts for secrets, credentials, and sensitive values embedded in
> source code, config files, and commit history. Every finding is reported with
> location only — actual secret values are REDACTED to prevent re-exposure.

---

## ⚠️ Critical Rule: Redact All Found Secrets

**Never display actual secret values in output.** When a secret is found:
- Show the file path and line number
- Show the variable/key name
- Replace the value with `<REDACTED>`
- Example: `STRIPE_SECRET_KEY = "<REDACTED>"` at `config/stripe.js:14`

---

## Phase 1 — File System Scan

### High-Risk Files to Check First

```bash
# Configuration and environment files
find . -name "*.env" -o -name ".env.*" -o -name "*.env.local" 2>/dev/null
find . -name "config.json" -o -name "secrets.json" -o -name "credentials.json" 2>/dev/null
find . -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null
find . -name "*.keystore" -o -name "*.jks" 2>/dev/null
find . -name "*.htpasswd" -o -name ".htpasswd" 2>/dev/null
find . -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find . -name "kubeconfig" -o -name "kube_config" 2>/dev/null
find . -name "*.tfstate" -o -name "terraform.tfvars" 2>/dev/null
```

### Files That Should NOT Be Committed
Create a checklist — if any of these exist in the repo (not .gitignored), report them:

| File Pattern | Risk | Expected Location |
|---|---|---|
| `.env`, `.env.*` | HIGH | Should be in `.gitignore` |
| `*.pem`, `*.key` | CRITICAL | Should never be committed |
| `id_rsa`, `id_ed25519` | CRITICAL | Should never be committed |
| `*.tfstate` | HIGH | Contains resource secrets |
| `*.log` with auth tokens | MEDIUM | Should be .gitignored |
| `package-lock.json` with `_authToken` | MEDIUM | Check for npm auth tokens |

---

## Phase 2 — Pattern-Based Scanning

### Generic High-Entropy String Detection

Flag assignments where the value appears to be a secret (high entropy, suspicious variable name):

```bash
# Variable names that suggest secrets
grep -rn -i \
  -e "password\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "passwd\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "secret\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "api_key\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "apikey\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "access_token\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "auth_token\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "private_key\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  -e "client_secret\s*[=:]\s*['\"][^'\"]\{6,\}['\"]" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.go" \
  --include="*.java" --include="*.rb" --include="*.php" --include="*.cs" \
  --include="*.env" --include="*.yaml" --include="*.yml" --include="*.json" \
  --include="*.toml" --include="*.ini" --include="*.cfg" --include="*.conf" \
  . | awk -F: '{print $1 ":" $2 " [GENERIC_SECRET: REDACTED]"}'
```

### Service-Specific Token Patterns

| Service | Pattern | Example Prefix |
|---|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | 40-char base64 after `aws_secret_access_key` | — |
| GitHub Token | `gh[pousr]_[A-Za-z0-9]{36}` | `ghp_`, `ghs_`, `gho_` |
| GitHub PAT (new) | `github_pat_[A-Za-z0-9_]{82}` | — |
| Slack Bot Token | `xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}` | `xoxb-` |
| Slack Webhook | `hooks.slack.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | — |
| Stripe Secret | `sk_live_[A-Za-z0-9]{24,}` | `sk_live_` |
| Stripe Test Key | `sk_test_[A-Za-z0-9]{24,}` | `sk_test_` |
| SendGrid Key | `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}` | `SG.` |
| Twilio Account SID | `AC[a-z0-9]{32}` | `AC` |
| Twilio Auth Token | `[a-z0-9]{32}` after twilio auth token variable | — |
| Google API Key | `AIza[0-9A-Za-z_-]{35}` | `AIza` |
| Firebase API Key | `AIza[0-9A-Za-z_-]{35}` | — |
| Heroku API Key | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | — |
| Mailgun API Key | `key-[0-9a-zA-Z]{32}` | `key-` |
| npm Auth Token | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` | in `.npmrc` |
| Discord Webhook | `discord.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+` | — |
| Telegram Bot Token | `[0-9]{9}:AA[A-Za-z0-9_-]{33}` | — |

```bash
# Example scan commands (prints file and line with redacted tokens)
grep -rn "AKIA[0-9A-Z]\{16\}" . | awk -F: '{print $1 ":" $2 " [AWS_ACCESS_KEY: REDACTED]"}'
grep -rn "gh[pousr]_[A-Za-z0-9]\{36\}" . | awk -F: '{print $1 ":" $2 " [GITHUB_TOKEN: REDACTED]"}'
grep -rn "sk_live_[A-Za-z0-9]\{24,\}" . | awk -F: '{print $1 ":" $2 " [STRIPE_KEY: REDACTED]"}'
grep -rn "AIza[0-9A-Za-z_-]\{35\}" . | awk -F: '{print $1 ":" $2 " [GOOGLE_KEY: REDACTED]"}'
```

### Private Keys & Certificates
```bash
grep -rn -e "-----BEGIN.*PRIVATE KEY-----" .
grep -rn -e "-----BEGIN CERTIFICATE-----" .
grep -rn -e "-----BEGIN PGP" .
grep -rn -e "-----BEGIN RSA" .
grep -rn -e "-----BEGIN EC" .
grep -rn -e "-----BEGIN OPENSSH" .
```

### Connection Strings with Embedded Credentials
```bash
grep -rn "mongodb://[^@]\+@" .
grep -rn "postgresql://[^@]\+@\|postgres://[^@]\+@" .
grep -rn "mysql://[^@]\+@" .
grep -rn "redis://:[^@]*@" .
grep -rn "amqp://[^@]\+@" .
grep -rn "Server=[^;]\+;.*Password=[^;]\+" . --include="*.cs" --include="*.config" --include="*.xml"
```

### JWT Secrets
```bash
grep -rn -i "jwt.*secret\s*[=:]\s*['\"][^'\"]\+['\"]" .
grep -rn "JWT_SECRET\s*=\s*['\"][^'\"]\+['\"]" .
grep -rn "jwtSecret\s*=\s*['\"][^'\"]\+['\"]" .
# Also check for weak JWT secrets
grep -rn "jwt.*secret.*\"secret\"\|\"password\"\|\"123\|\"test\|\"dev" . -i
```

---

## Phase 3 — Git History Scan

Secrets deleted from current code may still live in git history.

### Scan all commits for secrets (without dumping secret plaintext into stdout)
```bash
# List all files ever committed (including deleted)
git log --all --full-history --format="" --name-only | sort -u

# Search git history for commits containing secret patterns (identifies commit hash without leaking secret values)
git log --all -G"AKIA[0-9A-Z]{16}" --oneline
git log --all -G"gh[pousr]_[A-Za-z0-9]{36}" --oneline
git log --all -G"sk_live_[A-Za-z0-9]{24,}" --oneline

# Check if sensitive files were ever committed
git log --all --full-history --name-only -- "**/.env" "**/*.pem" "**/*.key" "**/id_rsa" \
    "**/secrets.json" "**/credentials.json"
```

### If secrets found in git history
Report:
1. The commit hash where the secret was introduced
2. The file and approximate line
3. Whether the secret is still present in HEAD
4. **Remediation required:** rotate the secret immediately + git history rewrite

---

## Phase 4 — CI/CD & Config File Scan

### GitHub Actions
```bash
# Check for secrets hardcoded in workflow files
grep -rn "password\|secret\|token\|key\s*=" .github/workflows/ -i
# Check for 3rd party actions not pinned to commit hash
grep -rn "uses: [^@]\+@[^a-f0-9]" .github/workflows/
```

### Docker
```bash
# Check Dockerfile for hardcoded secrets
grep -rn "ENV.*PASSWORD\|ENV.*SECRET\|ENV.*TOKEN\|ENV.*KEY" Dockerfile* docker-compose*
grep -rn "ARG.*PASSWORD\|ARG.*SECRET\|ARG.*TOKEN" Dockerfile*
# Check for secrets baked into image layers (using RUN commands)
grep -rn "RUN.*password\|RUN.*secret\|RUN.*token" Dockerfile* -i
```

### Kubernetes
```bash
# Check for plaintext secrets in manifests
grep -rn "kind: Secret" . --include="*.yaml" --include="*.yml" -A 10 | grep -v "secretKeyRef\|valueFrom"
# Base64 isn't encryption — flag all base64-encoded values in Secret manifests
grep -rn "kind: Secret" . --include="*.yaml" --include="*.yml"
```

### Terraform
```bash
# Sensitive values in tfvars
grep -rn "password\|secret\|private_key\|access_key" . --include="*.tfvars" --include="*.tf" -i
# Check tfstate for embedded credentials
grep -rn "password\|secret" . --include="*.tfstate" -i
```

---

## Phase 5 — .gitignore & Tracked File Audit

Verify effective git ignore rules using `git check-ignore` (avoid naive grep, which matches comments and partial names like `.env.example`), and ensure sensitive files aren't tracked in index:

```bash
# Test representative sensitive paths against effective git ignore rules
SENSITIVE_PATHS=(
    ".env"
    ".env.local"
    ".env.production"
    "server.key"
    "cert.pem"
    "id_rsa"
    "id_ed25519"
    "terraform.tfstate"
    "secrets.json"
    "credentials.json"
)

for path in "${SENSITIVE_PATHS[@]}"; do
    if ! git check-ignore -q "$path" 2>/dev/null; then
        echo "WARNING: Sensitive path '$path' is NOT effectively ignored by git!"
    fi
done

# Check if any sensitive files are ALREADY tracked in git index
echo "Checking git index for tracked secrets..."
git ls-files | grep -iE '(\.env(\.[a-z0-9]+)?$|\.pem$|\.key$|id_rsa|id_ed25519|\.tfstate$|credentials\.json$|secrets\.json$)' && \
    echo "CRITICAL: Sensitive files are actively tracked in the git index!" || \
    echo "✓ No obvious sensitive files tracked in git index"
```

---

## Output Format

### Finding Template

```
## SS-[NNN]: [Secret Type] Exposed

**Severity:** CRITICAL | HIGH | MEDIUM
**Type:** API Key | Password | Private Key | Connection String | Token
**Service:** [AWS / GitHub / Stripe / Generic / Unknown]

### Location
- **File:** `path/to/file.ext`
- **Line:** XX
- **Context:** `VARIABLE_NAME = "<REDACTED>"`

### In Git History
- **Present in HEAD:** Yes / No
- **Earliest commit:** [commit hash] on [date]
- **Still accessible:** Yes / No

### Risk
[One sentence: what can an attacker do with this secret]

### Immediate Actions Required
1. **Rotate the secret now** — assume it is already compromised
2. [Service-specific rotation steps]
3. Remove from code and use environment variable / secret store
4. If in git history: rewrite history or make the repo private immediately
```

### Summary Table

```
| ID | Secret Type | File | Line | In History | Severity |
|---|---|---|---|---|---|
| SS-001 | AWS Access Key | src/config.js | 14 | Yes (3 commits) | CRITICAL |
| SS-002 | JWT Secret (weak) | app.js | 7 | No | HIGH |
```

---

## Remediation Reference

### Safe Secret Management Patterns

```bash
# Environment variables (minimum viable)
export DATABASE_URL="postgresql://user:pass@host/db"
# In code: process.env.DATABASE_URL / os.environ["DATABASE_URL"]

# .env file (local dev only, gitignored)
# Use: dotenv (Node), python-dotenv, godotenv

# Secret stores (production)
# - AWS Secrets Manager / Parameter Store
# - HashiCorp Vault
# - Azure Key Vault
# - GCP Secret Manager
# - GitHub Actions secrets / environment secrets
```

### Post-Discovery Checklist

- [ ] Secret rotated in the service provider dashboard
- [ ] New secret stored in environment variable or secret store
- [ ] Code updated to read from environment (not hardcoded)
- [ ] If in git history: repository made private + history rewritten or key revoked permanently
- [ ] Audit access logs of the exposed service for unauthorized use
- [ ] .gitignore updated to prevent future accidental commits

---

## Rules of Engagement

1. **REDACT ALL VALUES** — never output the actual secret in any finding.
2. **Rotation first** — always recommend immediate rotation before any other action.
3. **Assume compromised** — any secret found in a repo (even private) should be considered exposed.
4. **Check git history** — a deleted secret is not safe; history must be checked.
5. **False negatives are dangerous** — when in doubt, flag it and let the user decide.
6. **Report location precisely** — file + line + variable name is sufficient without the value.
