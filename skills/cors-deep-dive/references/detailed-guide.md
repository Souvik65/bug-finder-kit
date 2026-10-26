# CORS Deep-Dive — Technical Reference

## 1. CORS Browser Enforcement Model

The browser enforces CORS on the **response** side, not the request side.
This is a frequently misunderstood distinction:

- The **request** is always sent, regardless of CORS (cookies, credentials included).
- The **response** is blocked by the browser if CORS headers are absent or incorrect.
- **The server processes the request before the browser can block anything.**

This means:
1. A CORS misconfiguration on a DELETE endpoint can be exploited even if the attacker never reads the response — the state change happens server-side before the browser enforces CORS.
2. Reading responses requires both a permissive ACAO header AND `ACAC: true` for credentialed requests.

---

## 2. CORS and SameSite Cookies Interaction

Modern browsers default to `SameSite=Lax` for cookies without an explicit `SameSite` attribute. Understanding this interaction is critical:

| Cookie SameSite | Cross-origin fetch() with credentials: 'include' | CORS credentials leak possible? |
|---|---|---|
| `Strict` | Cookie NOT sent | ✅ No — SameSite blocks cookies |
| `Lax` | Cookie NOT sent via fetch/XHR | ✅ No — fetch is a non-top-level navigation |
| `None; Secure` | Cookie IS sent | ❌ Yes — if CORS is misconfigured |
| (no attribute, legacy) | Browser-dependent | ⚠️ Risk if browser defaulted to None |

**Key takeaway:** `SameSite=Lax` or `Strict` cookies defend against CORS credential attacks even if CORS headers are misconfigured. However, relying solely on SameSite without fixing CORS is fragile — always fix both.

---

## 3. Framework-Specific CORS Secure Configurations

### Express.js (Node.js) — cors middleware
```javascript
const cors = require('cors');

const ALLOWED_ORIGINS = [
    'https://app.example.com',
    'https://admin.example.com'
];

app.use(cors({
    origin: (origin, callback) => {
        // Allow server-to-server (no origin) and allowlisted browser origins
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, origin || false);
        } else {
            callback(new Error('CORS: Origin not permitted'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
    maxAge: 300 // Cache preflight for 5 minutes only
}));
```

### Django (Python) — django-cors-headers
```python
# settings.py
CORS_ALLOWED_ORIGINS = [
    "https://app.example.com",
    "https://admin.example.com",
]

CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = False        # Never set to True with credentials
CORS_URLS_REGEX = r'^/api/.*$'        # Limit CORS to API routes only
CORS_PREFLIGHT_MAX_AGE = 300          # 5 minutes max-age

# Headers to expose to the browser (default: none)
CORS_EXPOSE_HEADERS = ['X-Request-ID', 'X-Rate-Limit-Remaining']
```

### Spring Boot (Java) — @CrossOrigin and WebMvcConfigurer
```java
// Global CORS configuration — prefer this over @CrossOrigin annotations
@Configuration
public class CorsConfig implements WebMvcConfigurer {

    private static final List<String> ALLOWED_ORIGINS = List.of(
        "https://app.example.com",
        "https://admin.example.com"
    );

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins(ALLOWED_ORIGINS.toArray(new String[0]))
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("Content-Type", "Authorization", "X-Request-ID")
            .allowCredentials(true)
            .maxAge(300);
    }
}
```

---

## 4. Testing CORS with Burp Suite

1. **Intercept** a credentialed request to a sensitive endpoint.
2. In Burp Repeater, add or modify the `Origin` header:
   - `Origin: https://evil.com`
   - `Origin: null`
   - `Origin: https://example.com.evil.com`
3. Check the response for `Access-Control-Allow-Origin` echoing your value.
4. If reflected: add `Access-Control-Allow-Credentials: true` confirmation test.
5. **Craft PoC** using the fetch() template in Phase 2.

---

## 5. CORS Vulnerability Scanning (Automated)

```bash
# CORStest (Python tool)
pip install corstest
corstest https://api.example.com/user/profile -s victim_session_cookie

# corsy (Python CORS scanner)
python3 corsy.py -u https://api.example.com -t 10 --headers "Cookie: session=abc"

# cors-scanner (Nuclei template)
nuclei -u https://api.example.com -t ~/nuclei-templates/vulnerabilities/cors/
```
