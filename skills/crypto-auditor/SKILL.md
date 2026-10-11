---
name: crypto-auditor
description: >
  Cryptography misuse and weakness detector for codebases. Identifies weak algorithms,
  improper key management, insecure random number generation, broken encryption modes,
  padding oracle vulnerabilities, hash-length extension attack vectors, and timing
  side-channels. Covers Python, JavaScript/TypeScript, Java, Go, C/C++, and .NET.
  Activate when the user asks to "audit cryptography", "check crypto", "weak encryption",
  "insecure random", "hash audit", "crypto review", or "timing attacks".
triggers:
  - "audit cryptography"
  - "check crypto"
  - "weak encryption"
  - "insecure random"
  - "hash audit"
  - "crypto review"
  - "timing attacks"
  - "encryption weakness"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
---

# Crypto Auditor — Cryptography Misuse & Weakness Detector

> Identifies cryptographic weaknesses, misuse of primitives, and implementation
> errors that undermine the security guarantees of encryption, hashing, and
> random number generation across all common programming languages.

---

## The Cryptography Hierarchy

```
NEVER use:     MD5, SHA1, DES, RC4, ECB mode, static IV, Math.random()
AVOID:         SHA-256 for passwords, RSA-1024, RSAES-PKCS1-v1_5 (for encryption; RSASSA-PKCS1-v1_5 signatures like RS256 are acceptable if algorithm is verified), CBC without MAC, secret-prefix hashes H(key||msg)
ACCEPTABLE:    AES-128-GCM, RSA-2048 (with OAEP for encryption, PSS/PKCS1 for signatures), ECDH P-256, PBKDF2-SHA256
RECOMMENDED:   AES-256-GCM, RSA-4096, X25519, PBKDF2-SHA512, argon2id, Ed25519, HMAC-SHA256
```

---

## Phase 1 — Weak Hash Algorithm Detection

### Pattern Scan

```bash
# Weak hash algorithms in code
grep -rn "md5\|MD5\|sha1\b\|SHA1\b\|sha-1\|SHA-1" \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" \
    --include="*.c" --include="*.cpp" --include="*.cs" --include="*.rb" --include="*.php" .

# Python hashlib
grep -rn "hashlib\.md5\|hashlib\.sha1\|hashlib\.new\s*(\s*['\"]md5\|hashlib\.new\s*(\s*['\"]sha1" \
    --include="*.py" .

# JavaScript
grep -rn "createHash\s*(\s*['\"]md5\|createHash\s*(\s*['\"]sha1" --include="*.js" --include="*.ts" .

# Java
grep -rn "MessageDigest\.getInstance\s*(\s*['\"]MD5\|MessageDigest\.getInstance\s*(\s*['\"]SHA-1" \
    --include="*.java" .

# Go
grep -rn "md5\.New\|md5\.Sum\|sha1\.New\|sha1\.Sum" --include="*.go" .
```

### Context-Based Assessment

| Use Case | MD5 / SHA1 | Severity |
|---|---|---|
| Password hashing | Never acceptable | CRITICAL |
| Digital signature | Never acceptable | CRITICAL |
| Security token generation | Never acceptable | CRITICAL |
| File integrity (non-security) | Acceptable with caveats | LOW |
| Non-security checksums | Acceptable | INFO |

### Hash Length Extension Vulnerabilities (Secret-Prefix MAC)

> **CWE-327 / CWE-328**: Hash functions based on the Merkle-Damgård construction (MD5, SHA-1, SHA-256, SHA-512) are susceptible to **hash length extension attacks** when used to authenticate data via simple secret-prefix concatenation (`H(secret || message)`). An attacker who intercepts `message` and its hash `H(secret || message)` can append arbitrary data and calculate the valid hash of `message || padding || extension` without knowing `secret`.

**Vulnerable pattern (Secret-Prefix MAC):**
```python
# ✗ VULNERABLE: Secret-prefix MAC allows length extension attack
tag = hashlib.sha256(secret_key + user_data).hexdigest()
```
```javascript
// ✗ VULNERABLE: Naive secret concatenation into hash
const tag = crypto.createHash("sha256").update(secret + data).digest("hex");
```

**How to scan:**
```bash
# Search for secret concatenation directly into hash calls
grep -rn "hashlib\.\(sha256\|sha512\|md5\|sha1\)\s*(\s*\w*secret\|\w*key\s*+" \
    --include="*.py" .
grep -rn "createHash.*\.update\s*(\s*\w*secret\|\w*key\s*+" \
    --include="*.js" --include="*.ts" .
grep -rn "sha256\s*(\s*\$\(secret\|key\)\s*\." \
    --include="*.php" .
```

**Safe patterns (Remediation):**
```python
# SAFE 1: Use HMAC (RFC 2104) — explicitly designed to defeat length extension
import hmac, hashlib
tag = hmac.new(secret_key, user_data, hashlib.sha256).hexdigest()

# SAFE 2: Use modern hash functions immune to length extension (BLAKE2, SHA-3)
tag = hashlib.blake2b(user_data, key=secret_key).hexdigest()
```
```javascript
// SAFE: Use crypto.createHmac
const tag = crypto.createHmac("sha256", secret).update(data).digest("hex");
```

---

## Phase 2 — Encryption Mode Weaknesses

### ECB Mode (Electronic Codebook) — CWE-327

ECB mode encrypts identical blocks to identical ciphertext, revealing patterns.

```bash
# Find ECB mode usage
grep -rn "MODE_ECB\|AES\.MODE_ECB\|ECB\|Cipher\.getInstance.*ECB" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.go" --include="*.cs" .
```

```python
# VULNERABLE — ECB mode
cipher = AES.new(key, AES.MODE_ECB)   # ✗ deterministic, leaks patterns

# SAFE — authenticated encryption
cipher = AES.new(key, AES.MODE_GCM)   # ✓ or AES-CBC with HMAC
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

### CBC Without Authentication — Padding Oracle

```bash
grep -rn "MODE_CBC\|AES\.MODE_CBC\|Cipher\.getInstance.*CBC" \
    --include="*.py" --include="*.java" --include="*.js" --include="*.ts" --include="*.go" --include="*.cs" .
```

```python
# VULNERABLE — CBC without MAC (padding oracle attack possible)
cipher = AES.new(key, AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(plaintext, 16))
# No integrity check = padding oracle attack ✗

# SAFE — use authenticated encryption instead
cipher = AES.new(key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
# tag authenticates the ciphertext ✓
```

### RSA Encryption Padding vs Signatures (PKCS#1 v1.5) — CWE-780 / RFC 8017

> **Critical Audit Rule:** Distinguish RSA encryption padding from RSA signature schemes:
> - **RSAES-PKCS1-v1_5 (Encryption):** VULNERABLE. Prone to Bleichenbacher's chosen-ciphertext padding oracle attacks (e.g., ROBOT attack). Asymmetric encryption must use **RSAES-OAEP** (with SHA-256).
> - **RSASSA-PKCS1-v1_5 (Signatures):** ACCEPTABLE. Commonly used in JWT (`RS256`), TLS, and X.509 certificates. Digital signatures do not decrypt ciphertext and are NOT subject to Bleichenbacher encryption padding oracles. **Do NOT flag RS256/RSASSA-PKCS1-v1_5 signature algorithms as padding oracle bugs.** (For new greenfield systems, RSASSA-PSS / `PS256` or Ed25519 is recommended).

```bash
# Scan for RSA encryption with PKCS#1 v1.5 padding (flag only for encryption, not signatures)
grep -rn "RSA/ECB/PKCS1Padding\|RSA_PKCS1_PADDING" \
    --include="*.java" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.cs" .
```

```python
# VULNERABLE — RSA encryption using PKCS#1 v1.5 padding
from cryptography.hazmat.primitives.asymmetric import padding
ciphertext = public_key.encrypt(data, padding.PKCS1v15())  # ✗ Bleichenbacher padding oracle

# SAFE — RSA encryption using OAEP padding
from cryptography.hazmat.primitives import hashes
ciphertext = public_key.encrypt(
    data,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    ),
)  # ✓ OAEP is immune to Bleichenbacher attacks
```

### Static / Hardcoded IV

```bash
grep -rn "iv\s*=\s*b['\"]\\\\x00\|iv\s*=\s*bytes\(16\)\|iv\s*=\s*['\"]0000\|IV\s*=\s*b['\"]" \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" .
```

```python
# VULNERABLE — zero/static IV
iv = b'\x00' * 16   # ✗ all-zero IV is predictable
iv = b'staticivvalue!!'  # ✗ hardcoded IV

# SAFE — random IV per encryption
iv = get_random_bytes(16)   # ✓ or use AES-GCM (random nonce built-in)
cipher = AES.new(key, AES.MODE_CBC, iv)
```

---

## Phase 3 — Insecure Random Number Generation

### Cryptographically Weak PRNGs

```bash
# JavaScript — Math.random() for security
grep -rn "Math\.random()" --include="*.js" --include="*.ts" .

# Python — random module (not crypto)
grep -rn "import random\|random\.random\|random\.randint\|random\.choice" \
    --include="*.py" . | grep -v "test\|spec\|#"

# PHP — rand(), mt_rand()
grep -rn "\brand\s*(\|\bmt_rand\s*(" --include="*.php" .

# Ruby — rand()
grep -rn "\brand\b\|Random\.rand\b" --include="*.rb" . | grep -v "test\|spec"

# Java — java.util.Random
grep -rn "new Random()\|new java\.util\.Random" --include="*.java" .

# Go — math/rand
grep -rn "math/rand\|rand\.Intn\|rand\.Int63\|rand\.Float" --include="*.go" .
```

### Context Assessment for Weak PRNG

| Use Case | Weak PRNG | Severity |
|---|---|---|
| Session token generation | `Math.random()` | CRITICAL |
| Password reset token | `random.randint()` | CRITICAL |
| CSRF token | `rand()` | CRITICAL |
| API key generation | `new Random()` | CRITICAL |
| Nonce/IV generation | `Math.random()` | CRITICAL |
| Game logic | `Math.random()` | INFO |
| Shuffle for display | `random.shuffle()` | INFO |

### Safe Alternatives

```javascript
// JavaScript — crypto.randomBytes()
const crypto = require("crypto")
const token = crypto.randomBytes(32).toString("hex")  // ✓

// Browser — crypto.getRandomValues()
const array = new Uint8Array(32)
crypto.getRandomValues(array)  // ✓
```

```python
# Python — secrets module
import secrets
token = secrets.token_hex(32)      # ✓
token = secrets.token_urlsafe(32)  # ✓
random_int = secrets.randbelow(100) # ✓
```

```go
// Go — crypto/rand
import "crypto/rand"
import "encoding/hex"

b := make([]byte, 32)
if _, err := rand.Read(b); err != nil { panic(err) }
token := hex.EncodeToString(b)  // ✓
```

```java
// Java — SecureRandom
import java.security.SecureRandom;
SecureRandom sr = new SecureRandom();
byte[] bytes = new byte[32];
sr.nextBytes(bytes);  // ✓
```

---

## Phase 4 — Key Management

### Hardcoded Keys

```bash
# Find hardcoded encryption keys
grep -rn "AES_KEY\s*=\s*b['\"\|aes_key\s*=\s*['\"\|encryption_key\s*=\s*['\"]" \
    --include="*.py" --include="*.js" --include="*.ts" --include="*.go" --include="*.java" --include="*.rb" --include="*.php" . -i

grep -rn "key\s*=\s*b['\"][^'\"]\{16,\}['\"]" --include="*.py" .
grep -rn "key\s*=\s*['\"][0-9a-fA-F]\{32,\}['\"]" --include="*.js" --include="*.ts" .

# Hardcoded RSA private key
grep -rn "PRIVATE KEY" --include="*.js" --include="*.ts" --include="*.py" --include="*.go" --include="*.java" --include="*.rb" .
```

### Weak Key Size

```bash
# RSA key size
grep -rn "RSA\.generate\s*(\s*[0-9]\{4\}" --include="*.py" .
# Flag if < 2048 bits
grep -rn "generateKeyPair.*rsa.*modulusLength" --include="*.js" --include="*.ts" .
# Flag if modulusLength < 2048

# Symmetric key size
# AES-128 (16 bytes) is acceptable, but AES-256 (32 bytes) preferred
```

### Key Derivation Weaknesses

```python
# VULNERABLE — using password directly as key
key = password.encode()[:16]     # ✗ password is not a key
key = password.encode().ljust(16, b'\x00')  # ✗ same problem

# VULNERABLE — weak KDF
key = hashlib.md5(password.encode()).digest()    # ✗ MD5, no salt, fast
key = hashlib.sha256(password.encode()).digest() # ✗ no salt, no iterations, fast

# SAFE — proper KDF
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000)
key = kdf.derive(password.encode())  # ✓
```

---

## Phase 5 — Timing Side-Channel Attacks

### String Comparison Timing Leaks

Any `==` comparison of security tokens (HMAC, password hashes, API keys) leaks
timing information that can be used to reconstruct the secret.

```bash
# Python — find direct equality comparison of tokens/signatures
grep -rn "signature\s*==\|hmac\s*==\|token\s*==\|hash\s*==" --include="*.py" .
grep -rn "if\s*\w*token\w*\s*==\|if\s*\w*hmac\w*\s*==" --include="*.py" .

# JavaScript
grep -rn "token\s*===\|signature\s*===\|hash\s*===" --include="*.js" --include="*.ts" .
grep -rn "if\s*(\s*\w*Token\s*===\|if\s*(\s*hmac\s*===" --include="*.js" --include="*.ts" .
```

```python
# VULNERABLE — timing leak
if provided_token == stored_token:      # ✗ short-circuits on first mismatch
    authenticate()

if hmac.hexdigest() == provided_hmac:   # ✗ same problem

# SAFE — constant-time comparison
import hmac
if hmac.compare_digest(provided_token, stored_token):  # ✓
    authenticate()
```

```javascript
// VULNERABLE
if (token === storedToken) // ✗ timing leak

// SAFE
import { timingSafeEqual } from "crypto"
const tokenA = Buffer.from(token)
const tokenB = Buffer.from(storedToken)
if (tokenA.length === tokenB.length && timingSafeEqual(tokenA, tokenB)) // ✓
```

---

## Phase 6 — Certificate & TLS Verification

```bash
# Python — disabled TLS verification
grep -rn "verify\s*=\s*False\|ssl\.create_default_context\s*(\s*)\s*\." --include="*.py" .
grep -rn "ssl\._create_unverified_context\|CERT_NONE" --include="*.py" .

# JavaScript — NODE_TLS_REJECT_UNAUTHORIZED
grep -rn "rejectUnauthorized\s*:\s*false\|NODE_TLS_REJECT_UNAUTHORIZED.*0" \
    --include="*.js" --include="*.ts" .

# Go — InsecureSkipVerify
grep -rn "InsecureSkipVerify\s*:\s*true" --include="*.go" .

# Java — TrustAllCerts, empty HostnameVerifier
grep -rn "TrustManager.*new.*0\|HostnameVerifier.*true\|setDefaultSSLSocketFactory" \
    --include="*.java" .
```

```python
# VULNERABLE — no certificate verification
requests.get(url, verify=False)  # ✗ MITM attack possible

# SAFE
requests.get(url, verify=True)   # ✓ (default)
requests.get(url)                # ✓ verify=True is default
```

---

## Phase 7 — JWT Cryptography

```bash
# Find JWT signing
grep -rn "jwt\.sign\|jwt\.encode\|jwt_encode\|Jwts\.builder" \
    --include="*.js" --include="*.ts" --include="*.py" --include="*.java" .
```

### JWT Algorithm Weaknesses

```javascript
// CRITICAL — none algorithm accepted
jwt.verify(token, secret, { algorithms: ["HS256", "none"] })  // ✗

// CRITICAL — no algorithm restriction
jwt.verify(token, publicKey)  // ✗ attacker can switch to HS256 using public key as secret

// HIGH — weak HS256 secret
jwt.sign(payload, "secret")       // ✗ too short
jwt.sign(payload, "password123")  // ✗ guessable

// SAFE
jwt.sign(payload, process.env.JWT_SECRET, { algorithm: "HS256", expiresIn: "1h" })  // ✓
jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] })  // ✓
```

---

## Output Format

````markdown
## [SEVERITY] CRYPTO-[NNN]: [Vulnerability Title]

**CWE:** CWE-XXX — [Name]
**Algorithm/Primitive:** [MD5 | ECB | Math.random() | etc.]
**Language:** [Python / JavaScript / Java / Go]
**Impact Category:** [Confidentiality | Integrity | Authentication | Non-repudiation]

### Location
- **File:** `path/to/crypto.py:LINE`
- **Function:** `encryptUserData()`

### Vulnerable Code
```[lang]
[exact vulnerable code snippet]
```

### Why It's Weak
[Technical explanation of the cryptographic weakness]

### Exploitability
[How an attacker would exploit this weakness — conceptual, not working code]

### Remediation
```[lang]
[safe replacement code]
```

### Algorithm Reference
- Recommended: [e.g., AES-256-GCM, argon2id]
- Standard: [e.g., NIST SP 800-38D, RFC 8439]
````

---

## Cryptography Recommendations Quick Reference

| Category | Avoid | Use Instead |
|---|---|---|
| **Symmetric encryption** | DES, 3DES, RC4, AES-ECB, AES-CBC (unauthenticated) | AES-256-GCM, ChaCha20-Poly1305 |
| **Hashing (general)** | MD5, SHA-1 | SHA-256, SHA-3, BLAKE2 |
| **Password hashing** | MD5, SHA-1, SHA-256 (unsalted), bcrypt cost<10 | argon2id, bcrypt (cost≥12), scrypt |
| **PRNG** | Math.random(), rand(), random.random() | crypto.getRandomValues(), secrets, crypto/rand |
| **Asymmetric** | RSA-1024, RSAES-PKCS1-v1_5 (encryption padding) | RSA-4096 (OAEP for encryption, PSS/Ed25519 for signatures), Ed25519, X25519 |
| **Key derivation** | Raw password as key, MD5(password) | PBKDF2 (600k+ iterations), argon2id |
| **MAC** | CRC, homemade HMAC, unkeyed hash | HMAC-SHA256, HMAC-SHA512 |
| **Token comparison** | == / === | hmac.compare_digest(), timingSafeEqual() |
| **TLS** | SSLv3, TLSv1.0, TLSv1.1, self-signed in prod | TLS 1.2+ (prefer 1.3) |

---

## Rules of Engagement

1. **Context matters** — MD5 for a non-security checksum is different from MD5 for password hashing.
2. **Cite the standard** — reference NIST, RFC, or academic paper for recommendations.
3. **Algorithm + mode + key management** — cryptography has three layers, audit all three.
4. **Timing attacks need careful analysis** — not every string comparison is a vulnerability.
5. **Key rotation** — flag any key management that doesn't support rotation without downtime.
6. **No custom crypto** — flag any attempt to implement custom encryption algorithms.
