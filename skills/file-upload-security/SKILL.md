---
name: file-upload-security
description: >
  Comprehensive file upload security review and vulnerability detection skill.
  Audits file upload mechanisms for unrestricted file upload leading to Remote Code
  Execution (RCE), filename path traversal (Zip Slip, directory traversal), MIME-type
  spoofing and browser sniffing bypasses, extension allowlist bypasses (double extensions,
  null bytes, alternate streams), malicious file contents (SVG-based Stored XSS, XXE,
  zip bombs), and insecure storage directory configurations. Activate when the user
  asks to "review file upload security", "check upload vulnerabilities", "prevent web shell upload",
  "audit file upload handler", "path traversal in filename", "MIME sniffing security", or
  "secure file upload checklist".
triggers:
  - "file upload"
  - "upload security"
  - "web shell"
  - "MIME sniffing"
  - "path traversal filename"
  - "zip slip"
  - "SVG XSS"
  - "file upload vulnerability"
  - "unrestricted file upload"
  - "decompression bomb"
  - "zip bomb"
  - "check upload handler"
  - "upload directory configuration"
version: 1.0.0
author: bug-finder-kit
category: security
risk: safe
tags: "[file-upload, rce, webshell, path-traversal, mime-sniffing, xss, security]"
date_added: "2026-10-21"
---

# File Upload Security — Unrestricted Uploads, MIME Sniffing & RCE Defense

> File upload functions represent one of the most critical attack vectors in web
> applications. Allowing users to upload files to a server creates immediate risks
> of Remote Code Execution (RCE) via web shells, file system overwrite via path
> traversal, Client-Side Stored XSS via SVG/HTML, and server resource exhaustion.

> This skill provides a comprehensive audit methodology to identify, exploit, and
> fix vulnerabilities in file upload workflows across server-side code, storage
> layers, and delivery architecture.

---

## File Upload Attack Surface

```
Incoming Upload Request (multipart/form-data)
  ├── 1. Filename & Path Traversal
  │     ├── Directory traversal (../../var/www/shell.php)
  │     ├── Zip Slip in archive extraction
  │     ├── Null bytes / Truncation (shell.php%00.jpg)
  │     └── Sensitive config overwrite (.htaccess, web.config)
  ├── 2. Extension & Validation Bypass
  │     ├── Blocklist bypass (php5, phtml, pht, phps, jspx, ashx)
  │     ├── Double / Hidden extensions (avatar.php.png, file.jpg.php)
  │     └── Case sensitivity & OS quirks (shell.PhP, shell.asp::$DATA)
  ├── 3. Content & MIME Verification
  │     ├── Client-supplied Content-Type header spoofing
  │     ├── Magic bytes spoofing (GIF89a + PHP payload)
  │     └── Polyglot files (valid image that executes as script)
  ├── 4. Stored Content Attacks
  │     ├── Stored XSS via SVG `<script>` or HTML files
  │     ├── XXE injection inside XML-based formats (SVG, DOCX, XLSX, PDF)
  │     └── Decompression bombs (Zip bomb causing Denial of Service)
  └── 5. Storage & Execution Environment
        ├── File saved directly under web root (direct HTTP access)
        ├── Server executes scripts in upload directory (Apache, Nginx, IIS)
        └── Missing defensive HTTP headers (nosniff, attachment)
```

---

## Phase 1 — Filename Sanitization & Path Traversal

Never trust the user-provided filename supplied in the `Content-Disposition` header.

### 1.1 Directory Traversal in Filenames

Attackers inject path traversal sequences into the original filename to escape the
intended upload directory and overwrite system binaries, cron jobs, or existing code.

```python
# VULNERABLE: Direct concatenation with original filename
filename = request.files['avatar'].filename
upload_path = os.path.join('/var/www/uploads', filename)
# If filename is "../../var/www/html/shell.php", it escapes uploads/!
request.files['avatar'].save(upload_path)
```

**Remediation (Randomized Filenames & Safe Basename):**

```python
# SAFE: Discard user-supplied filename completely; generate secure UUID
import uuid, os

ext = os.path.splitext(uploaded_file.filename)[1].lower()
if ext not in ALLOWED_EXTENSIONS:
    raise ValueError("Disallowed extension")

safe_filename = f"{uuid.uuid4().hex}{ext}"
safe_path = os.path.join(SECURE_UPLOAD_DIR, safe_filename)
```

### 1.2 Zip Slip (Archive Traversal)

When applications accept zip, tar, or rar archives and extract them, entries containing
`../` paths can write files anywhere the server process has permissions.

```javascript
// VULNERABLE (Node.js unzipper):
zipFile.pipe(unzipper.Extract({ path: 'output/dir' })); // Zip slip vulnerable if unvalidated!

// SAFE: Validate canonical path before writing each entry
const resolvedPath = path.resolve(destDir, entry.path);
if (!resolvedPath.startsWith(path.resolve(destDir) + path.sep)) {
    throw new Error('Directory traversal attempt detected in zip entry: ' + entry.path);
}
```

---

## Phase 2 — Extension Validation & Parser Quirks

### 2.1 The Blocklist Fallacy

Never use blocklists (e.g. blocking `.php` or `.exe`). Attackers bypass blocklists
using alternate executable extensions and server configuration quirks:

| Platform | Target Extensions | Alternative Bypasses |
|---|---|---|
| **PHP / Apache** | `.php` | `.php3`, `.php4`, `.php5`, `.phtml`, `.pht`, `.phar`, `.inc` |
| **ASP.NET / IIS** | `.aspx` | `.asp`, `.ashx`, `.asmx`, `.cer`, `.config`, `.cshtml` |
| **Java / Tomcat** | `.jsp` | `.jspx`, `.jsw`, `.jsv`, `.jspf` |
| **Node.js** | `.js` | `.mjs`, `.cjs` |
| **Server Config** | Configuration | `.htaccess`, `.user.ini`, `web.config` |

**Defensive Rule: Strict Allowlist Only:**
```python
ALLOWED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.pdf', '.webp'}

def validate_extension(filename: str) -> str:
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise SecurityException("Invalid file extension")
    return ext
```

### 2.2 Double Extensions and Web Server Handler Misconfigurations

- **Apache `AddHandler` Quirk:** Configurations like `AddHandler application/x-httpd-php .php`
  treat `image.php.jpg` as executable PHP code if `.jpg` has no registered handler!
- **Trailing Dots and Spaces (Windows/NTFS):** `shell.php.` or `shell.php ` strip trailing
  dots/spaces during filesystem writes, resulting in `shell.php`.
- **NTFS Alternate Data Streams (Windows):** `shell.php::$DATA` writes the file as `shell.php`
  while evading simple extension checks.

---

## Phase 3 — MIME-Type & Content Verification

### 3.1 Content-Type Header Spoofing

The HTTP `Content-Type` header (e.g. `image/png`) sent by the client is completely
under attacker control. Checking only `file.mimetype` provides zero security.

### 3.2 Magic Bytes (File Signature) Validation

Validate the initial header bytes of the file on the server using a binary signature
library (e.g., `libmagic`, `file-type`, `mime-types` with byte inspection).

```javascript
// SAFE (Node.js): Inspect buffer magic bytes using file-type
const fileType = require('file-type');
const fs = require('fs');

async function verifyFile(filePath) {
    const buffer = fs.readFileSync(filePath);
    const type = await fileType.fromBuffer(buffer);

    const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp'];
    if (!type || !ALLOWED_MIME.includes(type.mime)) {
        fs.unlinkSync(filePath);
        throw new Error("File content does not match allowed image signatures");
    }
}
```

### 3.3 Polyglot Files & Image Re-Encoding

Attackers can construct valid GIF/PNG/JPEG files that embed PHP or JavaScript payloads
inside image metadata (EXIF) or image headers:
- `GIF89a<?php system($_GET['c']); ?>` (Valid GIF magic bytes + PHP web shell).

**Remediation:**
Re-encode or re-render images through an image processing library (e.g., Pillow,
Sharp, ImageMagick) to strip malicious metadata and destroy embedded executable code:

```python
# SAFE: Re-encode image to strip EXIF and polyglot payloads
from PIL import Image
import io

def sanitize_image(image_bytes: bytes) -> bytes:
    image = Image.open(io.BytesIO(image_bytes))
    # Strip EXIF and normalize format
    clean_buffer = io.BytesIO()
    image.save(clean_buffer, format="PNG")
    return clean_buffer.getvalue()
```

---

## Phase 4 — Stored Content Attacks (XSS, XXE & Bombs)

### 4.1 SVG Files (Stored Cross-Site Scripting)

SVG is an XML-based image format that natively supports inline JavaScript and event
handlers. If an SVG is rendered directly in the user's browser, the embedded script executes
in the application's domain!

```xml
<!-- VULNERABLE: Malicious SVG triggering Stored XSS -->
<svg xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" fill="red" />
  <script type="text/javascript">
    alert(document.domain); // Full access to cookies, session, local storage!
  </script>
</svg>
```

**Remediation:**
- Block `.svg` uploads if not strictly required.
- If SVGs are required, sanitize using `DOMPurify` / `svg-sanitizer`.
- Serve SVGs with `Content-Disposition: attachment` or host on an isolated sandbox domain.

### 4.2 XXE Injection via XML Formats

Formats like `.docx`, `.xlsx`, `.pptx`, `.svg`, and `.pdf` contain XML. If the server
parses these files using an unhardened XML parser, attackers can execute XML External
Entity (XXE) attacks to read local files (`/etc/passwd`) or perform SSRF.

**Remediation:**
Ensure all XML/document parsers disable external entity resolution (`disallow-doctype-decl`,
`resolve_entities = False`).

### 4.3 Decompression Bombs (Zip / Image Bombs)

A tiny 42 KB archive can decompress into 4.5 Petabytes of null bytes, exhausting
disk space and RAM (Zip bomb). Similarly, 100 KB image bombs can claim gigabytes of memory.

**Remediation:**
- Limit total uncompressed stream size during decompression.
- Enforce strict memory and dimension limits on images before decoding.

---

## Phase 5 — Storage & Serving Architecture

The defense-in-depth model ensures that even if a malicious file bypasses validation,
it **cannot be executed** by the server or browser.

### 5.1 Store Outside Web Root

Never store uploaded files in directories exposed by the web server (e.g., `/var/www/html/uploads/`).
Store files outside the docroot (e.g., `/var/data/uploads/` or AWS S3 / Cloud Storage).

### 5.2 Disable Script Execution in Upload Directories

If files must be served locally by the web server, disable script execution completely:

#### Nginx:
```nginx
# Block PHP execution in upload directory
location /uploads/ {
    location ~ \.(php|phtml|phar|inc)$ {
        deny all;
    }
}
```

#### Apache (.htaccess in uploads directory):
```apache
# Disable script interpretation
php_flag engine off
RemoveHandler .php .phtml .php3
Options -ExecCGI -Indexes
```

### 5.3 Force Safe Delivery Headers

When users download or view uploaded files:

```http
Content-Type: application/octet-stream   # Or specific verified MIME
Content-Disposition: attachment; filename="download.pdf"
X-Content-Type-Options: nosniff          # Prevents browser MIME-sniffing execution
Content-Security-Policy: default-src 'none' # If served in browser
```

### 5.4 Use Dedicated Isolated Domains (CDN / S3)

Serve user-uploaded content from a completely separate origin (e.g., `https://user-content.example.com`
or direct S3 pre-signed URLs) to isolate cookies and browser permissions from the primary application.

---

## Phase 6 — Audit Checklist & Finding Format

### Complete File Upload Review Checklist

```
[ ] Filename Handling:
    - User filename discarded; replaced with server-generated UUID
    - Path traversal sequences (../, ..\) stripped
    - Zip archives validated against Zip Slip before extraction

[ ] Extension Validation:
    - Strict allowlist enforced (not a blocklist)
    - Double extensions and trailing characters stripped/inspected
    - Config files (.htaccess, web.config) strictly rejected

[ ] Content Validation:
    - Magic bytes inspected using binary signature library
    - Client-supplied Content-Type ignored
    - Images re-encoded to strip polyglot payloads and EXIF metadata
    - SVGs sanitized or rejected

[ ] Storage & Execution:
    - Files saved outside the web root
    - Script execution disabled on storage directories
    - Max file size limits enforced on server and proxy
    - Uploaded files served with nosniff and attachment headers
```

### Finding Template

```
### [Severity] Insecure File Upload: <Title>
- Location: <file:line> or <Endpoint + Upload Field>
- Attack Vector: Web Shell RCE | Path Traversal | Stored XSS | DoS
- Flaw Description: <Explain how the upload handler fails to restrict files>
- Bypass Scenario: <E.g., Content-Type spoofing, double extension, Zip Slip>
- Evidence / Code:
    ```<language>
    // Show flawed validation or direct save
    ```
- Remediation:
    - Generate random filenames (UUID)
    - Implement magic byte verification
    - Configure web server to deny script execution
    - Before & After code snippet
- Confidence: Confirmed | Likely | Configuration Dependent
```
