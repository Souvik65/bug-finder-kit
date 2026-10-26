# file-upload-security

> File upload vulnerability analysis and hardening skill for the **bug-finder-kit**.
> Audits file upload handlers for unrestricted file upload leading to Remote Code
> Execution (RCE), web shells, path traversal (Zip Slip), MIME sniffing bypasses,
> SVG Stored XSS, and insecure upload directory configurations.

---

## What This Skill Covers

| Vulnerability Target | Attack Technique | Key Defense |
|---|---|---|
| **Web Shell / RCE** | Uploading `.php`, `.jsp`, `.aspx`, or `.phtml` files | Strict extension allowlist, random UUID renaming, script execution disabled |
| **Path Traversal** | Filename manipulation (`../../etc/cron.d/shell`) | Discard user filename, strip paths, use random file names |
| **Zip Slip** | Archive entries with `../` path components | Canonical path resolution check before extracting |
| **MIME Sniffing** | Browser executing HTML/JS disguised as images | `X-Content-Type-Options: nosniff`, `Content-Disposition: attachment` |
| **Polyglot Files** | Valid image headers wrapping executable script (`GIF89a<?php`) | Server-side image re-encoding (Pillow/Sharp) |
| **Stored XSS** | SVGs containing embedded `<script>` or event handlers | Strict sanitization (DOMPurify), block SVG uploads, isolated CDN origin |
| **XXE Injection** | DOCX/XLSX/SVG files with malicious XML entities | Disable external entity resolution in all document parsers |
| **Decompression Bombs** | Small archives decompressing to gigabytes/petabytes | Enforce strict uncompressed stream limits during extraction |

---

## Trigger Phrases

Activate this skill by asking:
- `"file upload security"`, `"check upload handler"`
- `"prevent web shell upload"`, `"unrestricted file upload"`
- `"MIME sniffing vulnerability"`, `"path traversal filename"`
- `"zip slip"`, `"SVG XSS upload"`
- `"upload directory configuration"`, `"secure file upload checklist"`

---

## Directory Structure

```
skills/file-upload-security/
├── SKILL.md              — Core audit guide (Phases 1–6, code sinks, defensive architectures)
├── README.md             — Overview, attack techniques, and triggers
└── references/
    └── detailed-guide.md — Magic bytes reference table, server configs (Apache/Nginx), and S3 patterns
```

---

## Author & Version
`bug-finder-kit` — v1.0.0 — 2026-10-21
