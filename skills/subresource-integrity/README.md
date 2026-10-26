# subresource-integrity

> Subresource Integrity (SRI) and external CDN asset security audit skill for the
> **bug-finder-kit**. Provides end-to-end evaluation of external scripts and stylesheets
> to protect against CDN compromise, DNS hijacking, and Magecart formjacking attacks.

---

## What This Skill Covers

| Attack Vector / Technique | Audit Focus |
|---|---|
| **Missing SRI on External Scripts** | Plain `<script src="https://cdn...">` vulnerable to CDN compromise |
| **Missing SRI on Stylesheets** | External CSS injection risks (data exfiltration via CSS selectors) |
| **CORS Attribute Pairing** | Missing `crossorigin="anonymous"` breaking SRI enforcement |
| **Weak Hash Algorithms** | Legacy sha1/md5 vs required modern sha384/sha512 digests |
| **Dynamic Script Classification** | Handling unpinnable tags (GTM, analytics) vs static vendor libraries |
| **Magecart Defense** | Formjacking protections for checkout, payment, and login pages |
| **ES Modules & Import Maps** | Integrity enforcement for modern JavaScript `import` maps |
| **Build Pipeline Automation** | `webpack-subresource-integrity`, `vite-plugin-manifest-sri` integration |
| **Hash Drift Detection** | CI/CD monitoring scripts detecting upstream CDN alterations |

---

## Scope Boundary

| Skill | What It Covers |
|---|---|
| `csp-auditor` | Content Security Policy headers, script-src allowlists, nonces, and hashes |
| `supply-chain-security` | Package dependency integrity (npm/pip), lockfiles, typosquatting, CI/CD |
| **`subresource-integrity`** | Cryptographic integrity verification (`integrity="..."`, `crossorigin`) for external CDN-hosted JS/CSS subresources and Magecart defense |

---

## Trigger Phrases

Activate this skill by asking:
- `"subresource integrity"`, `"SRI audit"`
- `"integrity attribute check"`, `"CDN security audit"`
- `"crossorigin anonymous review"`, `"Magecart defense"`
- `"third-party script risk"`, `"CDN compromise detection"`
- `"webpack-subresource-integrity"`, `"hash drift verification"`

---

## Directory Structure

```
skills/subresource-integrity/
├── SKILL.md              — Core audit guide (Phases 1–10, attack classes, code examples)
├── README.md             — Overview, scope boundary, and triggers
└── references/
    └── detailed-guide.md — Technical reference on SRI browser verification algorithm,
                            CSS injection attacks via CDN, and automated build configs
```
