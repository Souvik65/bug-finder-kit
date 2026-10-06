# Server Hardening, Configuration, and Scanner Triage

## Contents
1. Web server fixes
2. Error handling
3. Triage of scanner results
4. Modern items beyond the source book

## 1. Web server fixes

Many server-level fixes are more than a decade old and still correct; they fail because they aren't applied consistently.

- **Repeatable hardening**: automate a locked-down baseline so every new environment is built the same way; keep dev, test, and production configured identically.
- **Patch everything on a schedule**: OS, web server, runtimes, frameworks, and all third-party libraries and CMS plugins (libraries are the commonly forgotten part).
- **Remove what you don't need**: unused services, ports, sample apps, default accounts, admin consoles exposed to the internet, directory listing.
- **Change default credentials** on every component (servers, databases, appliances, admin panels).
- **Least privilege** for the account the web server runs as and for filesystem permissions.
- **Periodic audits**: internal and external scans and penetration tests to catch drift and missed patches.
- Keep secrets (keys, database passwords) out of source control and out of web-accessible paths.

## 2. Error handling

Verbose errors (stack traces, SQL errors, file paths, version strings) hand attackers material for further attacks.
- Show users a generic message ("Something went wrong, try again later"), with no distinction that reveals internals.
- Log full details server-side with an incident/correlation id.
- Turn off debug modes in production.
- Remember generic pages are one layer of defense in depth: an intercepting proxy still shows status codes.

## 3. Triage of scanner results

1. **Verify before reporting.** Version-based findings often misfire (backported patches, banner spoofing). Reproduce with a minimal request.
2. **Deduplicate** by root cause: ten reflected-parameter findings may be one missing encoding helper.
3. **Rate by exposure and impact**, not by the scanner's label alone.
4. **Know scanner blind spots**: authorization flaws, business-logic abuse, multi-step flows, and anything behind complex authentication.
5. **Record false positives** with the reason, so retests are faster.

## 4. Modern items beyond the source book

Add these checks to code or config review; the 2013 book does not cover them in depth.
- **TLS everywhere** with modern configuration; HSTS.
- **Security headers**: `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, frame protection (`frame-ancestors`).
- **SSRF**: server fetches URLs from user input; restrict destinations and block internal ranges.
- **Mass assignment / over-posting**: binding request bodies directly to models.
- **Insecure deserialization** and unsafe template rendering from user input.
- **JWT and token handling**: algorithm pinning, expiry, signature verification, no secrets in tokens.
- **CORS**: no wildcard origins with credentials.
- **Dependency and supply-chain risk**: lockfiles, vulnerability scanning of dependencies.
- **Logging and monitoring** for authentication events and access-control failures.
