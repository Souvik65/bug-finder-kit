#!/usr/bin/env python3
"""Static inventory of third-party script exposure.

Usage: python audit_scripts.py <path> [--json] [--md]

Finds external script loads, known vendor snippets, tag managers, missing SRI on
pinned CDN URLs, dynamic loaders, risky patterns, shadow DOM usage, and header/CSP
evidence. Output is a set of leads. Tag-manager-injected scripts are only visible
at runtime.
"""
import json
import os
import re
import sys
from collections import defaultdict
from urllib.parse import urlparse

EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm",
        ".json", ".conf", ".toml", ".yml", ".yaml", ".md"}
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "coverage", ".vercel", "out", ".turbo"}

VENDORS = [
    ("Google Tag Manager", r"googletagmanager\.com/(gtm|ns)|GTM-[A-Z0-9]{5,}|react-gtm-module|GoogleTagManager", "tag-manager"),
    ("Google Analytics/gtag", r"googletagmanager\.com/gtag|google-analytics\.com|\bgtag\(|react-ga4|G-[A-Z0-9]{8,}", "analytics"),
    ("Meta Pixel", r"connect\.facebook\.net|\bfbq\(", "ad-pixel"),
    ("TikTok Pixel", r"analytics\.tiktok\.com|\bttq\.", "ad-pixel"),
    ("LinkedIn Insight", r"snap\.licdn\.com|_linkedin_partner_id", "ad-pixel"),
    ("Hotjar", r"static\.hotjar\.com|\bhj\(", "session-replay"),
    ("Microsoft Clarity", r"clarity\.ms|\bclarity\(", "session-replay"),
    ("FullStory", r"fullstory\.com|FS\.identify|fs\.js", "session-replay"),
    ("LogRocket", r"logrocket|cdn\.lr-ingest", "session-replay"),
    ("Intercom", r"widget\.intercom\.io|\bIntercom\(", "chat"),
    ("Drift/Crisp/Zendesk", r"js\.driftt\.com|client\.crisp\.chat|static\.zdassets\.com", "chat"),
    ("Segment", r"cdn\.segment\.com|analytics\.load\(", "tag-manager"),
    ("Tealium", r"tiqcdn\.com|\butag\b", "tag-manager"),
    ("Adobe Launch", r"assets\.adobedtm\.com|launch-[a-z0-9]+(\.min)?\.js", "tag-manager"),
    ("Optimizely/VWO", r"optimizely\.com|dev\.visualwebsiteoptimizer\.com|\bvwo_", "ab-testing"),
    ("PostHog/Mixpanel/Amplitude", r"posthog|mixpanel|amplitude\.com|cdn\.amplitude", "analytics"),
    ("Sentry/Datadog RUM", r"sentry-cdn\.com|browser\.sentry|datadoghq-browser-agent", "monitoring"),
    ("Consent manager", r"onetrust|cookiebot|usercentrics|cookieyes", "consent"),
    ("Stripe/PayPal/Razorpay JS", r"js\.stripe\.com|paypal\.com/sdk|checkout\.razorpay\.com", "payment"),
    ("Ads (AdSense/DoubleClick)", r"pagead2\.googlesyndication|doubleclick\.net", "ads"),
    ("Polyfill/CDN lib hosts", r"cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|code\.jquery\.com|polyfill\.io", "cdn-lib"),
]
VENDORS_C = [(n, re.compile(p, re.I), c) for n, p, c in VENDORS]

SCRIPT_TAG = re.compile(r"<script\b([^>]*)>", re.I)
SRC_ATTR = re.compile(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I)
SENSITIVE_ROUTE = re.compile(r"(login|signin|sign-in|signup|register|checkout|payment|billing|account|admin|reset|password|dashboard|cart)", re.I)

PATTERNS = [
    ("DYN-LOADER", "medium", re.compile(r"createElement\(\s*['\"]script['\"]\s*\)"), "dynamic script loader: needs nonce/strict-dynamic and a host allowlist"),
    ("DYN-IMPORT-URL", "high", re.compile(r"import\(\s*['\"]https?://"), "dynamic import of remote URL"),
    ("DOC-WRITE", "medium", re.compile(r"document\.write\("), "document.write: legacy vendor pattern, blocks parsing, injection risk"),
    ("EVAL", "medium", re.compile(r"\beval\(|new Function\("), "eval/new Function: incompatible with strict CSP"),
    ("MUTABLE-URL", "medium", re.compile(r"(latest|/current/|@latest|gtm\.js\?id=)", re.I), "mutable vendor/CDN URL: pin version or isolate"),
    ("DATALAYER-PUSH", "low", re.compile(r"dataLayer\.push\("), "dataLayer push: check for user-controlled or sensitive values"),
    ("PII-TO-TRACKER", "high", re.compile(r"(gtag|fbq|mixpanel\.\w+|analytics\.(identify|track)|posthog\.(identify|capture)|hj|clarity)\([^)]*(email|phone|password|token|ssn|aadhaar|card)", re.I), "possible PII/secret sent to tracker"),
    ("UNSAFE-INLINE", "medium", re.compile(r"script-src[^;\n]*'unsafe-(inline|eval)'", re.I), "CSP allows unsafe-inline/eval in script-src"),
    ("CSP-WILDCARD", "medium", re.compile(r"script-src[^;\n]*(\s\*(\s|;|$)|\shttps:(\s|;|$)|\*\.(cloudfront\.net|amazonaws\.com|googleapis\.com|herokuapp\.com))", re.I), "broad script-src allowlist"),
    ("SHADOW-ATTACH", "info", re.compile(r"attachShadow\(|shadowrootmode"), "shadow DOM: not a security boundary; confirm scanners/masking traverse it"),
    ("SHADOW-CLOSED", "low", re.compile(r"mode\s*:\s*['\"]closed['\"]"), "closed shadow root: obfuscation only, not protection"),
    ("SHADOW-HTML-SINK", "medium", re.compile(r"shadowRoot\.(innerHTML|insertAdjacentHTML)|\b(root|shadow|sr|r)\.(innerHTML|insertAdjacentHTML)\b"), "HTML string sink inside shadow tree"),
]


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if os.path.splitext(fn)[1].lower() in EXTS:
                yield os.path.join(dp, fn)


def read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return ""


def analyze(root):
    scripts, vendors, findings = [], defaultdict(list), []
    headers = {k: False for k in ("content-security-policy", "report-only", "strict-dynamic", "nonce", "trusted-types",
                                  "x-frame-options", "frame-ancestors", "referrer-policy", "permissions-policy")}
    for path in iter_files(root):
        txt = read(path)
        low = txt.lower()
        for k in headers:
            key = "content-security-policy-report-only" if k == "report-only" else k
            if key in low:
                headers[k] = True
        lines = txt.splitlines()
        for n, line in enumerate(lines, 1):
            if len(line) > 800:
                continue
            for m in SCRIPT_TAG.finditer(line):
                attrs = m.group(1)
                s = SRC_ATTR.search(attrs)
                if not s:
                    continue
                url = s.group(1)
                host = urlparse(url if "//" in url else "//x/" + url).netloc if url.startswith(("http", "//")) else ""
                if not host:
                    continue
                has_sri = "integrity=" in attrs.lower()
                pinned = bool(re.search(r"@\d+\.\d+|/\d+\.\d+\.\d+/|-\d+\.\d+\.\d+", url))
                scripts.append({"file": path, "line": n, "url": url, "host": host, "sri": has_sri, "pinned_version": pinned,
                                "sensitive_route_file": bool(SENSITIVE_ROUTE.search(path))})
                if pinned and not has_sri:
                    findings.append({"severity": "medium", "rule": "NO-SRI-PINNED", "file": path, "line": n,
                                     "message": "pinned CDN resource without SRI", "code": line.strip()[:160]})
            for name, rx, cat in VENDORS_C:
                if rx.search(line):
                    vendors[name].append({"file": path, "line": n, "category": cat})
            for rid, sev, rx, msg in PATTERNS:
                if rx.search(line):
                    findings.append({"severity": sev, "rule": rid, "file": path, "line": n, "message": msg, "code": line.strip()[:160]})
    return scripts, vendors, findings, headers


def sens_note(vendor_hits):
    files = {h["file"] for h in vendor_hits}
    return sorted(f for f in files if SENSITIVE_ROUTE.search(f))


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        sys.exit(2)
    as_json, as_md = "--json" in sys.argv, "--md" in sys.argv
    scripts, vendors, findings, headers = analyze(args[0])
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: (order[f["severity"]], f["rule"], f["file"], f["line"]))

    if as_json:
        print(json.dumps({"external_scripts": scripts, "vendors": {k: v for k, v in vendors.items()},
                          "findings": findings, "header_evidence": headers}, indent=2))
        return

    hosts = defaultdict(int)
    for s in scripts:
        hosts[s["host"]] += 1
    if as_md:
        print("# Third-Party Script Audit (static scan)\n")
        print("## Inventory\n| Vendor / host | Category | Locations | On sensitive-named files |\n|---|---|---|---|")
        for name, hits in sorted(vendors.items()):
            print(f"| {name} | {hits[0]['category']} | {len(hits)} | {', '.join(sens_note(hits)) or '-'} |")
        for h, c in sorted(hosts.items()):
            print(f"| {h} | external script host | {c} | - |")
        print("\n## Findings (leads)")
        for f in findings:
            print(f"- **[{f['severity'].upper()}] {f['rule']}** `{f['file']}:{f['line']}`: {f['message']}")
        print("\n## Controls evidence\n" + "\n".join(f"- {k}: {'found' if v else 'NOT FOUND'}" for k, v in headers.items()))
        print("\n_Tag-manager-loaded scripts require runtime capture to inventory._")
        return

    print(f"External script tags: {len(scripts)} across {len(hosts)} hosts")
    for h, c in sorted(hosts.items(), key=lambda x: -x[1]):
        print(f"  {h}  x{c}")
    print("\nKnown vendors/snippets detected:")
    for name, hits in sorted(vendors.items()):
        sens = sens_note(hits)
        flag = f"  <-- in sensitive-named files: {', '.join(sens)}" if sens else ""
        print(f"  [{hits[0]['category']:14}] {name} ({len(hits)} hit(s)){flag}")
    print(f"\n{len(findings)} leads:")
    for f in findings:
        print(f"[{f['severity'].upper():6}] {f['rule']:16} {f['file']}:{f['line']}\n         {f['message']}\n         > {f['code']}")
    print("\nControl evidence in project files (not proof it is applied):")
    for k, v in headers.items():
        print(f"  {k}: {'found' if v else 'NOT FOUND - verify at server/CDN'}")
    if any(c for c in vendors if "Tag Manager" in c or c in ("Segment", "Tealium", "Adobe Launch")):
        print("\nNote: a tag manager is present; scripts it injects are only visible at runtime.")


if __name__ == "__main__":
    main()
