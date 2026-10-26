#!/usr/bin/env python3
"""Triage scanner for security review.

Greps a codebase for risky patterns (dangerous sinks, secrets, unsafe defaults,
log leaks) and prints leads as file:line. Hits are NOT findings: read the code
and trace the data before reporting anything.

Usage: python scan_signals.py <path> [--format md|json]
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {".git", "node_modules", ".next", "dist", "build", "venv", ".venv",
             "__pycache__", "vendor", "coverage", ".turbo"}
EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".sql", ".json",
        ".env", ".yml", ".yaml", ".html", ".php", ".rb", ".go", ".java"}
MAX_BYTES = 1_000_000

# (category, regex, why it matters)
RULES = [
    ("injection", r"\b(eval|exec)\s*\(", "Dynamic code execution; check whether input can reach it"),
    ("injection", r"child_process|\bexecSync\b|shell\s*=\s*True|os\.system\(", "Shell execution; command injection if input is interpolated"),
    ("injection", r"(execute|query|raw)\s*\(\s*(f[\"']|[\"'`][^\"'`]*(\+|\$\{|%s))", "SQL built by string interpolation; use parameters"),
    ("injection", r"\$where|\{\s*[\"']?\$(ne|gt|regex)[\"']?\s*:", "NoSQL operator usage; check for client-controlled operators"),
    ("xss", r"dangerouslySetInnerHTML|\.innerHTML\s*=|mark_safe|\|\s*safe\b|v-html", "Raw HTML sink; needs sanitization"),
    ("deserialize", r"pickle\.loads?|yaml\.load\((?!.*Safe)|unserialize\(", "Unsafe deserialization of potentially untrusted data"),
    ("secrets", r"(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*[\"'][A-Za-z0-9_\-/+=]{12,}[\"']", "Possible hardcoded secret; if real, rotate"),
    ("secrets", r"AKIA[0-9A-Z]{16}|sk_live_[0-9a-zA-Z]{10,}|-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Known credential format"),
    ("secrets", r"(NEXT_PUBLIC_|VITE_|REACT_APP_)\w*(SECRET|SERVICE_ROLE|PRIVATE|PASSWORD)", "Secret exposed via public env prefix"),
    ("secrets", r"service_role", "Service-role key usage; must be server-only"),
    ("crypto", r"\b(md5|sha1)\b|Math\.random\(\)|createCipher\(", "Weak hash/randomness; confirm not used for security"),
    ("defaults", r"DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*[\"']\*|origin\s*:\s*[\"']\*[\"']|verify\s*=\s*False|rejectUnauthorized\s*:\s*false", "Insecure default or disabled verification"),
    ("defaults", r"csrf_exempt|AllowAny|httpOnly\s*:\s*false|secure\s*:\s*false", "Protection explicitly disabled"),
    ("authz", r"using\s*\(\s*true\s*\)|with check\s*\(\s*true\s*\)", "Permissive RLS policy"),
    ("authz", r"disable row level security|security definer", "RLS bypass or privileged function; review checks"),
    ("jwt", r"jwt\.(decode|verify)\([^)]*(verify\s*=\s*False|algorithms?\s*:\s*\[?\s*[\"']none)", "JWT verification weakened"),
    ("logging", r"(console\.(log|debug)|print|logger\.\w+|logging\.\w+)\s*\([^)]*(password|token|secret|authorization|cookie|api[_-]?key)", "Possible secret/credential written to logs"),
    ("errors", r"except\s*(Exception)?\s*:\s*(pass)?\s*$|catch\s*\(\s*\w*\s*\)\s*\{\s*\}", "Swallowed error; check it is not hiding a security failure"),
    ("errors", r"(res\.(send|json)|return\s+Response)\([^)]*(err\.stack|traceback|\.stack)", "Stack trace returned to client"),
    ("ssrf/path", r"(fetch|axios\.\w+|requests\.\w+|urlopen)\(\s*(req|request|params|input)\b", "Outbound request to user-controlled URL; SSRF"),
    ("ssrf/path", r"(open|readFile\w*|sendFile|join)\([^)]*(req\.|request\.|params|input)", "File path from user input; traversal"),
    ("redirect", r"(redirect|location\.href)\s*[=(]\s*(req|request|params|searchParams)", "Possible open redirect"),
]
COMPILED = [(c, re.compile(p, re.IGNORECASE), w) for c, p, w in RULES]


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            ext = os.path.splitext(fn)[1].lower()
            if ext in EXTS or fn.startswith(".env"):
                p = os.path.join(dp, fn)
                try:
                    if os.path.getsize(p) <= MAX_BYTES:
                        yield p
                except OSError:
                    pass


def scan(root):
    hits = []
    for path in iter_files(root):
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for n, line in enumerate(f, 1):
                    if len(line) > 600:
                        continue  # minified/bundled
                    for cat, rx, why in COMPILED:
                        if rx.search(line):
                            hits.append({"file": path, "line": n, "category": cat,
                                         "why": why, "code": line.strip()[:160]})
        except OSError:
            continue
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    a = ap.parse_args()
    if not os.path.exists(a.path):
        sys.exit(f"Path not found: {a.path}")
    hits = scan(a.path)
    if a.format == "json":
        print(json.dumps(hits, indent=2))
        return
    if not hits:
        print("No signals found. This does not mean the code is secure; "
              "scanner only covers common patterns. Continue with manual tracing.")
        return
    print(f"# Triage signals ({len(hits)} leads, unverified)\n")
    by_cat = {}
    for h in hits:
        by_cat.setdefault(h["category"], []).append(h)
    for cat in sorted(by_cat):
        print(f"## {cat} ({len(by_cat[cat])})")
        for h in by_cat[cat]:
            print(f"- `{h['file']}:{h['line']}` {h['why']}\n  `{h['code']}`")
        print()


if __name__ == "__main__":
    main()
