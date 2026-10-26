#!/usr/bin/env python3
"""Heuristic scanner for client-side security leads.

Flags candidate lines for: DOM clobbering, prototype pollution, postMessage abuse,
window.opener/tabnabbing, clickjacking config, and iframe sandboxing mistakes.
Output is a list of LEADS to triage manually, not confirmed vulnerabilities.

Usage: python scan.py <path> [--json]
"""
import json
import os
import re
import sys

EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".htm", ".json", ".conf", ".toml", ".yml", ".yaml"}
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "coverage", ".vercel", "out"}

# (class, rule id, severity hint, regex, message)
RULES = [
    ("postmessage", "PM-LISTENER", "info", r"addEventListener\(\s*['\"]message['\"]|\.onmessage\s*=|on\(\s*['\"]message['\"]",
     "message listener: verify exact event.origin allowlist and data validation"),
    ("postmessage", "PM-WILDCARD", "medium", r"postMessage\([^)]*,\s*['\"]\*['\"]\s*\)",
     "postMessage with '*' target origin: do not send sensitive data"),
    ("postmessage", "PM-WEAK-ORIGIN", "high", r"origin\s*\.\s*(includes|indexOf|startsWith|endsWith|match)\(|origin\s*(==|===)\s*['\"]null['\"]",
     "weak origin check (substring/prefix/suffix/null): use exact allowlist match"),
    ("pollution", "PP-PROTO", "high", r"__proto__|constructor\s*\.\s*prototype|\[\s*['\"]constructor['\"]\s*\]",
     "direct prototype access: check for key filtering in merge/set paths"),
    ("pollution", "PP-MERGE", "medium", r"\b(_\.|lodash\.)?(merge|mergeWith|defaultsDeep|zipObjectDeep)\(|\$\.extend\(\s*true|deepMerge|recursiveMerge|deepExtend",
     "deep merge helper: confirm keys are not attacker-controlled or are filtered"),
    ("pollution", "PP-SET", "medium", r"\b(_\.|lodash\.)?set\(\s*\w+\s*,\s*[\w.\[\]'\"]+\s*,|dot-prop|objectPath\.set|setIn\(",
     "path-based setter: confirm path segments are validated"),
    ("pollution", "PP-DYNAMIC-KEY", "low", r"\w+\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*=",
     "nested dynamic-key assignment: possible pollution if both keys are user-controlled"),
    ("clobbering", "DC-GLOBAL-FALLBACK", "medium", r"window\.\w+\s*\|\|\s*|if\s*\(\s*!\s*window\.\w+\s*\)|typeof\s+window\.\w+\s*===?\s*['\"]undefined['\"]",
     "global read with fallback: clobberable if untrusted HTML with id/name is rendered"),
    ("clobbering", "DC-DOC-NAMED", "low", r"document\.(forms|anchors|images)\b|document\.getElementById\([^)]*\)\.(src|href|value)\b",
     "named DOM access without type check"),
    ("clobbering", "DC-HTML-SINK", "medium", r"dangerouslySetInnerHTML|v-html|\.innerHTML\s*=|insertAdjacentHTML|DOMPurify\.sanitize",
     "HTML rendering: check sanitizer config for id/name handling (SANITIZE_DOM / FORBID_ATTR)"),
    ("opener", "OP-BLANK-NO-REL", "low", r"target\s*[=:]\s*['\"]_blank['\"](?![^>\n]*rel\s*[=:]\s*['\"][^'\"]*noopener)",
     "target=_blank without rel=noopener on same line (check shared Link component / multi-line props)"),
    ("opener", "OP-WINDOW-OPEN", "medium", r"window\.open\((?![^)]*noopener)",
     "window.open without noopener feature: validate URL and sever opener"),
    ("opener", "OP-OPENER-USE", "medium", r"window\.opener|\bopener\.(location|postMessage)",
     "window.opener usage: verify origin checks and need"),
    ("clickjacking", "CJ-META-HEADER", "medium", r"<meta[^>]+http-equiv=['\"](X-Frame-Options|Content-Security-Policy)['\"][^>]*(frame-ancestors|DENY|SAMEORIGIN)",
     "framing protection via <meta> is ignored by browsers: set as HTTP header"),
    ("clickjacking", "CJ-FRAMEBUST-ONLY", "low", r"top\s*!==?\s*self|self\s*!==?\s*top|window\.top\s*!==?\s*window\.self|top\.location\s*=",
     "JS frame-busting: bypassable, must be paired with frame-ancestors header"),
    ("clickjacking", "CJ-ALLOW-ALL", "high", r"frame-ancestors[^;\"']*\*|X-Frame-Options['\"]?\s*[:,]\s*['\"]?ALLOW",
     "permissive framing policy"),
    ("iframe", "IF-NO-SANDBOX", "low", r"<iframe\b(?![^>]*\bsandbox\b)[^>]*>",
     "iframe without sandbox: acceptable only for trusted first-party content"),
    ("iframe", "IF-SCRIPTS-SAMEORIGIN", "high", r"sandbox\s*=\s*['\"][^'\"]*allow-scripts[^'\"]*allow-same-origin|sandbox\s*=\s*['\"][^'\"]*allow-same-origin[^'\"]*allow-scripts",
     "allow-scripts + allow-same-origin: sandbox is void if content is same-origin"),
    ("iframe", "IF-TOP-NAV", "medium", r"sandbox\s*=\s*['\"][^'\"]*allow-top-navigation(?!-by-user)",
     "allow-top-navigation lets framed content redirect the tab"),
    ("iframe", "IF-SRCDOC", "medium", r"srcdoc\s*=|\.srcdoc\s*=",
     "srcdoc content inherits parent origin if allow-same-origin is set"),
    ("iframe", "IF-DYNAMIC-SRC", "medium", r"createElement\(\s*['\"]iframe['\"]\s*\)|iframe\w*\.src\s*=",
     "dynamically created iframe: validate src (https + host allowlist) and apply sandbox"),
]

COMPILED = [(c, i, s, re.compile(p, re.I), m) for c, i, s, p, m in RULES]


def iter_files(root):
    if os.path.isfile(root):
        yield root
        return
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            if os.path.splitext(fn)[1].lower() in EXTS:
                yield os.path.join(dp, fn)


def scan_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    hits = []
    for n, line in enumerate(lines, 1):
        if len(line) > 600:  # skip minified lines
            continue
        for cls, rid, sev, rx, msg in COMPILED:
            if rx.search(line):
                hits.append({"file": path, "line": n, "class": cls, "rule": rid,
                             "severity_hint": sev, "message": msg, "code": line.strip()[:160]})
    return hits


def header_check(root):
    """Look for evidence of framing/COOP headers in config files."""
    found = {"frame-ancestors": False, "x-frame-options": False, "cross-origin-opener-policy": False}
    for p in iter_files(root):
        try:
            txt = open(p, "r", encoding="utf-8", errors="ignore").read().lower()
        except OSError:
            continue
        for k in found:
            if k in txt:
                found[k] = True
    return found


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_json = "--json" in sys.argv
    if not args:
        print(__doc__)
        sys.exit(2)
    root = args[0]
    hits = []
    for p in iter_files(root):
        hits.extend(scan_file(p))
    headers = header_check(root)
    if as_json:
        print(json.dumps({"hits": hits, "header_evidence": headers}, indent=2))
        return
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    hits.sort(key=lambda h: (order[h["severity_hint"]], h["class"], h["file"], h["line"]))
    print(f"{len(hits)} leads (heuristic; triage manually)\n")
    for h in hits:
        print(f"[{h['severity_hint'].upper():6}] {h['class']:12} {h['rule']:20} {h['file']}:{h['line']}")
        print(f"         {h['message']}")
        print(f"         > {h['code']}")
    print("\nHeader evidence found anywhere in project files (not proof it is applied):")
    for k, v in headers.items():
        print(f"  {k}: {'yes' if v else 'NOT FOUND - verify at server/CDN'}")


if __name__ == "__main__":
    main()
