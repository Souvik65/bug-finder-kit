#!/usr/bin/env python3
"""Merge, dedupe, and rank SARIF output from multiple SAST tools.

Usage:
    python sarif_summary.py semgrep.sarif bandit.sarif codeql.sarif \
        [--min-level note|warning|error] [--format markdown|json] [--top N]

Dedupe key: (file, start line, CWE or rule id). Findings reported by more than
one tool are merged and boosted in rank, since independent agreement is a good
signal of a true positive.
"""
import argparse
import json
import re
import sys
from collections import defaultdict

LEVEL_RANK = {"none": 0, "note": 1, "warning": 2, "error": 3}
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.I)


def extract_cwe(rule, result):
    """Find a CWE id in rule tags/properties/help text, if present."""
    blobs = []
    for obj in (rule or {}, result or {}):
        props = obj.get("properties", {}) or {}
        blobs.extend(str(t) for t in props.get("tags", []) or [])
        blobs.append(str(props.get("cwe", "")))
    blobs.append(json.dumps((rule or {}).get("relationships", "")))
    for b in blobs:
        m = CWE_RE.search(b)
        if m:
            return f"CWE-{m.group(1)}"
    return None


def effective_level(rule, result):
    level = result.get("level")
    if not level and rule:
        level = (rule.get("defaultConfiguration") or {}).get("level")
    level = level or "warning"
    # Prefer numeric security-severity when present (CodeQL, some Semgrep rules)
    sev = ((rule or {}).get("properties", {}) or {}).get("security-severity")
    try:
        sev = float(sev)
        level = "error" if sev >= 7.0 else "warning" if sev >= 4.0 else "note"
    except (TypeError, ValueError):
        pass
    return level


def load(paths):
    findings = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: skipping {path}: {exc}", file=sys.stderr)
            continue
        for run in doc.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            tool = driver.get("name", "unknown")
            rules = {r.get("id"): r for r in driver.get("rules", []) or []}
            for res in run.get("results", []) or []:
                rule = rules.get(res.get("ruleId"))
                locs = res.get("locations") or [{}]
                phys = locs[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "?")
                line = phys.get("region", {}).get("startLine", 0)
                findings.append(
                    {
                        "tool": tool,
                        "rule": res.get("ruleId", "?"),
                        "cwe": extract_cwe(rule, res),
                        "level": effective_level(rule, res),
                        "file": uri,
                        "line": line,
                        "message": (res.get("message", {}).get("text", "") or "").strip()[:200],
                        "has_flow": bool(res.get("codeFlows")),
                    }
                )
    return findings


def merge(findings):
    groups = defaultdict(list)
    for f in findings:
        groups[(f["file"], f["line"], f["cwe"] or f["rule"])].append(f)
    merged = []
    for (file, line, key), items in groups.items():
        tools = sorted({i["tool"] for i in items})
        level = max((i["level"] for i in items), key=lambda l: LEVEL_RANK.get(l, 0))
        score = LEVEL_RANK.get(level, 0) * 10 + (len(tools) - 1) * 5 + (2 if any(i["has_flow"] for i in items) else 0)
        merged.append(
            {
                "file": file,
                "line": line,
                "key": key,
                "cwe": items[0]["cwe"],
                "level": level,
                "tools": tools,
                "rules": sorted({i["rule"] for i in items}),
                "has_flow": any(i["has_flow"] for i in items),
                "message": items[0]["message"],
                "score": score,
            }
        )
    merged.sort(key=lambda m: (-m["score"], m["file"], m["line"]))
    return merged


def to_markdown(merged, top):
    by_level = defaultdict(int)
    for m in merged:
        by_level[m["level"]] += 1
    out = ["# SAST findings summary", ""]
    out.append(
        f"Total unique findings: **{len(merged)}** "
        f"(error: {by_level['error']}, warning: {by_level['warning']}, note: {by_level['note']})"
    )
    multi = [m for m in merged if len(m["tools"]) > 1]
    out.append(f"Reported by 2+ tools: **{len(multi)}** (triage these first)\n")
    out.append("| # | Level | CWE / rule | Location | Tools | Flow |")
    out.append("|---|-------|-----------|----------|-------|------|")
    for i, m in enumerate(merged[:top], 1):
        out.append(
            f"| {i} | {m['level']} | {m['key']} | `{m['file']}:{m['line']}` | "
            f"{', '.join(m['tools'])} | {'yes' if m['has_flow'] else '-'} |"
        )
    if len(merged) > top:
        out.append(f"\n_{len(merged) - top} more not shown (use --top)._")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sarif", nargs="+")
    ap.add_argument("--min-level", default="note", choices=["note", "warning", "error"])
    ap.add_argument("--format", default="markdown", choices=["markdown", "json"])
    ap.add_argument("--top", type=int, default=50)
    args = ap.parse_args()

    findings = [f for f in load(args.sarif) if LEVEL_RANK.get(f["level"], 0) >= LEVEL_RANK[args.min_level]]
    merged = merge(findings)
    if args.format == "json":
        json.dump(merged, sys.stdout, indent=2)
        print()
    else:
        print(to_markdown(merged, args.top))
    # Non-zero exit if any error-level finding, handy as a CI gate
    sys.exit(1 if any(m["level"] == "error" for m in merged) else 0)


if __name__ == "__main__":
    main()
