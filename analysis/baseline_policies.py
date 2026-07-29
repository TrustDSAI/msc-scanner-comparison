#!/usr/bin/env python3
"""
baseline_policies.py — Compare p_gate's 30-image outcome (10 block / 18
review / 2 pass) against three single-scanner policies teams actually use:

  1. trivy --severity CRITICAL --exit-code 1  (block if Trivy reports any
     native CRITICAL finding)
  2. grype --fail-on critical                 (block if Grype reports any
     native CRITICAL finding)
  3. fixable-CRITICAL-only                    (block if either tool reports
     a native CRITICAL finding with a fix available)

All three read directly from the existing per-tool raw scan output in
data/raw/{trivy,grype}/ — no new scans needed, finding counts are
deterministic for a fixed digest+DB (Section 4.1.4 of the thesis).

Usage: python3 analysis/baseline_policies.py
"""
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.join(ROOT, "data", "raw")

IMAGES = [
    ("vulnerables_web-dvwa", "A"), ("bkimminich_juice-shop", "A"),
    ("v01_log4shell", "A"), ("v03_text4shell", "A"), ("v04_spring4shell", "A"),
    ("webgoat_webgoat", "A"), ("citizenstig_nowasp", "A"),
    ("nginx_1.19", "B"), ("node_14", "B"), ("python_3.8", "B"),
    ("golang_1.16-alpine", "B"), ("ruby_2.5-slim", "B"),
    ("eclipse-temurin_8-jre", "B"), ("dotnet_runtime_3.1", "B"),
    ("php_7.4-apache", "B"), ("rust_1.56-slim", "B"), ("node_12", "B"),
    ("python_2.7", "B"),
    ("alpine_3.19", "C"), ("nginx_1.29.7", "C"), ("node_20", "C"),
    ("python_3.12", "C"), ("golang_1.23-alpine", "C"), ("ruby_3.3-slim", "C"),
    ("eclipse-temurin_21-jre", "C"), ("dotnet_runtime_8.0", "C"),
    ("php_8.3-apache", "C"), ("rust_1.82-slim", "C"), ("node_22", "C"),
    ("python_3.13-slim", "C"),
]

# p_gate rule-classifier verdicts, Table 5.6 of the thesis (2026-06-21 run).
P_GATE_VERDICT = {
    "vulnerables_web-dvwa": "BLOCK", "bkimminich_juice-shop": "REVIEW",
    "v01_log4shell": "BLOCK", "v03_text4shell": "REVIEW",
    "v04_spring4shell": "BLOCK", "webgoat_webgoat": "BLOCK",
    "citizenstig_nowasp": "REVIEW",
    "nginx_1.19": "BLOCK", "node_14": "BLOCK", "python_3.8": "REVIEW",
    "golang_1.16-alpine": "REVIEW", "ruby_2.5-slim": "BLOCK",
    "eclipse-temurin_8-jre": "REVIEW", "dotnet_runtime_3.1": "REVIEW",
    "php_7.4-apache": "BLOCK", "rust_1.56-slim": "REVIEW",
    "node_12": "BLOCK", "python_2.7": "BLOCK",
    "alpine_3.19": "PASS", "nginx_1.29.7": "PASS", "node_20": "REVIEW",
    "python_3.12": "REVIEW", "golang_1.23-alpine": "REVIEW",
    "ruby_3.3-slim": "REVIEW", "eclipse-temurin_21-jre": "REVIEW",
    "dotnet_runtime_8.0": "REVIEW", "php_8.3-apache": "REVIEW",
    "rust_1.82-slim": "REVIEW", "node_22": "REVIEW",
    "python_3.13-slim": "REVIEW",
}


def trivy_criticals(safe):
    path = os.path.join(BASE, "trivy", f"{safe}_trivy.json")
    with open(path) as f:
        tj = json.load(f)
    out = []
    for r in tj.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            if (v.get("Severity", "").upper() == "CRITICAL"):
                out.append({"id": v.get("VulnerabilityID", ""),
                             "fixed": bool(v.get("FixedVersion"))})
    return out


def grype_criticals(safe):
    path = os.path.join(BASE, "grype", f"{safe}_grype.json")
    with open(path) as f:
        gj = json.load(f)
    out = []
    for m in gj.get("matches", []):
        v = m.get("vulnerability", {})
        if v.get("severity", "").upper() == "CRITICAL":
            fix = v.get("fix", {})
            out.append({"id": v.get("id", ""),
                         "fixed": fix.get("state", "") == "fixed"})
    return out


def main():
    rows = []
    for safe, group in IMAGES:
        t_crit = trivy_criticals(safe)
        g_crit = grype_criticals(safe)
        trivy_block = len(t_crit) > 0
        grype_block = len(g_crit) > 0
        fixable_block = any(c["fixed"] for c in t_crit) or any(c["fixed"] for c in g_crit)
        rows.append({
            "safe": safe, "group": group,
            "trivy_crit_n": len(t_crit), "grype_crit_n": len(g_crit),
            "trivy_block": trivy_block, "grype_block": grype_block,
            "fixable_block": fixable_block,
            "p_gate": P_GATE_VERDICT[safe],
        })

    print(f"{'Grp':<4}{'Image':<26}{'TrivyCrit':>10}{'GrypeCrit':>10}"
          f"{'trivy-CRIT':>12}{'grype-CRIT':>12}{'fixable-CRIT':>14}{'p_gate':>9}")
    for r in rows:
        print(f"{r['group']:<4}{r['safe']:<26}{r['trivy_crit_n']:>10}{r['grype_crit_n']:>10}"
              f"{('BLOCK' if r['trivy_block'] else 'pass'):>12}"
              f"{('BLOCK' if r['grype_block'] else 'pass'):>12}"
              f"{('BLOCK' if r['fixable_block'] else 'pass'):>14}"
              f"{r['p_gate']:>9}")

    n = len(rows)
    trivy_blocks = sum(r["trivy_block"] for r in rows)
    grype_blocks = sum(r["grype_block"] for r in rows)
    fixable_blocks = sum(r["fixable_block"] for r in rows)
    p_gate_blocks = sum(r["p_gate"] == "BLOCK" for r in rows)

    print(f"\nTotal images: {n}")
    print(f"trivy --severity CRITICAL --exit-code 1  blocks: {trivy_blocks}/{n}")
    print(f"grype --fail-on critical                  blocks: {grype_blocks}/{n}")
    print(f"fixable-CRITICAL-only (either tool)        blocks: {fixable_blocks}/{n}")
    print(f"p_gate (tri-state, rule classifier)        blocks: {p_gate_blocks}/{n}")

    # Disagreement: images where trivy-only and grype-only single-scanner
    # gates would reach a DIFFERENT block/pass decision from each other.
    disagree = [r for r in rows if r["trivy_block"] != r["grype_block"]]
    print(f"\nImages where trivy-only and grype-only single-scanner gates "
          f"DISAGREE on block/pass: {len(disagree)}/{n}")
    for r in disagree:
        print(f"  {r['group']}  {r['safe']:<26} trivy={'BLOCK' if r['trivy_block'] else 'pass':<6} "
              f"grype={'BLOCK' if r['grype_block'] else 'pass'}")


if __name__ == "__main__":
    main()
