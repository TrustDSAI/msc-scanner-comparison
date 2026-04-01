#!/usr/bin/env python3
"""
parse_results.py — Extract and summarise vulnerability scanner outputs.

Reads raw JSON from results/{trivy,grype,osv}/ and SBOMs from sbom/,
prints summary tables to stdout, and writes logs/parsed_results.json.

Usage:
    python3 parse_results.py

Paths are resolved relative to this script's location, so the script
works correctly regardless of the working directory.
"""

import json
import os
import sys

# ---------------------------------------------------------------------------
# Resolve base paths relative to this script, not the working directory
# ---------------------------------------------------------------------------
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
BASE        = os.path.join(SCRIPT_DIR, "results")
SBOM_BASE   = os.path.join(SCRIPT_DIR, "sbom")
OUTPUT_FILE = os.path.join(SCRIPT_DIR, "logs", "parsed_results.json")

# ---------------------------------------------------------------------------
# Image dataset
# (safe_name, full_image_reference, group)
# ---------------------------------------------------------------------------
IMAGES = [
    ("alpine_3.19",           "alpine:3.19",                "C"),
    ("nginx_latest",          "nginx:latest",               "C"),
    ("node_20",               "node:20",                    "C"),
    ("python_3.12",           "python:3.12",                "C"),
    ("nginx_1.19",            "nginx:1.19",                 "B"),
    ("node_14",               "node:14",                    "B"),
    ("python_3.8",            "python:3.8",                 "B"),
    ("vulnerables_web-dvwa",  "vulnerables/web-dvwa:latest","A"),
    ("bkimminich_juice-shop", "bkimminich/juice-shop:latest","A"),
]

# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def parse_trivy(safe):
    path = os.path.join(BASE, "trivy", f"{safe}_trivy.json")
    with open(path) as f:
        tj = json.load(f)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
              "UNKNOWN": 0, "total": 0, "fixed": 0}
    for result in tj.get("Results", []):
        for v in result.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
            counts["total"] += 1
            if v.get("FixedVersion"):
                counts["fixed"] += 1

    os_info = tj.get("Metadata", {}).get("OS", {})
    return counts, {
        "family":  os_info.get("Family", ""),
        "version": os_info.get("Name", "") or os_info.get("Version", ""),
        "eosl":    os_info.get("EOSL", False),
    }


def parse_grype(safe):
    path = os.path.join(BASE, "grype", f"{safe}_grype.json")
    with open(path) as f:
        gj = json.load(f)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0,
              "NEGLIGIBLE": 0, "UNKNOWN": 0, "total": 0, "fixed": 0}
    for match in gj.get("matches", []):
        vuln = match.get("vulnerability", {})
        sev = vuln.get("severity", "UNKNOWN").upper()
        counts[sev] = counts.get(sev, 0) + 1
        counts["total"] += 1
        if vuln.get("fix", {}).get("state", "") == "fixed":
            counts["fixed"] += 1

    return counts


def parse_osv(safe):
    """
    OSV-Scanner outputs advisory-level records (DSA/DLA/GHSA IDs), each of
    which may bundle multiple CVEs.  Per-finding severity is not available in
    this format, so only advisory and package-match counts are returned.
    Direct numerical comparison with Trivy/Grype CVE-level counts is not valid.
    """
    path = os.path.join(BASE, "osv", f"{safe}_osv.json")
    with open(path) as f:
        oj = json.load(f)

    advisory_ids = set()
    total_pkg_entries = 0
    for result in oj.get("results", []):
        for pkg in result.get("packages", []):
            for v in pkg.get("vulnerabilities", []):
                advisory_ids.add(v.get("id", ""))
                total_pkg_entries += 1

    return {"advisories": len(advisory_ids), "total": total_pkg_entries}


def parse_sbom(safe):
    path = os.path.join(SBOM_BASE, f"{safe}_syft.json")
    if not os.path.exists(path):
        return None, {}

    with open(path) as f:
        sj = json.load(f)

    pkgs = sj.get("artifacts", [])
    ecosystems = {}
    for p in pkgs:
        eco = p.get("type", "unknown")
        ecosystems[eco] = ecosystems.get(eco, 0) + 1

    return len(pkgs), ecosystems


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

results = []

for safe, image, group in IMAGES:
    row = {"safe": safe, "image": image, "group": group}

    try:
        trivy_counts, os_meta = parse_trivy(safe)
        row["trivy"] = trivy_counts
        row["os_family"]  = os_meta["family"]
        row["os_version"] = os_meta["version"]
        row["os_eosl"]    = os_meta["eosl"]
    except Exception as e:
        row["trivy"] = {"error": str(e)}
        print(f"[WARN] Trivy parse failed for {safe}: {e}", file=sys.stderr)

    try:
        row["grype"] = parse_grype(safe)
    except Exception as e:
        row["grype"] = {"error": str(e)}
        print(f"[WARN] Grype parse failed for {safe}: {e}", file=sys.stderr)

    try:
        row["osv"] = parse_osv(safe)
    except Exception as e:
        row["osv"] = {"error": str(e), "total": 0}
        print(f"[WARN] OSV parse failed for {safe}: {e}", file=sys.stderr)

    sbom_total, sbom_ecosystems = parse_sbom(safe)
    row["sbom_total"]      = sbom_total   # None if sbom/ not present
    row["sbom_ecosystems"] = sbom_ecosystems

    results.append(row)

# ---------------------------------------------------------------------------
# Print tables
# ---------------------------------------------------------------------------

print("=== TABLE 1: CORE VULNERABILITY COUNTS ===")
print(f"{'Image':<32} {'Grp'} {'Trivy':>6} {'Grype':>6} {'OSV*':>6}  "
      f"{'T:C/H/M/L':<18} {'G:C/H/M/L':<18} {'EOSL'}")
print("-" * 120)
for r in results:
    t = r.get("trivy", {})
    g = r.get("grype", {})
    o = r.get("osv",   {})
    tc = f"{t.get('CRITICAL',0)}/{t.get('HIGH',0)}/{t.get('MEDIUM',0)}/{t.get('LOW',0)}"
    gc = f"{g.get('CRITICAL',0)}/{g.get('HIGH',0)}/{g.get('MEDIUM',0)}/{g.get('LOW',0)}"
    eosl = "YES" if r.get("os_eosl") else "no"
    print(f"{r['image']:<32} {r['group']}   "
          f"{t.get('total',0):>6} {g.get('total',0):>6} {o.get('total',0):>6}  "
          f"{tc:<18} {gc:<18} {eosl}")

print("\n* OSV totals are advisory/package match counts "
      "(OSV format does not include per-finding severity)")

print("\n=== TABLE 2: FIXABLE VULNERABILITIES ===")
print(f"{'Image':<32} {'T:Total':>8} {'T:Fixed':>8} {'T:Fixed%':>9} "
      f"{'G:Total':>8} {'G:Fixed':>8} {'G:Fixed%':>9}")
print("-" * 90)
for r in results:
    t  = r.get("trivy", {})
    g  = r.get("grype", {})
    tt = t.get("total", 0)
    tf = t.get("fixed", 0)
    gt = g.get("total", 0)
    gf = g.get("fixed", 0)
    tp = f"{tf/tt*100:.0f}%" if tt > 0 else "n/a"
    gp = f"{gf/gt*100:.0f}%" if gt > 0 else "n/a"
    print(f"{r['image']:<32} {tt:>8} {tf:>8} {tp:>9} {gt:>8} {gf:>8} {gp:>9}")

print("\n=== TABLE 3: SBOM PACKAGE BASELINE ===")
print(f"{'Image':<32} {'Total Pkgs':>11}  {'Ecosystems'}")
print("-" * 90)
for r in results:
    ecos    = r.get("sbom_ecosystems", {})
    eco_str = ", ".join(
        f"{k}:{v}" for k, v in sorted(ecos.items(), key=lambda x: -x[1])
    )
    total = r.get("sbom_total")
    total_str = str(total) if total is not None else "n/a (sbom/ not present)"
    print(f"{r['image']:<32} {total_str:>11}  {eco_str}")

# ---------------------------------------------------------------------------
# Save structured JSON
# ---------------------------------------------------------------------------
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
with open(OUTPUT_FILE, "w") as f:
    json.dump(results, f, indent=2)
print(f"\nSaved: {OUTPUT_FILE}")
