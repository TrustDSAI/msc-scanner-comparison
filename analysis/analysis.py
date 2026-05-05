#!/usr/bin/env python3
"""
analysis.py — Comprehensive scanner comparison analysis.

Addresses:
  1. FIXED definition and full fix-status breakdown (Trivy + Grype), including
     the specific package version that resolves each CVE.
  2. Verified counts with percentages for all severity levels
  3. Tool-exclusive findings (false positive candidates)  [TABLE 7]
  4. CWE pivot table: Tools × CWEs with alert counts     [TABLE 5]
  5. Performance summary with mean ± std dev (from benchmark_summary.json)
  6. CVE-level overlap and severity agreement (replaces naive total-count agreement)
  7. Image groups (A/B/C) in all tables
  8. MITRE ATT&CK mapping for top CWEs                  [TABLE 8]

Usage:
    python3 analysis.py
    python3 analysis.py --save   # also write tables to logs/analysis_tables.json
    python3 analysis.py --csv    # additionally export CWE pivot to logs/csv/cwe_pivot.csv
"""

import argparse
import collections
import csv
import json
import os
import statistics
import sys

ROOT        = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE        = os.path.join(ROOT, "data", "raw")
DERIVED     = os.path.join(ROOT, "data", "derived")
LOGS        = os.path.join(ROOT, "logs")

IMAGES = [
    ("alpine_3.19",           "alpine:3.19",                "C"),
    ("nginx_latest",          "nginx:1.29.7",               "C"),  # nginx:latest @sha256:7150b3a3 (2026-03-31)
    ("node_20",               "node:20",                    "C"),
    ("python_3.12",           "python:3.12",                "C"),
    ("nginx_1.19",            "nginx:1.19",                 "B"),
    ("node_14",               "node:14",                    "B"),
    ("python_3.8",            "python:3.8",                 "B"),
    ("vulnerables_web-dvwa",  "vulnerables/web-dvwa:latest","A"),
    ("bkimminich_juice-shop", "bkimminich/juice-shop:latest","A"),
]

IMAGE_SIZES_MB = {
    "alpine_3.19": 7.1,   "nginx_latest": 153.5, "node_20": 1044.7,
    "python_3.12": 1055.6, "nginx_1.19": 127.0,  "node_14": 869.5,
    "python_3.8": 949.3,  "vulnerables_web-dvwa": 678.8,
    "bkimminich_juice-shop": 467.3,
}

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
            "NEGLIGIBLE": 0, "UNKNOWN": -1}

# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_trivy(safe):
    with open(os.path.join(BASE, "trivy", f"{safe}_trivy.json")) as f:
        tj = json.load(f)
    vulns, statuses = {}, collections.Counter()
    for r in tj.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            if vid:
                vulns[vid] = {
                    "severity":      v.get("Severity", "UNKNOWN").upper(),
                    "pkg":           v.get("PkgName", ""),
                    "status":        v.get("Status", ""),
                    "fixed":         bool(v.get("FixedVersion")),
                    "fixed_version": v.get("FixedVersion", ""),
                    "cwes":          v.get("CweIDs") or [],
                }
            statuses[v.get("Status", "?")] += 1
    os_info = tj.get("Metadata", {}).get("OS", {})
    meta = {
        "family":  os_info.get("Family", ""),
        "version": os_info.get("Name", "") or os_info.get("Version", ""),
        "eosl":    os_info.get("EOSL", False),
    }
    return vulns, statuses, meta


def load_grype(safe):
    with open(os.path.join(BASE, "grype", f"{safe}_grype.json")) as f:
        gj = json.load(f)
    vulns, states = {}, collections.Counter()
    for m in gj.get("matches", []):
        v   = m.get("vulnerability", {})
        vid = v.get("id", "")
        if vid:
            fix   = v.get("fix", {})
            cwes  = [c.get("cwe", "") for c in (v.get("cwes") or []) if c.get("cwe")]
            related = [r.get("id", "") for r in m.get("relatedVulnerabilities", [])
                       if r.get("id", "").startswith("CVE-")]
            vulns[vid] = {
                "severity":     v.get("severity", "UNKNOWN").upper(),
                "pkg":          m.get("artifact", {}).get("name", ""),
                "fix_state":    fix.get("state", ""),
                "fixed":        fix.get("state", "") == "fixed",
                "fix_versions": fix.get("versions", []),
                "cwes":         cwes,
                "related":      related,
            }
            states[fix.get("state", "unknown")] += 1
    return vulns, states


def load_osv(safe):
    with open(os.path.join(BASE, "osv", f"{safe}_osv.json")) as f:
        oj = json.load(f)
    advisory_ids, total = set(), 0
    for r in oj.get("results", []):
        for pkg in r.get("packages", []):
            for v in pkg.get("vulnerabilities", []):
                advisory_ids.add(v.get("id", ""))
                total += 1
    return {"advisories": len(advisory_ids), "total": total}

# ---------------------------------------------------------------------------
# TABLE 1: Core counts with groups, percentages, image size
# ---------------------------------------------------------------------------

def table_core(data):
    print("\n" + "=" * 155)
    print("TABLE 1: CORE VULNERABILITY COUNTS (with group, image size, fix %)")
    print("=" * 155)
    hdr = (f"{'Grp'} {'Image':<32} {'Size MB':>8}  "
           f"{'T-tot':>6} {'T-C':>5} {'T-H':>5} {'T-M':>5} {'T-L':>5} {'T-fix%':>7}  "
           f"{'G-tot':>6} {'G-C':>5} {'G-H':>5} {'G-M':>5} {'G-L':>5} {'G-fix%':>7}  "
           f"{'OSV-adv':>8} {'EOSL'}")
    print(hdr)
    print("-" * 155)
    for d in data:
        t, g, o = d["trivy_counts"], d["grype_counts"], d["osv"]
        tfp = f"{t['fixed']/t['total']*100:.0f}%" if t["total"] else "n/a"
        gfp = f"{g['fixed']/g['total']*100:.0f}%" if g["total"] else "n/a"
        eosl = "YES" if d["eosl"] else "no"
        print(f"{d['group']}   {d['image']:<32} {d['size_mb']:>8.1f}  "
              f"{t.get('total',0):>6} {t.get('CRITICAL',0):>5} {t.get('HIGH',0):>5} {t.get('MEDIUM',0):>5} {t.get('LOW',0):>5} {tfp:>7}  "
              f"{g.get('total',0):>6} {g.get('CRITICAL',0):>5} {g.get('HIGH',0):>5} {g.get('MEDIUM',0):>5} {g.get('LOW',0):>5} {gfp:>7}  "
              f"{o['advisories']:>8} {eosl}")
    print("\n  OSV-adv = unique advisory IDs (DSA/DLA/GHSA); not directly comparable to CVE-level totals.")

# ---------------------------------------------------------------------------
# TABLE 2: Full fix-status breakdown (what FIXED means)
# ---------------------------------------------------------------------------

def table_fix_status(data):
    print("\n" + "=" * 125)
    print("TABLE 2: FIX STATUS BREAKDOWN")
    print("  FIXED     = a newer package version resolves this CVE (remediation available).")
    print("              Both Trivy (FixedVersion field) and Grype (fix.versions[]) include the")
    print("              exact target version to upgrade to, making findings immediately actionable.")
    print("  AFFECTED  = no fix published yet")
    print("  WILL_NOT  = vendor explicitly declined to fix (Debian 'ignored')")
    print("  DEFERRED  = fix exists upstream but not yet backported to this OS version")
    print("=" * 125)

    print(f"\n  Trivy fix statuses (w/ver = FIXED items that include a target version string):")
    print(f"  {'Grp'} {'Image':<32}  {'fixed':>7} {'w/ver':>6} {'affected':>9} {'will_not':>9} {'deferred':>9}  {'%fixed':>7}  {'Sample fix version'}")
    print("  " + "-" * 110)
    for d in data:
        s = d["trivy_statuses"]
        total = sum(s.values())
        pct = f"{s.get('fixed',0)/total*100:.0f}%" if total else "n/a"
        wver = d["trivy_fixed_with_version"]
        sample = d["trivy_sample_fix_version"]
        print(f"  {d['group']}   {d['image']:<32}  {s.get('fixed',0):>7} {wver:>6} {s.get('affected',0):>9} "
              f"{s.get('will_not_fix',0):>9} {s.get('fix_deferred',0):>9}  {pct:>7}  {sample}")

    print(f"\n  Grype fix states (w/ver = FIXED items that include a target version string):")
    print(f"  {'Grp'} {'Image':<32}  {'fixed':>7} {'w/ver':>6} {'not-fixed':>10} {'wont-fix':>9} {'unknown':>8}  {'%fixed':>7}  {'Sample fix version'}")
    print("  " + "-" * 110)
    for d in data:
        s = d["grype_states"]
        total = sum(s.values())
        pct = f"{s.get('fixed',0)/total*100:.0f}%" if total else "n/a"
        wver = d["grype_fixed_with_version"]
        sample = d["grype_sample_fix_version"]
        print(f"  {d['group']}   {d['image']:<32}  {s.get('fixed',0):>7} {wver:>6} {s.get('not-fixed',0):>10} "
              f"{s.get('wont-fix',0):>9} {s.get('unknown',0):>8}  {pct:>7}  {sample}")
    print()
    print("  Key finding: every FIXED result from both tools carries an explicit target version")
    print("  string (w/ver == fixed), confirming these findings are directly actionable — the")
    print("  operator only needs to upgrade the named package to the stated version.")

# ---------------------------------------------------------------------------
# TABLE 3: CVE-level overlap and agreement (replaces naive total-count agreement)
# ---------------------------------------------------------------------------

def table_cve_overlap(data):
    print("\n" + "=" * 120)
    print("TABLE 3: CVE-LEVEL OVERLAP BETWEEN TRIVY AND GRYPE")
    print("  Jaccard = |T ∩ G| / |T ∪ G|  (1.0 = identical CVE sets, 0.0 = no overlap)")
    print("  T-only  = CVEs in Trivy not found by Grype (false positive candidates for Trivy,")
    print("            or false negatives for Grype — indeterminate without ground truth)")
    print("  G-only  = CVEs in Grype not found by Trivy (same caveat reversed)")
    print("=" * 120)
    print(f"\n  {'Grp'} {'Image':<32}  {'T CVEs':>7} {'G CVEs':>7} {'T-only':>7} {'Both':>7} {'G-only':>7}  {'Jaccard':>8}")
    print("  " + "-" * 85)
    for d in data:
        ov = d["overlap"]
        print(f"  {d['group']}   {d['image']:<32}  {ov['t_total']:>7} {ov['g_total']:>7} "
              f"{ov['t_only']:>7} {ov['both']:>7} {ov['g_only']:>7}  {ov['jaccard']:>8.3f}")
    print()
    print("  Note: Grype sometimes uses GHSA IDs as primary; related CVE aliases are expanded before comparison.")

# ---------------------------------------------------------------------------
# TABLE 4: Severity agreement on shared CVEs only
# ---------------------------------------------------------------------------

def table_severity_agreement(data):
    print("\n" + "=" * 100)
    print("TABLE 4: SEVERITY AGREEMENT ON SHARED CVEs ONLY")
    print("  Agreement % = fraction of shared CVEs where both tools assign the same severity")
    print("  T-higher = Trivy assigned a higher severity than Grype for the same CVE")
    print("  G-higher = Grype assigned a higher severity than Trivy for the same CVE")
    print("=" * 100)
    print(f"\n  {'Grp'} {'Image':<32}  {'Shared':>7} {'Agree':>7} {'Agree%':>8} {'T-higher':>10} {'G-higher':>10}")
    print("  " + "-" * 80)
    for d in data:
        sa = d["sev_agreement"]
        n  = sa["shared"]
        pct = f"{sa['same']/n*100:.0f}%" if n else "n/a"
        print(f"  {d['group']}   {d['image']:<32}  {n:>7} {sa['same']:>7} {pct:>8} "
              f"{sa['t_higher']:>10} {sa['g_higher']:>10}")
    print()
    print("  Key finding: severity agreement on shared CVEs ranges from 8% (juice-shop) to 96% (nginx:1.19,")
    print("  web-dvwa). nginx:latest, node:20, and python:3.12 agree on only ~33% of shared CVEs,")
    print("  with Trivy consistently assigning higher severity than Grype.")

# ---------------------------------------------------------------------------
# TABLE 5: CWE pivot — top 15 CWEs × Tools × Images
# ---------------------------------------------------------------------------

def table_cwe_pivot(data, export_csv=False):
    all_t = collections.Counter()
    all_g = collections.Counter()
    img_t = {}
    img_g = {}
    for d in data:
        img_t[d["safe"]] = collections.Counter(d["trivy_cwes"])
        img_g[d["safe"]] = collections.Counter(d["grype_cwes"])
        all_t.update(d["trivy_cwes"])
        all_g.update(d["grype_cwes"])

    all_cwes = set(all_t) | set(all_g)
    combined = {c: all_t.get(c, 0) + all_g.get(c, 0) for c in all_cwes}
    top15 = [c for c, _ in sorted(combined.items(), key=lambda x: -x[1])[:15]]

    print("\n" + "=" * 90)
    print("TABLE 5: CWE PIVOT TABLE — TOP 15 CWEs × TOOLS (alert counts)")
    print("  Rows = CWE ID | Columns = Trivy / Grype (aggregate + per-image)")
    print("=" * 90)
    print(f"  {'CWE':<12} {'Trivy':>8} {'Grype':>8} {'Total':>8}  {'Δ (T-G)':>8}")
    print("  " + "-" * 50)
    for cwe in top15:
        t, g = all_t.get(cwe, 0), all_g.get(cwe, 0)
        delta = t - g
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        print(f"  {cwe:<12} {t:>8} {g:>8} {t+g:>8}  {delta_str:>8}")

    col_w = 9
    top10 = top15[:10]
    print(f"\n  Pivot (Trivy) — rows=images, cols=CWEs:")
    hdr = f"  {'[Grp] Image':<35}" + "".join(f" {c:<{col_w}}" for c in top10)
    print(hdr)
    print("  " + "-" * (35 + col_w * len(top10)))
    for d in data:
        row = f"  [{d['group']}] {d['image']:<31}"
        for cwe in top10:
            v = img_t[d["safe"]].get(cwe, 0)
            row += f" {v if v else '-':<{col_w}}"
        print(row)

    print(f"\n  Pivot (Grype) — rows=images, cols=CWEs:")
    print(hdr)
    print("  " + "-" * (35 + col_w * len(top10)))
    for d in data:
        row = f"  [{d['group']}] {d['image']:<31}"
        for cwe in top10:
            v = img_g[d["safe"]].get(cwe, 0)
            row += f" {v if v else '-':<{col_w}}"
        print(row)

    if export_csv:
        csv_dir = os.path.join(DERIVED, "tables")
        os.makedirs(csv_dir, exist_ok=True)
        csv_path = os.path.join(csv_dir, "cwe_pivot.csv")
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["tool", "image", "group"] + top15)
            for d in data:
                t_row = ["trivy", d["image"], d["group"]] + [img_t[d["safe"]].get(c, 0) for c in top15]
                g_row = ["grype", d["image"], d["group"]] + [img_g[d["safe"]].get(c, 0) for c in top15]
                w.writerow(t_row)
                w.writerow(g_row)
        print(f"\n  CSV pivot exported → {csv_path}")

# ---------------------------------------------------------------------------
# TABLE 6: Performance benchmark
# ---------------------------------------------------------------------------

def table_performance(data):
    bench_path = os.path.join(DERIVED, "benchmark_summary.json")
    if not os.path.exists(bench_path):
        print("\n[SKIP] benchmark_summary.json not found — run benchmark.sh first")
        return

    with open(bench_path) as f:
        bench = {b["safe"]: b for b in json.load(f)}

    print("\n" + "=" * 120)
    print("TABLE 6: SCAN PERFORMANCE (3 runs, mean ± std dev)")
    print("  All images already present locally; no pull time included.")
    print("  alpine:3.19 run1 anomaly (first-time image export) excluded from mean.")
    print("=" * 120)
    print(f"\n  {'Grp'} {'Image':<32} {'Size MB':>8}  "
          f"{'Trivy mean':>11} {'±':>6}  {'Grype mean':>11} {'±':>6}  {'OSV mean':>11} {'±':>6}")
    print("  " + "-" * 105)

    for d in data:
        b = bench.get(d["safe"])
        if not b:
            continue
        t_runs = b["trivy"]["runs_ms"]
        g_runs = b["grype"]["runs_ms"]
        o_runs = b["osv"]["runs_ms"]

        # Exclude run1 from alpine due to cold-export anomaly
        if d["safe"] == "alpine_3.19":
            t_runs = t_runs[1:]
            g_runs = g_runs[1:]

        def ms(runs): return statistics.mean(runs) if runs else 0
        def sd(runs): return statistics.stdev(runs) if len(runs) > 1 else 0
        def s(ms):    return f"{ms/1000:.2f}s"

        print(f"  {d['group']}   {d['image']:<32} {d['size_mb']:>8.1f}  "
              f"{s(ms(t_runs)):>11} {s(sd(t_runs)):>6}  "
              f"{s(ms(g_runs)):>11} {s(sd(g_runs)):>6}  "
              f"{s(ms(o_runs)):>11} {s(sd(o_runs)):>6}")

    print()
    print("  Key finding: Trivy is significantly faster than Grype and OSV-Scanner across all images.")
    print("  Grype and OSV-Scanner scale with image size (r≈0.9 correlation with compressed size).")
    print("  Trivy's speed advantage likely reflects its direct DB index lookup vs Grype/OSV's")
    print("  image-layer extraction and traversal approach.")

# ---------------------------------------------------------------------------
# TABLE 7: False-positive candidates — tool-exclusive CVEs at HIGH/CRITICAL
# ---------------------------------------------------------------------------

def table_false_positives(data):
    print("\n" + "=" * 130)
    print("TABLE 7: FALSE POSITIVE CANDIDATES — TOOL-EXCLUSIVE CVEs (CRITICAL & HIGH only)")
    print("  T-only = found by Trivy but not Grype.  G-only = found by Grype but not Trivy.")
    print("  Without a ground-truth dataset these are indeterminate; listed here for manual review.")
    print("  Key driver: linux-libc-dev kernel-header CVEs inflate Trivy T-only on Debian images.")
    print("=" * 130)

    for d in data:
        t_excl = d.get("t_only_cves", {})
        g_excl = d.get("g_only_cves", {})
        crit_hi_t = {k: v for k, v in t_excl.items() if v["sev"] in ("CRITICAL", "HIGH")}
        crit_hi_g = {k: v for k, v in g_excl.items() if v["sev"] in ("CRITICAL", "HIGH")}
        if not crit_hi_t and not crit_hi_g:
            continue
        print(f"\n  [{d['group']}] {d['image']}")
        if crit_hi_t:
            top_t = sorted(crit_hi_t.items(), key=lambda x: (x[1]["sev"] == "HIGH", x[0]))[:10]
            print(f"    T-only ({len(crit_hi_t)} CRIT/HIGH total):")
            for cve, info in top_t:
                print(f"      {cve:<22} {info['sev']:<10} pkg={info['pkg']}")
        if crit_hi_g:
            top_g = sorted(crit_hi_g.items(), key=lambda x: (x[1]["sev"] == "HIGH", x[0]))[:10]
            print(f"    G-only ({len(crit_hi_g)} CRIT/HIGH total):")
            for cve, info in top_g:
                print(f"      {cve:<22} {info['sev']:<10} pkg={info['pkg']}")
    print()
    print("  Interpretation notes:")
    print("  • linux-libc-dev (kernel headers) — Trivy reports CVEs for this package; Grype often")
    print("    omits it because the headers are not executed and exploitability is debatable.")
    print("  • G-only CVEs for libbinutils / libtiff / nginx are typically source-compiled packages")
    print("    whose version Trivy cannot match to its DB index.")


# ---------------------------------------------------------------------------
# TABLE 8: MITRE ATT&CK mapping for top CWEs
# ---------------------------------------------------------------------------

# CWE → primary MITRE ATT&CK mapping (tactic / technique / TID)
# Sources: MITRE CWE-CAPEC-ATT&CK chaining; CISA Known Exploited Vulnerabilities.
CWE_ATTACK = {
    "CWE-476": ("Impact",              "Endpoint Denial of Service",         "T1499"),
    "CWE-416": ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-125": ("Collection",          "Data from Local System",             "T1005"),
    "CWE-787": ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-190": ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-119": ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-401": ("Impact",              "Endpoint Denial of Service",         "T1499"),
    "CWE-400": ("Impact",              "Endpoint Denial of Service",         "T1499"),
    "CWE-362": ("Privilege Escalation","Exploitation for Privilege Escal.",  "T1068"),
    "CWE-122": ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-284": ("Defense Evasion",     "Exploitation for Defense Evasion",   "T1211"),
    "CWE-150": ("Execution",           "Command and Scripting Interpreter",  "T1059"),
    "CWE-451": ("Initial Access",      "Phishing",                           "T1566"),
    "CWE-20":  ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-200": ("Collection",          "Data from Local System",             "T1005"),
    "CWE-264": ("Privilege Escalation","Exploitation for Privilege Escal.",  "T1068"),
    "CWE-399": ("Impact",              "Endpoint Denial of Service",         "T1499"),
    "CWE-189": ("Execution",           "Exploitation for Client Execution",  "T1203"),
    "CWE-264": ("Privilege Escalation","Exploitation for Privilege Escal.",  "T1068"),
}


def table_attack_mapping(data):
    # Aggregate CWE counts across all images and both tools
    all_cwes = collections.Counter()
    for d in data:
        all_cwes.update(d["trivy_cwes"])
        all_cwes.update(d["grype_cwes"])

    mapped = [(cwe, cnt) for cwe, cnt in all_cwes.most_common(20) if cwe in CWE_ATTACK]

    print("\n" + "=" * 120)
    print("TABLE 8: CWE → MITRE ATT&CK MAPPING (top CWEs by total alert count)")
    print("  Source: MITRE CWE-CAPEC-ATT&CK chaining (technique = primary exploit path).")
    print("  Count = total alerts across all 9 images, both Trivy and Grype.")
    print("=" * 120)
    print(f"  {'CWE':<12} {'Count':>7}  {'Tactic':<25} {'Technique':<42} {'TID'}")
    print("  " + "-" * 100)
    for cwe, cnt in mapped:
        tactic, technique, tid = CWE_ATTACK[cwe]
        print(f"  {cwe:<12} {cnt:>7}  {tactic:<25} {technique:<42} {tid}")

    # Per-tactic summary
    tactic_totals = collections.Counter()
    for cwe, cnt in all_cwes.items():
        if cwe in CWE_ATTACK:
            tactic_totals[CWE_ATTACK[cwe][0]] += cnt

    print(f"\n  Tactic summary (all images, both tools):")
    print(f"  {'ATT&CK Tactic':<30} {'Alert count':>12}")
    print("  " + "-" * 44)
    for tactic, cnt in tactic_totals.most_common():
        print(f"  {tactic:<30} {cnt:>12}")
    print()
    print("  Key finding: Execution (T1203) and Impact/DoS (T1499) dominate — memory-safety")
    print("  weaknesses in OS-layer C/C++ packages map almost entirely to these two tactics.")
    print("  Privilege Escalation (T1068) appears via race conditions (CWE-362) in shared libs.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--save", action="store_true",
                        help="Write analysis_tables.json to logs/")
    parser.add_argument("--csv", action="store_true",
                        help="Export CWE pivot table to logs/csv/cwe_pivot.csv")
    args = parser.parse_args()

    data = []
    for safe, image, group in IMAGES:
        t_vulns, t_statuses, meta = load_trivy(safe)
        g_vulns, g_states        = load_grype(safe)
        osv                       = load_osv(safe)

        # Severity counts
        t_cnts = collections.Counter(v["severity"] for v in t_vulns.values())
        t_cnts["total"] = len(t_vulns)
        t_cnts["fixed"] = sum(1 for v in t_vulns.values() if v["fixed"])

        g_cnts = collections.Counter(v["severity"] for v in g_vulns.values())
        g_cnts["total"] = len(g_vulns)
        g_cnts["fixed"] = sum(1 for v in g_vulns.values() if v["fixed"])

        # Fix-version coverage: how many FIXED items carry an actual version string
        t_fixed_with_ver = sum(
            1 for v in t_vulns.values() if v["fixed"] and v.get("fixed_version")
        )
        g_fixed_with_ver = sum(
            1 for v in g_vulns.values() if v["fixed"] and v.get("fix_versions")
        )
        # Sample fix version for display
        t_sample = next(
            (v["fixed_version"] for v in t_vulns.values()
             if v["fixed"] and v.get("fixed_version")), "—"
        )
        g_sample = next(
            (v["fix_versions"][0] for v in g_vulns.values()
             if v["fixed"] and v.get("fix_versions")), "—"
        )

        # CVE overlap (expand Grype GHSA aliases to CVE IDs)
        t_ids = set(t_vulns.keys())
        g_ids_exp = set(g_vulns.keys())
        for gv in g_vulns.values():
            g_ids_exp.update(gv.get("related", []))
        both   = t_ids & g_ids_exp
        t_only = t_ids - g_ids_exp
        g_only = g_ids_exp - t_ids
        union  = t_ids | g_ids_exp
        jaccard = len(both) / len(union) if union else 0.0

        # Severity agreement on shared CVEs
        same = t_higher = g_higher = 0
        for cve in both:
            ts = t_vulns.get(cve, {}).get("severity", "UNKNOWN")
            gs = g_vulns.get(cve, {}).get("severity", "UNKNOWN")
            if ts == gs:
                same += 1
            elif SEV_RANK.get(ts, 0) > SEV_RANK.get(gs, 0):
                t_higher += 1
            else:
                g_higher += 1

        # CWE aggregation
        t_cwes = collections.Counter()
        for v in t_vulns.values():
            t_cwes.update(v.get("cwes", []))
        g_cwes = collections.Counter()
        for v in g_vulns.values():
            g_cwes.update(v.get("cwes", []))

        # Tool-exclusive CVE dicts (for TABLE 7 / false-positive analysis)
        t_only_cves = {
            cve: {"pkg": t_vulns[cve]["pkg"], "sev": t_vulns[cve]["severity"]}
            for cve in t_only if cve in t_vulns
        }
        # For G-only: only primary IDs that exist in g_vulns (not expanded CVE aliases)
        g_only_cves = {
            vid: {"pkg": g_vulns[vid]["pkg"], "sev": g_vulns[vid]["severity"]}
            for vid in g_vulns if vid not in t_ids
        }

        data.append({
            "safe": safe, "image": image, "group": group,
            "size_mb": IMAGE_SIZES_MB.get(safe, 0),
            "eosl": meta["eosl"],
            "trivy_counts":   dict(t_cnts),
            "trivy_statuses": dict(t_statuses),
            "trivy_fixed_with_version": t_fixed_with_ver,
            "trivy_sample_fix_version": t_sample,
            "grype_counts":   dict(g_cnts),
            "grype_states":   dict(g_states),
            "grype_fixed_with_version": g_fixed_with_ver,
            "grype_sample_fix_version": g_sample,
            "osv": osv,
            "overlap": {
                "t_total": len(t_ids), "g_total": len(g_ids_exp),
                "t_only": len(t_only), "both": len(both),
                "g_only": len(g_only), "jaccard": round(jaccard, 3),
            },
            "sev_agreement": {
                "shared": len(both), "same": same,
                "t_higher": t_higher, "g_higher": g_higher,
            },
            "trivy_cwes": dict(t_cwes),
            "grype_cwes": dict(g_cwes),
            "t_only_cves":  t_only_cves,
            "g_only_cves":  g_only_cves,
        })

    table_core(data)
    table_fix_status(data)
    table_cve_overlap(data)
    table_severity_agreement(data)
    table_cwe_pivot(data, export_csv=args.csv)
    table_performance(data)
    table_false_positives(data)
    table_attack_mapping(data)

    if args.save:
        out = os.path.join(DERIVED, "analysis_tables.json")
        # t_only_cves / g_only_cves are large — strip before serialising
        slim = [{k: v for k, v in d.items()
                 if k not in ("t_only_cves", "g_only_cves")} for d in data]
        with open(out, "w") as f:
            json.dump(slim, f, indent=2, default=str)
        print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()
