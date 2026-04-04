#!/usr/bin/env python3
"""
export_csv.py — Export all analysis tables and experiment log datasets to CSV.

Outputs to logs/csv/:
  From analysis.py data:
    table1_core_counts.csv
    table2_fix_status_trivy.csv
    table2_fix_status_grype.csv
    table3_cve_overlap.csv
    table4_severity_agreement.csv
    table5_cwe_pivot.csv
    table5_cwe_per_image_trivy.csv
    table5_cwe_per_image_grype.csv
    table6_performance.csv

  From experiment log datasets:
    D1_core_results.csv
    D2_performance_original.csv
    D3_sbom_baseline.csv
    D4_policy_evaluation.csv
"""

import collections
import csv
import json
import os
import statistics

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE       = os.path.join(SCRIPT_DIR, "results")
LOGS       = os.path.join(SCRIPT_DIR, "logs")
CSV_DIR    = os.path.join(LOGS, "csv")
os.makedirs(CSV_DIR, exist_ok=True)

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

IMAGE_SIZES_MB = {
    "alpine_3.19": 7.1,   "nginx_latest": 153.5, "node_20": 1044.7,
    "python_3.12": 1055.6, "nginx_1.19": 127.0,  "node_14": 869.5,
    "python_3.8": 949.3,  "vulnerables_web-dvwa": 678.8,
    "bkimminich_juice-shop": 467.3,
}

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1,
            "NEGLIGIBLE": 0, "UNKNOWN": -1}

# ---------------------------------------------------------------------------
# Loaders (same as analysis.py)
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
                    "severity": v.get("Severity", "UNKNOWN").upper(),
                    "pkg":      v.get("PkgName", ""),
                    "status":   v.get("Status", ""),
                    "fixed":    bool(v.get("FixedVersion")),
                    "cwes":     v.get("CweIDs") or [],
                }
            statuses[v.get("Status", "?")] += 1
    os_info = tj.get("Metadata", {}).get("OS", {})
    return vulns, statuses, os_info.get("EOSL", False)


def load_grype(safe):
    with open(os.path.join(BASE, "grype", f"{safe}_grype.json")) as f:
        gj = json.load(f)
    vulns, states = {}, collections.Counter()
    for m in gj.get("matches", []):
        v   = m.get("vulnerability", {})
        vid = v.get("id", "")
        if vid:
            fix    = v.get("fix", {})
            cwes   = [c.get("cwe", "") for c in (v.get("cwes") or []) if c.get("cwe")]
            related = [r.get("id", "") for r in m.get("relatedVulnerabilities", [])
                       if r.get("id", "").startswith("CVE-")]
            vulns[vid] = {
                "severity":  v.get("severity", "UNKNOWN").upper(),
                "pkg":       m.get("artifact", {}).get("name", ""),
                "fix_state": fix.get("state", ""),
                "fixed":     fix.get("state", "") == "fixed",
                "cwes":      cwes,
                "related":   related,
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
    return len(advisory_ids), total


def load_sbom(safe):
    path = os.path.join(SCRIPT_DIR, "sbom", f"{safe}_syft.json")
    if not os.path.exists(path):
        return None, {}
    with open(path) as f:
        sj = json.load(f)
    pkgs = sj.get("artifacts", [])
    ecosystems = collections.Counter(p.get("type", "unknown") for p in pkgs)
    return len(pkgs), dict(ecosystems)


def w(name):
    path = os.path.join(CSV_DIR, name)
    print(f"  Writing {name}")
    return open(path, "w", newline="")


# ---------------------------------------------------------------------------
# Build unified dataset once
# ---------------------------------------------------------------------------

dataset = []
for safe, image, group in IMAGES:
    t_vulns, t_statuses, eosl = load_trivy(safe)
    g_vulns, g_states         = load_grype(safe)
    osv_adv, osv_total        = load_osv(safe)
    sbom_total, sbom_eco      = load_sbom(safe)

    t_cnts = collections.Counter(v["severity"] for v in t_vulns.values())
    t_cnts["total"] = len(t_vulns)
    t_cnts["fixed"] = sum(1 for v in t_vulns.values() if v["fixed"])

    g_cnts = collections.Counter(v["severity"] for v in g_vulns.values())
    g_cnts["total"] = len(g_vulns)
    g_cnts["fixed"] = sum(1 for v in g_vulns.values() if v["fixed"])

    # CVE overlap
    t_ids = set(t_vulns)
    g_ids_exp = set(g_vulns)
    for gv in g_vulns.values():
        g_ids_exp.update(gv.get("related", []))
    both   = t_ids & g_ids_exp
    t_only = t_ids - g_ids_exp
    g_only = g_ids_exp - t_ids
    union  = t_ids | g_ids_exp
    jaccard = round(len(both) / len(union), 3) if union else 0.0

    same = t_higher = g_higher = 0
    for cve in both:
        ts = t_vulns.get(cve, {}).get("severity", "UNKNOWN")
        gs = g_vulns.get(cve, {}).get("severity", "UNKNOWN")
        if ts == gs:          same += 1
        elif SEV_RANK.get(ts, 0) > SEV_RANK.get(gs, 0): t_higher += 1
        else:                 g_higher += 1

    t_cwes = collections.Counter()
    for v in t_vulns.values(): t_cwes.update(v.get("cwes", []))
    g_cwes = collections.Counter()
    for v in g_vulns.values(): g_cwes.update(v.get("cwes", []))

    dataset.append({
        "safe": safe, "image": image, "group": group,
        "size_mb": IMAGE_SIZES_MB.get(safe, 0), "eosl": eosl,
        "t_cnts": dict(t_cnts), "t_statuses": dict(t_statuses),
        "g_cnts": dict(g_cnts), "g_states": dict(g_states),
        "osv_adv": osv_adv, "osv_total": osv_total,
        "sbom_total": sbom_total, "sbom_eco": sbom_eco,
        "overlap": {
            "t_total": len(t_ids), "g_total": len(g_ids_exp),
            "t_only": len(t_only), "both": len(both),
            "g_only": len(g_only), "jaccard": jaccard,
        },
        "sev_agreement": {
            "shared": len(both), "same": same,
            "t_higher": t_higher, "g_higher": g_higher,
        },
        "t_cwes": dict(t_cwes), "g_cwes": dict(g_cwes),
    })

# ---------------------------------------------------------------------------
# TABLE 1 — Core counts
# ---------------------------------------------------------------------------
with w("table1_core_counts.csv") as f:
    writer = csv.writer(f)
    writer.writerow([
        "group", "image", "size_mb",
        "trivy_total", "trivy_critical", "trivy_high", "trivy_medium", "trivy_low",
        "trivy_fixed", "trivy_fix_pct",
        "grype_total", "grype_critical", "grype_high", "grype_medium", "grype_low",
        "grype_fixed", "grype_fix_pct",
        "osv_advisories", "osv_pkg_matches", "eosl",
    ])
    for d in dataset:
        t, g = d["t_cnts"], d["g_cnts"]
        tfp = round(t.get("fixed", 0) / t.get("total", 1) * 100, 1)
        gfp = round(g.get("fixed", 0) / g.get("total", 1) * 100, 1)
        writer.writerow([
            d["group"], d["image"], d["size_mb"],
            t.get("total", 0), t.get("CRITICAL", 0), t.get("HIGH", 0),
            t.get("MEDIUM", 0), t.get("LOW", 0), t.get("fixed", 0), tfp,
            g.get("total", 0), g.get("CRITICAL", 0), g.get("HIGH", 0),
            g.get("MEDIUM", 0), g.get("LOW", 0), g.get("fixed", 0), gfp,
            d["osv_adv"], d["osv_total"], d["eosl"],
        ])

# ---------------------------------------------------------------------------
# TABLE 2 — Fix status breakdown
# ---------------------------------------------------------------------------
with w("table2_fix_status_trivy.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image", "fixed", "affected", "will_not_fix", "fix_deferred", "fix_pct"])
    for d in dataset:
        s = d["t_statuses"]
        total = sum(s.values())
        pct = round(s.get("fixed", 0) / total * 100, 1) if total else 0
        writer.writerow([d["group"], d["image"],
            s.get("fixed", 0), s.get("affected", 0),
            s.get("will_not_fix", 0), s.get("fix_deferred", 0), pct])

with w("table2_fix_status_grype.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image", "fixed", "not_fixed", "wont_fix", "unknown", "fix_pct"])
    for d in dataset:
        s = d["g_states"]
        total = sum(s.values())
        pct = round(s.get("fixed", 0) / total * 100, 1) if total else 0
        writer.writerow([d["group"], d["image"],
            s.get("fixed", 0), s.get("not-fixed", 0),
            s.get("wont-fix", 0), s.get("unknown", 0), pct])

# ---------------------------------------------------------------------------
# TABLE 3 — CVE overlap
# ---------------------------------------------------------------------------
with w("table3_cve_overlap.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image", "trivy_cves", "grype_cves",
                     "trivy_only", "both", "grype_only", "jaccard"])
    for d in dataset:
        ov = d["overlap"]
        writer.writerow([d["group"], d["image"],
            ov["t_total"], ov["g_total"],
            ov["t_only"], ov["both"], ov["g_only"], ov["jaccard"]])

# ---------------------------------------------------------------------------
# TABLE 4 — Severity agreement on shared CVEs
# ---------------------------------------------------------------------------
with w("table4_severity_agreement.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image", "shared_cves", "same_severity",
                     "agree_pct", "trivy_higher", "grype_higher"])
    for d in dataset:
        sa = d["sev_agreement"]
        n  = sa["shared"]
        pct = round(sa["same"] / n * 100, 1) if n else 0
        writer.writerow([d["group"], d["image"],
            n, sa["same"], pct, sa["t_higher"], sa["g_higher"]])

# ---------------------------------------------------------------------------
# TABLE 5 — CWE pivot
# ---------------------------------------------------------------------------
all_t = collections.Counter()
all_g = collections.Counter()
for d in dataset:
    all_t.update(d["t_cwes"])
    all_g.update(d["g_cwes"])

all_cwes = set(all_t) | set(all_g)
combined = {c: all_t.get(c, 0) + all_g.get(c, 0) for c in all_cwes}
top10 = [c for c, _ in sorted(combined.items(), key=lambda x: -x[1])[:10]]

with w("table5_cwe_pivot.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["cwe", "trivy_total", "grype_total", "combined_total"])
    for cwe in top10:
        writer.writerow([cwe, all_t.get(cwe, 0), all_g.get(cwe, 0),
                         all_t.get(cwe, 0) + all_g.get(cwe, 0)])

with w("table5_cwe_per_image_trivy.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image"] + top10)
    for d in dataset:
        writer.writerow([d["group"], d["image"]] +
                        [d["t_cwes"].get(c, 0) for c in top10])

with w("table5_cwe_per_image_grype.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image"] + top10)
    for d in dataset:
        writer.writerow([d["group"], d["image"]] +
                        [d["g_cwes"].get(c, 0) for c in top10])

# ---------------------------------------------------------------------------
# TABLE 6 — Performance benchmark
# ---------------------------------------------------------------------------
bench_path = os.path.join(LOGS, "benchmark_summary.json")
if os.path.exists(bench_path):
    with open(bench_path) as f:
        bench = {b["safe"]: b for b in json.load(f)}

    with w("table6_performance.csv") as f:
        writer = csv.writer(f)
        writer.writerow([
            "group", "image", "size_mb",
            "trivy_run1_ms", "trivy_run2_ms", "trivy_run3_ms",
            "trivy_mean_ms", "trivy_sd_ms",
            "grype_run1_ms", "grype_run2_ms", "grype_run3_ms",
            "grype_mean_ms", "grype_sd_ms",
            "osv_run1_ms",   "osv_run2_ms",   "osv_run3_ms",
            "osv_mean_ms",   "osv_sd_ms",
        ])
        for d in dataset:
            b = bench.get(d["safe"])
            if not b:
                continue
            t_r = b["trivy"]["runs_ms"]
            g_r = b["grype"]["runs_ms"]
            o_r = b["osv"]["runs_ms"]
            # Exclude run1 from alpine cold-export anomaly
            t_calc = t_r[1:] if d["safe"] == "alpine_3.19" else t_r
            g_calc = g_r[1:] if d["safe"] == "alpine_3.19" else g_r

            def ms(runs): return round(statistics.mean(runs)) if runs else 0
            def sd(runs): return round(statistics.stdev(runs)) if len(runs) > 1 else 0

            row = [d["group"], d["image"], d["size_mb"]]
            row += t_r + [ms(t_calc), sd(t_calc)]
            row += g_r + [ms(g_calc), sd(g_calc)]
            row += o_r + [ms(o_r),    sd(o_r)]
            writer.writerow(row)

# ---------------------------------------------------------------------------
# EXPERIMENT LOG DATASETS
# ---------------------------------------------------------------------------

# D1 — Core results (same as Table 1 but with original first-run timing)
with open(os.path.join(LOGS, "timing.log")) as f:
    timing_raw = f.readlines()

timing = collections.defaultdict(dict)
for line in timing_raw:
    parts = line.strip().split()
    if len(parts) >= 4:
        _, safe, tool, ms_str, *_ = parts
        ms = ms_str.replace("ms","").replace("retry_ok","")
        if ms.isdigit():
            timing[safe][tool] = int(ms)

with w("D1_core_results.csv") as f:
    writer = csv.writer(f)
    writer.writerow([
        "group", "image",
        "trivy_total", "trivy_critical", "trivy_high", "trivy_medium", "trivy_low", "trivy_fixed",
        "grype_total", "grype_critical", "grype_high", "grype_medium", "grype_low", "grype_fixed",
        "osv_advisories", "eosl",
    ])
    for d in dataset:
        t, g = d["t_cnts"], d["g_cnts"]
        writer.writerow([
            d["group"], d["image"],
            t.get("total", 0), t.get("CRITICAL", 0), t.get("HIGH", 0),
            t.get("MEDIUM", 0), t.get("LOW", 0), t.get("fixed", 0),
            g.get("total", 0), g.get("CRITICAL", 0), g.get("HIGH", 0),
            g.get("MEDIUM", 0), g.get("LOW", 0), g.get("fixed", 0),
            d["osv_adv"], d["eosl"],
        ])

# D2 — Original single-run performance (from timing.log)
with w("D2_performance_original.csv") as f:
    writer = csv.writer(f)
    writer.writerow(["group", "image", "size_mb",
                     "syft_ms", "trivy_ms", "grype_ms", "osv_ms"])
    for safe, image, group in IMAGES:
        t = timing.get(safe, {})
        writer.writerow([group, image, IMAGE_SIZES_MB.get(safe, 0),
            t.get("syft", ""), t.get("trivy", ""),
            t.get("grype", ""), t.get("osv", "")])

# D3 — SBOM baseline
with w("D3_sbom_baseline.csv") as f:
    writer = csv.writer(f)
    ecosystems_all = sorted({eco for d in dataset
                              for eco in (d["sbom_eco"] or {}).keys()})
    writer.writerow(["group", "image", "total_packages"] + ecosystems_all)
    for d in dataset:
        eco = d["sbom_eco"] or {}
        total = d["sbom_total"] if d["sbom_total"] is not None else ""
        writer.writerow([d["group"], d["image"], total] +
                        [eco.get(e, 0) for e in ecosystems_all])

# D4 — Policy evaluation
def has_critical(t_cnts, g_cnts, tool="both"):
    tc = t_cnts.get("CRITICAL", 0) > 0
    gc = g_cnts.get("CRITICAL", 0) > 0
    if tool == "trivy": return tc
    if tool == "grype": return gc
    return tc and gc  # P3: both

with w("D4_policy_evaluation.csv") as f:
    writer = csv.writer(f)
    writer.writerow([
        "group", "image",
        "trivy_critical", "grype_critical",
        "trivy_fixed_total", "grype_fixed_total",
        "P1_trivy", "P1_grype",
        "P2_trivy", "P2_grype",
        "P3_consensus",
    ])
    for d in dataset:
        t, g = d["t_cnts"], d["g_cnts"]
        tc, gc = t.get("CRITICAL", 0), g.get("CRITICAL", 0)
        p1t = "REJECT" if tc > 0 else "PASS"
        p1g = "REJECT" if gc > 0 else "PASS"
        p2t = "REJECT" if tc > 0 and t.get("fixed", 0) > 0 else "PASS"
        p2g = "REJECT" if gc > 0 and g.get("fixed", 0) > 0 else "PASS"
        p3  = "REJECT" if tc > 0 and gc > 0 else "PASS"
        writer.writerow([d["group"], d["image"], tc, gc,
            t.get("fixed", 0), g.get("fixed", 0),
            p1t, p1g, p2t, p2g, p3])

print(f"\nAll CSVs written to: {CSV_DIR}/")
print(f"Files: {sorted(os.listdir(CSV_DIR))}")
