#!/usr/bin/env python3
"""
rescan_compare.py — Compare CVE-level Jaccard similarity and the
OS-only-vs-mixed-ecosystem Mann-Whitney test between the original
2026-03-31 baseline scan and a re-scan against today's live databases.

Usage: python3 analysis/rescan_compare.py
"""
import json
import os
import statistics
from scipy.stats import mannwhitneyu

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ORIGINAL_BASE = os.path.join(ROOT, "data", "raw")
RESCAN_BASE = os.path.join(ROOT, "data", "raw_rescan_2026-07-29")

IMAGES = [
    ("vulnerables_web-dvwa", "A"),
    ("bkimminich_juice-shop", "A"),
    ("nginx_1.19", "B"),
    ("node_14", "B"),
    ("python_3.8", "B"),
    ("alpine_3.19", "C"),
    ("nginx_1.29.7", "C"),
    ("node_20", "C"),
    ("python_3.12", "C"),
]

# Section 5.1 of the thesis: "the three pure-OS images (alpine:3.19, both
# nginx versions, and web-dvwa, whose PHP findings are entirely
# OS-packaged)". Everything else is mixed (npm/PyPI + OS packages).
OS_ONLY = {"alpine_3.19", "nginx_1.19", "nginx_1.29.7", "vulnerables_web-dvwa"}

# Published Table 5.3 Jaccard values (2026-03-31 baseline), used below to
# validate this script's own logic before trusting any new-data output.
PUBLISHED_JACCARD = {
    "vulnerables_web-dvwa": 0.704, "bkimminich_juice-shop": 0.952,
    "nginx_1.19": 0.741, "node_14": 0.240, "python_3.8": 0.144,
    "alpine_3.19": 0.500, "nginx_1.29.7": 0.885, "node_20": 0.291,
    "python_3.12": 0.448,
}


def load_trivy_ids(base, safe):
    with open(os.path.join(base, "trivy", f"{safe}_trivy.json")) as f:
        tj = json.load(f)
    ids = set()
    for r in tj.get("Results", []):
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            if vid:
                ids.add(vid)
    return ids


def load_grype_ids(base, safe):
    with open(os.path.join(base, "grype", f"{safe}_grype.json")) as f:
        gj = json.load(f)
    ids = set()
    for m in gj.get("matches", []):
        v = m.get("vulnerability", {})
        vid = v.get("id", "")
        if not vid:
            continue
        if vid.startswith("CVE-"):
            ids.add(vid)
        else:
            related = [r.get("id", "") for r in m.get("relatedVulnerabilities", [])
                       if r.get("id", "").startswith("CVE-")]
            ids.add(related[0] if related else vid)
    return ids


def jaccard_for(base, safe):
    t_ids = load_trivy_ids(base, safe)
    g_ids = load_grype_ids(base, safe)
    union = t_ids | g_ids
    both = t_ids & g_ids
    return round(len(both) / len(union), 3) if union else 0.0


def group_means_and_test(jaccards):
    os_vals = [jaccards[safe] for safe, _ in IMAGES if safe in OS_ONLY]
    mixed_vals = [jaccards[safe] for safe, _ in IMAGES if safe not in OS_ONLY]
    # one-sided: thesis's a priori hypothesis is OS-only > mixed (Section 5.1);
    # matches the thesis's reported U=16, p=0.095 on the original 9-image set.
    u_stat, p_value = mannwhitneyu(os_vals, mixed_vals, alternative="greater")
    return {
        "os_mean": round(statistics.mean(os_vals), 3),
        "mixed_mean": round(statistics.mean(mixed_vals), 3),
        "n_os": len(os_vals),
        "n_mixed": len(mixed_vals),
        "u": u_stat,
        "p": round(p_value, 3),
    }


def main():
    # --- Self-check: reproduce the published baseline before trusting
    # anything new. If this fails, the loader logic has a bug.
    original_jaccards = {safe: jaccard_for(ORIGINAL_BASE, safe) for safe, _ in IMAGES}
    for safe, published in PUBLISHED_JACCARD.items():
        computed = original_jaccards[safe]
        assert abs(computed - published) < 0.001, (
            f"Baseline mismatch on {safe}: published={published}, "
            f"computed={computed}. Fix the loader before trusting the re-scan."
        )
    print("Self-check passed: recomputed baseline matches published Table 5.3 exactly.\n")

    original_stats = group_means_and_test(original_jaccards)
    print("ORIGINAL (2026-03-31 DB) OS-only vs mixed:")
    print(f"  OS-only mean:  {original_stats['os_mean']} (n={original_stats['n_os']})")
    print(f"  Mixed mean:    {original_stats['mixed_mean']} (n={original_stats['n_mixed']})")
    print(f"  Mann-Whitney U={original_stats['u']}, p={original_stats['p']}\n")

    rescan_jaccards = {safe: jaccard_for(RESCAN_BASE, safe) for safe, _ in IMAGES}
    rescan_stats = group_means_and_test(rescan_jaccards)
    print("RE-SCAN (2026-07-29 DB) OS-only vs mixed:")
    print(f"  OS-only mean:  {rescan_stats['os_mean']} (n={rescan_stats['n_os']})")
    print(f"  Mixed mean:    {rescan_stats['mixed_mean']} (n={rescan_stats['n_mixed']})")
    print(f"  Mann-Whitney U={rescan_stats['u']}, p={rescan_stats['p']}\n")

    print("Per-image Jaccard drift (original -> re-scan):")
    for safe, group in IMAGES:
        orig = original_jaccards[safe]
        new = rescan_jaccards[safe]
        print(f"  {group}  {safe:<28} {orig:.3f} -> {new:.3f}  (delta {new - orig:+.3f})")

    print("\nVerdict:")
    order_flipped = (
        (original_stats["os_mean"] > original_stats["mixed_mean"])
        != (rescan_stats["os_mean"] > rescan_stats["mixed_mean"])
    )
    if order_flipped:
        print("  Group-mean ordering FLIPPED between original and re-scan.")
        print("  -> The ecosystem-split pattern does not survive same-digest "
              "re-scanning: consistent with database drift, not a genuine "
              "ecosystem effect.")
    else:
        print("  Group-mean ordering held between original and re-scan.")
        print("  -> The ecosystem-split pattern is not explained by database "
              "drift alone; the original 9-vs-21 image discrepancy needs a "
              "different explanation.")


if __name__ == "__main__":
    main()
