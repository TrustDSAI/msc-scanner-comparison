# Re-scan Database-Drift Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-scan the 9 design-set images against today's (2026-07-29) live scanner databases, and determine whether the "operating-system-only images agree more than mixed-ecosystem images" pattern reported on the original March-2026 scan survives, or whether it was an artifact of database drift between the March design-set scan and the June extension-set scan.

**Architecture:** Scan the same 9 pinned-digest images a second time with Trivy/Grype/OSV-Scanner (1 run each, no timing repeats — finding counts are deterministic per digest+DB, Section 4.1.4 of the thesis), into an isolated output directory so the original baseline in `data/raw/` is never touched. A new analysis script loads both the original and the re-scanned data, recomputes per-image Jaccard similarity and the OS-only-vs-mixed Mann-Whitney test used in the thesis (Figure 5.2 / Table 5.3), and reports whether the group means and p-value hold up.

**Tech Stack:** bash (scan orchestration, reusing the existing `docker`/`trivy`/`grype`/`osv-scanner` CLIs already on this host), Python 3.9 + scipy 1.13 (`scipy.stats.mannwhitneyu`) for the statistics.

## Global Constraints

- Never write into `data/raw/{trivy,grype,osv}/` — that's the original baseline (2026-03-31 DB snapshot) the thesis's published numbers depend on. All new scan output goes to `data/raw_rescan_2026-07-29/{trivy,grype,osv}/`.
- Scope is the 9 design-set images only (`vulnerables/web-dvwa`, `bkimminich/juice-shop`, `nginx:1.19`, `node:14`, `python:3.8`, `alpine:3.19`, `nginx:1.29.7`, `node:20`, `python:3.12`) — same set as `analysis/analysis.py`'s `IMAGES` list. Do not touch the 21-image extension set.
- Images are pulled by the same pinned digest as the original scan (`scripts/reproduce.sh`'s `DIGESTS` map) — only the vulnerability databases are allowed to differ between the two scans. If the image content differed too, database drift wouldn't be the only variable.
- 1 run per tool per image (27 scans total: 9 images × 3 tools), not 30 — Section 4.1.4 of the thesis established that finding counts are deterministic for a fixed digest+DB, so repeat runs only characterise timing variance, which this check doesn't need.
- Before trusting any new-data conclusion, the analysis script must first reproduce the *original* published Table 5.3 Jaccard values from the untouched `data/raw/` baseline. If it doesn't, the script has a bug — don't proceed to interpreting the re-scan.
- This repo's `analysis/` directory has no existing pytest suite (unlike `policy/tests/`) — it's one-shot analysis scripts, not a library. Don't introduce a test framework here; use plain `assert`-based self-checks in the script itself, consistent with the rest of `analysis/`.

---

### Task 1: Re-scan the 9 design images into an isolated directory

**Files:**
- Create: `scripts/rescan_2026-07.sh`

**Interfaces:**
- Consumes: `docker`, `trivy`, `grype`, `osv-scanner` CLIs (already installed and verified working on this host); the pinned digests already hard-coded in `scripts/reproduce.sh`.
- Produces: `data/raw_rescan_2026-07-29/trivy/<safe>_trivy.json`, `data/raw_rescan_2026-07-29/grype/<safe>_grype.json`, `data/raw_rescan_2026-07-29/osv/<safe>_osv.json` for all 9 `safe` names below. Task 2 reads these paths directly.

- [ ] **Step 1: Write the re-scan script**

```bash
#!/bin/bash
# rescan_2026-07.sh — Re-run the 9 design-set images against today's live
# scanner databases, writing to an isolated directory so the original
# 2026-03-31 baseline in data/raw/ is never overwritten.
#
# Usage: ./scripts/rescan_2026-07.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${REPO_DIR}/data/raw_rescan_2026-07-29"
LOG="${REPO_DIR}/logs/rescan_2026-07-29.log"

mkdir -p "${OUT}/trivy" "${OUT}/grype" "${OUT}/osv"

declare -A DIGESTS=(
    ["alpine_3.19"]="alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
    ["nginx_1.29.7"]="nginx@sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18"
    ["node_20"]="node@sha256:a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520"
    ["python_3.12"]="python@sha256:c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436"
    ["nginx_1.19"]="nginx@sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2"
    ["node_14"]="node@sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa"
    ["python_3.8"]="python@sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c"
    ["vulnerables_web-dvwa"]="vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7"
    ["bkimminich_juice-shop"]="bkimminich/juice-shop@sha256:5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114"
)

declare -A OSV_TAGS=(
    ["alpine_3.19"]="alpine:3.19"
    ["nginx_1.29.7"]="nginx:1.29.7"
    ["node_20"]="node:20"
    ["python_3.12"]="python:3.12"
    ["nginx_1.19"]="nginx:1.19"
    ["node_14"]="node:14"
    ["python_3.8"]="python:3.8"
    ["vulnerables_web-dvwa"]="vulnerables/web-dvwa:latest"
    ["bkimminich_juice-shop"]="bkimminich/juice-shop:latest"
)

for safe in "${!DIGESTS[@]}"; do
    IMAGE="${DIGESTS[$safe]}"
    OSV_TAG="${OSV_TAGS[$safe]}"

    echo "=== ${safe} (${IMAGE}) ===" | tee -a "${LOG}"
    docker pull "${IMAGE}" | tee -a "${LOG}"
    docker tag "${IMAGE}" "${OSV_TAG}"

    trivy image --format json --scanners vuln \
        --output "${OUT}/trivy/${safe}_trivy.json" "${IMAGE}" 2>&1 | tee -a "${LOG}"

    grype "${IMAGE}" -o json > "${OUT}/grype/${safe}_grype.json" 2>>"${LOG}"

    osv-scanner scan image --format json \
        --output-file "${OUT}/osv/${safe}_osv.json" "${OSV_TAG}" 2>>"${LOG}" || true

    echo "done: ${safe}" | tee -a "${LOG}"
done

echo "Re-scan complete. Output: ${OUT}"
```

- [ ] **Step 2: Make it executable and run it**

```bash
chmod +x scripts/rescan_2026-07.sh
./scripts/rescan_2026-07.sh
```

Expected: 9 `=== <safe> ===` sections in the log, each ending `done: <safe>`, no unhandled errors (OSV-Scanner failures are tolerated via `|| true`, matching `scan.sh`'s existing convention — OSV-Scanner sometimes exits non-zero on findings).

- [ ] **Step 3: Verify all 27 output files exist and parse as JSON**

```bash
python3 -c "
import json, sys
safes = ['alpine_3.19','nginx_1.29.7','node_20','python_3.12','nginx_1.19',
         'node_14','python_3.8','vulnerables_web-dvwa','bkimminich_juice-shop']
base = 'data/raw_rescan_2026-07-29'
missing = []
for safe in safes:
    for tool, ext in [('trivy','trivy'),('grype','grype'),('osv','osv')]:
        path = f'{base}/{tool}/{safe}_{ext}.json'
        try:
            with open(path) as f:
                json.load(f)
        except Exception as e:
            missing.append((path, str(e)))
if missing:
    for p, e in missing:
        print(f'BAD: {p}: {e}')
    sys.exit(1)
print(f'OK: all {len(safes)*3} files present and parse as JSON')
"
```

Expected: `OK: all 27 files present and parse as JSON`.

- [ ] **Step 4: Commit**

```bash
git add scripts/rescan_2026-07.sh data/raw_rescan_2026-07-29 logs/rescan_2026-07-29.log
git commit -m "feat: re-scan 9 design images against 2026-07-29 live databases"
```

---

### Task 2: Recompute Jaccard and the OS-only-vs-mixed Mann-Whitney test on old and new data

**Files:**
- Create: `analysis/rescan_compare.py`
- Test: none (no pytest harness in `analysis/`; the script's own baseline-reproduction assertion in Step 1 below is its self-check, per Global Constraints)

**Interfaces:**
- Consumes: `data/raw/{trivy,grype}/<safe>_{trivy,grype}.json` (original baseline, untouched) and `data/raw_rescan_2026-07-29/{trivy,grype}/<safe>_{trivy,grype}.json` (Task 1's output).
- Produces: prints a report to stdout; Task 3 redirects this into `docs/rescan_2026-07-29_findings.md`.

- [ ] **Step 1: Write the comparison script**

```python
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

# (safe_name, group) — group is only used for display; the OS-only vs
# mixed split below is what the statistics actually run against.
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
    u_stat, p_value = mannwhitneyu(os_vals, mixed_vals, alternative="two-sided")
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
```

- [ ] **Step 2: Run it and confirm the self-check passes**

```bash
python3 analysis/rescan_compare.py
```

Expected: first line of output is `Self-check passed: recomputed baseline matches published Table 5.3 exactly.` If it raises `AssertionError` instead, stop — do not proceed to Task 3 — and fix the loader logic (most likely cause: a Grype CVE-alias edge case not matched exactly the way `analysis/analysis.py`'s `_canonical_cve_id`-equivalent logic handles it).

- [ ] **Step 3: Commit**

```bash
git add analysis/rescan_compare.py
git commit -m "feat: add database-drift comparison script for 9 design images"
```

---

### Task 3: Record the finding

**Files:**
- Create: `docs/rescan_2026-07-29_findings.md`
- Modify: `docs/experiment_log.md` (append one entry, following that file's existing entry format)

**Interfaces:**
- Consumes: the full stdout of `python3 analysis/rescan_compare.py` from Task 2.
- Produces: a committed, dated record of the outcome — this is what the thesis-side decision (whether to revise §5.1/§6.1's ecosystem-drift discussion) gets made from, in a separate, later task outside this plan's scope.

- [ ] **Step 1: Capture the run output**

```bash
python3 analysis/rescan_compare.py > /tmp/rescan_output.txt
cat /tmp/rescan_output.txt
```

- [ ] **Step 2: Write the findings doc**

Create `docs/rescan_2026-07-29_findings.md` with this structure (fill in the `<...>` placeholders with the actual numbers from Step 1's captured output — these cannot be known until the scan has run):

```markdown
# Database-Drift Check: 9 Design Images Re-scanned 2026-07-29

## Question

The thesis's original 9-image design-set scan (databases pinned 2026-03-30)
found operating-system-only images agreeing more closely (mean Jaccard
<original_os_mean>) than mixed-ecosystem images (mean <original_mixed_mean>,
Mann-Whitney U=<original_u>, p=<original_p>). The 21-image extension scan
(databases current as of 2026-06-21) found this reversed and
non-significant. Does the reversal survive re-scanning the *same 9 images,
same pinned digests* against today's (2026-07-29) live databases, or does
it disappear — indicating the original pattern was database drift between
the two scan dates, not a genuine ecosystem effect?

## Method

`scripts/rescan_2026-07.sh` re-ran all 9 design-set images (identical
pinned digests to the original scan) against live Trivy/Grype/OSV-Scanner
databases as of 2026-07-29, 1 run per tool per image, output isolated to
`data/raw_rescan_2026-07-29/` (original baseline in `data/raw/` untouched).
`analysis/rescan_compare.py` recomputed per-image CVE-level Jaccard
similarity and the OS-only-vs-mixed Mann-Whitney test for both the
original and re-scanned data, after first confirming it reproduces the
published Table 5.3 values exactly from the untouched baseline.

## Result

<paste the full "ORIGINAL" / "RE-SCAN" / "Per-image Jaccard drift" /
"Verdict" sections from /tmp/rescan_output.txt here verbatim>

## Conclusion

<one of:>
- Reversal SURVIVES same-digest re-scanning: group-mean ordering held.
  Database drift is not a sufficient explanation for the 9-vs-21 image
  discrepancy; the thesis's existing "neither difference is significant"
  framing (§5.1/§6.1) stands, and the open question of what does explain
  the discrepancy stays open.
- Reversal DISAPPEARS under same-digest re-scanning: group-mean ordering
  flipped. This is evidence the original ecosystem-split pattern was an
  artifact of the ~3-month gap between the design-set and extension-set
  scan dates, not a real effect — a stronger and more specific finding
  than the thesis's current "neither difference is significant, and the
  small samples cannot separate database drift from sampling noise"
  hedge (§6.1). Revising §5.1/§6.1 to state this is a separate,
  thesis-side task, not part of this plan.
```

- [ ] **Step 3: Append one entry to `docs/experiment_log.md`**

Read the file's existing most recent entry first to match its exact heading/field format, then append a new entry for this run (date 2026-07-29, images: the 9 design-set images, tools: Trivy/Grype/OSV-Scanner, purpose: database-drift check, pointer to `docs/rescan_2026-07-29_findings.md`).

- [ ] **Step 4: Commit**

```bash
git add docs/rescan_2026-07-29_findings.md docs/experiment_log.md
git commit -m "docs: record 2026-07-29 database-drift check finding"
```

---

## Self-Review

**1. Spec coverage:** Day 1 of the pasted 6-week plan asked for exactly three things: (a) re-scan the 9 images once each against today's databases, (b) recompute Jaccard/OS-split/Mann-Whitney, (c) report which of the two outcomes ("reversal survives" / "reversal disappears") holds. Tasks 1, 2, and 3 cover these respectively. Nothing else from that plan (real-tool baselines, ablation, validation harness, sampling, triage-burden study, re-partition) is in scope here — those are separate, later plans if the user wants to proceed with the rest of the 6-week plan.

**2. Placeholder scan:** The two `<...>`-bracketed spots in Task 3 Step 2 are not placeholders in the "TBD" sense — they're explicitly the run's actual output, which cannot exist until Task 1/2 execute; the step's instructions say precisely what to paste there and from where.

**3. Type consistency:** `IMAGES`, `OS_ONLY`, and `PUBLISHED_JACCARD` in `rescan_compare.py` all key on the same 9 `safe` strings used in `scripts/rescan_2026-07.sh`'s `DIGESTS`/`OSV_TAGS` maps and in `analysis/analysis.py`'s existing `IMAGES` list — verified these match exactly (`vulnerables_web-dvwa`, `bkimminich_juice-shop`, `nginx_1.19`, `node_14`, `python_3.8`, `alpine_3.19`, `nginx_1.29.7`, `node_20`, `python_3.12`).
