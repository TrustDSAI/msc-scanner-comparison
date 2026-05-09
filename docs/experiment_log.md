# Container Vulnerability Scanner Comparison — Experiment Log

**Dissertation:** *Policy-as-Code for Container Vulnerability Gating in CI/CD Pipelines*
**Author:** Simão Cabral Sousa — University of Coimbra, 2026
**Scans performed:** 2026-03-31 · **Benchmark:** 30 runs × 9 images × 3 tools, 2026-04-25/26

---

## 1. Tool Versions

| Tool | Version | DB / Schema | Notes |
|------|---------|-------------|-------|
| Trivy | 0.69.3 | Vulnerability DB v2, updated 2026-03-30 | `--scanners vuln` only |
| Grype | 0.110.0 | Schema v6.1.4, built 2026-03-30 | default profile |
| OSV-Scanner | 2.3.5 (scalibr v0.4.5) | Live — api.osv.dev at scan time | `scan image` subcommand |
| Syft | 1.42.3 | Schema v16.1.3 | SBOM generation only |

---

## 2. Image Dataset

Images pulled and pinned by digest on **2026-03-31**.

### Group A — Intentionally Vulnerable

| Image | OS | EOSL | Digest |
|-------|----|------|--------|
| vulnerables/web-dvwa:latest | Debian 9.5 | YES | `sha256:dae203fe…37daa7` |
| bkimminich/juice-shop:latest | Debian 13.4 | no | `sha256:5539448a…14114` |

### Group B — Outdated Real-World

| Image | OS | EOSL | Digest |
|-------|----|------|--------|
| nginx:1.19 | Debian 10.9 | YES | `sha256:df13abe4…f4f1f2` |
| node:14 | Debian 10.13 | YES | `sha256:a158d3b9…d8461aa` |
| python:3.8 | Debian 12.7 | no | `sha256:d411270700…390c` |

### Group C — Modern Baseline

| Image | OS | EOSL | Digest |
|-------|----|------|--------|
| alpine:3.19 | Alpine 3.19.9 | YES | `sha256:6baf4358…eb11ca1` |
| nginx:1.29.7 | Debian 13.4 | no | `sha256:7150b3a3…51c18` |
| node:20 | Debian 12.13 | no | `sha256:a4545fc6…718520` |
| python:3.12 | Debian 13.4 | no | `sha256:c4c9e439…b3436` |

> **Note:** Alpine 3.19.9 was flagged EOSL at scan time despite being the current stable release — a real-world finding about version lifecycle lag.

---

## 3. Scan Results

### 3.1 alpine:3.19 (Group C)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 6 | 0 | 0 | 3 | 3 | 6 (100%) |
| Grype | 10 | 0 | 0 | 4 | 6 | 6 (60%) |
| OSV | 6 | — | — | — | — | — |

- Minimal package surface (15 apk packages). All Trivy findings fixable; Grype finds 4 additional LOW/MEDIUM.
- All three tools flagged Alpine 3.19.9 as EOSL.

---

### 3.2 nginx:1.29.7 (Group C)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 169 | 0 | 14 | 29 | 126 | 0 (0%) |
| Grype | 172 | 0 | 25 | 33 | 8 | 0 (0%) |
| OSV | 177 | — | — | — | — | — |

- Zero CRITICAL across all tools — consistent agreement.
- 0% fix availability: Debian 13 marks most CVEs as accepted-unfixed.
- Severity classification diverges: Grype reports 11 more HIGH (25 vs 14); Trivy inflates LOW (126 vs 8).

---

### 3.3 node:20 (Group C)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 2268 | 33 | 277 | 936 | 997 | 14 (1%) |
| Grype | 1474 | 32 | 178 | 360 | 67 | 14 (1%) |
| OSV | 1458 | — | — | — | — | — |

- CRITICAL near-identical (33 vs 32) — strong agreement at highest severity.
- Total divergence driven by LOW: Trivy 997 vs Grype 67 (14.9×).
- OSV (1458) closely matches Grype (1474).
- 204 npm packages in SBOM contribute large vulnerability surface.

---

### 3.4 python:3.12 (Group C)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 1751 | 0 | 196 | 557 | 971 | 238 (14%) |
| Grype | 1418 | 0 | 165 | 375 | 59 | 249 (18%) |
| OSV | 1422 | — | — | — | — | — |

- No CRITICAL across all tools.
- LOW divergence: 971 (Trivy) vs 59 (Grype) — 16.5×.
- Fix counts closely aligned: Trivy 238 vs Grype 249.
- OSV (1422) closely matches Grype (1418) — consistent pattern with Debian 13 images.

---

### 3.5 nginx:1.19 (Group B)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 424 | 42 | 149 | 193 | 31 | 337 (79%) |
| Grype | 550 | 40 | 159 | 194 | 35 | 320 (58%) |
| OSV | 132† | — | — | — | — | — |

†OSV reports at advisory level — each entry covers multiple CVEs.

- High CRITICAL count with strong cross-tool agreement (42 vs 40).
- High fix availability (79% / 58%) — most risk is remediable by upgrading.
- Prime candidate for P1 and P2 policy rejection.

---

### 3.6 node:14 (Group B)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 1439 | 22 | 569 | 754 | 90 | 1112 (77%) |
| Grype | 1995 | 19 | 453 | 477 | 95 | 681 (34%) |
| OSV | 210† | — | — | — | — | — |

- Grype exceeds Trivy in total findings (reversal of the Group C pattern) — driven by npm coverage differences.
- Fix rate divergence: Trivy 77% vs Grype 34% — 43pp gap on the same image.
- Largest combined package surface of any non-Group A image (879 packages; 461 npm + 413 deb).

---

### 3.7 python:3.8 (Group B)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 5660 | 182 | 1369 | 2957 | 1114 | 3371 (60%) |
| Grype | 2533 | 185 | 652 | 694 | 125 | 1030 (41%) |
| OSV | 2620 | — | — | — | — | — |

- **Largest divergence in the dataset:** Trivy reports 2.24× more findings than Grype.
- CRITICAL near-identical: 182 vs 185 (3-finding gap).
- Trivy LOW count: 8.9× higher than Grype.
- python:3.8 reached EOL in October 2024 — accounts for elevated counts despite a supported (Debian 12) base OS.

---

### 3.8 vulnerables/web-dvwa:latest (Group A)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 1575 | 254 | 551 | 642 | 116 | 1380 (88%) |
| Grype | 2097 | 327 | 760 | 700 | 99 | 1362 (65%) |
| OSV | 336† | — | — | — | — | — |

- Highest CRITICAL count in dataset (254 / 327) — 73-finding gap on CRITICAL alone.
- Grype finds 33% more total findings than Trivy.
- Very high fix availability (88% / 65%) — counts are dominated by accumulated OS-level Debian CVEs, not application logic flaws.

---

### 3.9 bkimminich/juice-shop:latest (Group A)

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 98 | 10 | 47 | 27 | 14 | 83 (85%) |
| Grype | 93 | 10 | 46 | 26 | 4 | 78 (84%) |
| OSV | 94 | — | — | — | — | — |

- **Best cross-tool agreement in the dataset** — all three within 5% of each other.
- CRITICAL and HIGH agreement near-perfect: 10/10, 47/46.
- 1111 npm packages but low vulnerability count — reflects modern dependency hygiene on a current Debian 13 base.
- Fix rate agreement strong: 85% vs 84%.

---

## 4. Performance Benchmark

**30 runs per image per tool.** Trivy DB pre-warmed before the run; `--skip-db-update` used throughout to eliminate DB refresh noise. Images already present locally — no pull time included.

| Grp | Image | Size MB | Trivy mean | ±sd | Grype mean | ±sd | OSV mean | ±sd |
|-----|-------|---------|-----------|-----|-----------|-----|---------|-----|
| C | alpine:3.19 | 3.2 | 189ms | 49ms | 6,915ms | 13,911ms | 2,498ms | 885ms |
| C | nginx:1.29.7 | 60.0 | 386ms | 153ms | 14,917ms | 1,985ms | 18,047ms | 2,401ms |
| C | node:20 | 395.6 | 877ms | 413ms | 98,954ms | 4,356ms | 99,559ms | 9,007ms |
| C | python:3.12 | 399.0 | 861ms | 135ms | 92,428ms | 5,293ms | 101,863ms | 9,305ms |
| B | nginx:1.19 | 47.9 | 268ms | 180ms | 13,473ms | 2,136ms | 14,338ms | 1,968ms |
| B | node:14 | 333.3 | 650ms | 319ms | 83,038ms | 4,057ms | 77,985ms | 4,111ms |
| B | python:3.8 | 357.9 | 1,543ms | 360ms | 93,746ms | 5,417ms | 96,354ms | 5,535ms |
| A | web-dvwa | 64.5 | 597ms | 172ms | 44,004ms | 2,467ms | 45,715ms | 1,492ms |
| A | juice-shop | 170.8 | 353ms | 63ms | 41,152ms | 2,401ms | 45,526ms | 4,816ms |

> **fig1_performance.png** — scan time per tool per image, log scale, mean ± sd
> **fig8_time_vs_size.png** — scan time vs image size scatter with linear fit
> **fig9_scan_boxplot.png** — 30-run distribution box plots per tool

**Key observations:**
- Trivy is **50–130× faster** than Grype and OSV across all images at steady state.
- Grype and OSV scale linearly with image size (r ≈ 0.9); Trivy shows weaker size dependence.
- Grype and OSV are within 10–20% of each other for most images; OSV slightly slower for large images.
- Trivy's SDs are tight (49–413ms); Grype's alpine SD (13,911ms) reflects occasional first-run DB initialisation overhead.

---

## 5. Cross-Tool Comparison

### 5.1 Total Vulnerability Counts

| Grp | Image | Trivy | T-fix% | Grype | G-fix% | OSV† | Trivy/Grype |
|-----|-------|-------|--------|-------|--------|------|-------------|
| C | alpine:3.19 | 6 | 100% | 10 | 60% | 6 | 0.6× |
| C | nginx:1.29.7 | 169 | 0% | 172 | 0% | 177 | 1.0× |
| C | node:20 | 2268 | 1% | 1474 | 1% | 1458 | 1.5× |
| C | python:3.12 | 1751 | 14% | 1418 | 18% | 1422 | 1.2× |
| B | nginx:1.19 | 424 | 79% | 550 | 58% | 132† | 0.8× |
| B | node:14 | 1439 | 77% | 1995 | 34% | 210† | 0.7× |
| B | python:3.8 | 5660 | 60% | 2533 | 41% | 2620 | 2.2× |
| A | web-dvwa | 1575 | 88% | 2097 | 65% | 336† | 0.8× |
| A | juice-shop | 98 | 85% | 93 | 84% | 94 | 1.1× |

†OSV advisory-level count — not directly comparable to CVE-level totals for Debian-based images.

> **fig2_total_findings.png** — total findings grouped bar with divergence ratios

- Trivy inflates totals for OS-heavy images via LOW severity entries absent from Grype's DB.
- Grype exceeds Trivy for npm-heavy images (node:14, web-dvwa) — different npm DB coverage.
- juice-shop and nginx:1.29.7 show the tightest agreement (<5% delta); python:3.8 the widest (2.24×).

---

### 5.2 CVE-Level Overlap (Jaccard Similarity — Trivy vs Grype)

`Jaccard = |T ∩ G| / |T ∪ G|`. Grype GHSA IDs expanded to CVE aliases before comparison.

| Grp | Image | T CVEs | G CVEs | Shared | T-only | G-only | Jaccard |
|-----|-------|--------|--------|--------|--------|--------|---------|
| C | alpine:3.19 | 2 | 4 | 2 | 0 | 2 | 0.500 |
| C | nginx:1.29.7 | 96 | 100 | 92 | 4 | 8 | **0.885** |
| C | node:20 | 1127 | 347 | 329 | 798 | 18 | 0.287 |
| C | python:3.12 | 630 | 284 | 282 | 348 | 2 | 0.446 |
| B | nginx:1.19 | 279 | 353 | 269 | 10 | 84 | 0.741 |
| B | node:14 | 709 | 553 | 240 | 469 | 313 | 0.235 |
| B | python:3.8 | 3684 | 544 | 530 | 3154 | 14 | **0.143** |
| A | web-dvwa | 439 | 590 | 425 | 14 | 165 | 0.704 |
| A | juice-shop | 83 | 143 | 79 | 4 | 64 | 0.537 |

> **fig3_cve_overlap.png** — Jaccard similarity + CVE set composition stacked bars

- Range: 0.143 (python:3.8) to 0.885 (nginx:1.29.7).
- python:3.8: only 530 of 4228 distinct CVE IDs are shared — Trivy reports 3154 CVEs absent from Grype, virtually all LOW.
- EOSL Debian images (nginx:1.19, web-dvwa) show good overlap (0.70–0.74) — consistent EOSL DB coverage between tools.

---

### 5.3 Severity Agreement on Shared CVEs

For CVEs found by **both** tools: fraction receiving the same severity rating. T-higher = Trivy assigned higher severity.

| Grp | Image | Shared | Agree | Agree% | T-higher | G-higher |
|-----|-------|--------|-------|--------|----------|----------|
| C | alpine:3.19 | 2 | 1 | 50% | 1 | 0 |
| C | nginx:1.29.7 | 92 | 30 | 33% | 54 | 8 |
| C | node:20 | 329 | 111 | 34% | 203 | 15 |
| C | python:3.12 | 282 | 95 | 34% | 174 | 13 |
| B | nginx:1.19 | 269 | 259 | **96%** | 4 | 6 |
| B | node:14 | 240 | 196 | 82% | 37 | 7 |
| B | python:3.8 | 530 | 291 | 55% | 213 | 26 |
| A | web-dvwa | 425 | 406 | **96%** | 1 | 18 |
| A | juice-shop | 79 | 6 | **8%** | 71 | 2 |

> **fig4_severity_agreement.png** — severity agreement breakdown per image

- Agreement ranges from 8% (juice-shop) to 96% (nginx:1.19, web-dvwa).
- Group C modern Debian images: only ~33% agreement — Trivy consistently rates higher, reflecting NVD CVSS v3 (theoretical worst-case) vs Grype's GitHub Advisory Database (vendor-conservative).
- Group B EOSL images: 82–96% agreement — older CVEs have more settled severity records.
- juice-shop near-total disagreement: Trivy rates 71 of 79 shared CVEs higher — npm advisory vs NVD divergence.

---

### 5.4 LOW Severity as the Primary Divergence Driver

| Image | Trivy LOW | Grype LOW | Ratio |
|-------|-----------|-----------|-------|
| node:20 | 997 | 67 | 14.9× |
| python:3.12 | 971 | 59 | 16.5× |
| python:3.8 | 1114 | 125 | 8.9× |
| node:14 | 90 | 95 | ~1× |

Trivy's LOW inflation is the principal driver of total count divergence. CRITICAL counts converge across tools (delta ≤3 in 7/9 images) — CRITICAL is the most reliable cross-tool signal. **Policy implication:** total-count thresholds produce inconsistent outcomes depending on which scanner is used.

---

## 6. Policy Evaluation

**Policies tested (Trivy and Grype independently; OSV excluded — no severity breakdown in output):**

| Policy | Definition |
|--------|-----------|
| **P1** | REJECT if CRITICAL count > 0 |
| **P2** | REJECT if CRITICAL count > 0 AND at least one fix available |
| **P3** | REJECT if CRITICAL count > 0 in **both** Trivy and Grype (consensus) |

| Image | Grp | P1 Trivy | P1 Grype | P2 Trivy | P2 Grype | P3 |
|-------|-----|---------|---------|---------|---------|-----|
| alpine:3.19 | C | PASS | PASS | PASS | PASS | PASS |
| nginx:1.29.7 | C | PASS | PASS | PASS | PASS | PASS |
| node:20 | C | REJECT | REJECT | REJECT | REJECT | REJECT |
| python:3.12 | C | PASS | PASS | PASS | PASS | PASS |
| nginx:1.19 | B | REJECT | REJECT | REJECT | REJECT | REJECT |
| node:14 | B | REJECT | REJECT | REJECT | REJECT | REJECT |
| python:3.8 | B | REJECT | REJECT | REJECT | REJECT | REJECT |
| web-dvwa | A | REJECT | REJECT | REJECT | REJECT | REJECT |
| juice-shop | A | REJECT | REJECT | REJECT | REJECT | REJECT |

> **fig6_critical_counts.png** — CRITICAL counts Trivy vs Grype per image

**Key findings:**
- 5 of 9 images rejected by all policies — zero tool-specific P1 discrepancies (wherever one rejects, both reject).
- P3 (consensus) produces identical outcomes to P1 in this dataset — no case where one tool detected CRITICAL and the other did not.
- P1 and P2 produce identical outcomes because every image with CRITICAL vulnerabilities also has at least one fix available. The P1/P2 distinction is only meaningful for images with CRITICAL vulns and zero fixes — not observed here.

---

## 7. SBOM Baseline

| Image | Group | Total pkgs | deb | npm | apk | python | binary | php | java |
|-------|-------|-----------|-----|-----|-----|--------|--------|-----|------|
| alpine:3.19 | C | 15 | — | — | 15 | — | — | — | — |
| nginx:1.29.7 | C | 152 | 151 | — | — | — | — | — | 1 |
| node:20 | C | 619 | 413 | 204 | — | 1 | 1 | — | — |
| python:3.12 | C | 479 | 469 | — | — | 3 | 7 | — | — |
| nginx:1.19 | B | 136 | 135 | — | — | — | — | — | 1 |
| node:14 | B | 879 | 413 | 461 | — | 3 | 2 | — | — |
| python:3.8 | B | 446 | 429 | — | — | 4 | 13 | — | — |
| web-dvwa | A | 221 | 215 | — | — | — | — | 6 | — |
| juice-shop | A | 1125 | 13 | 1111 | — | — | 1 | — | — |

> **fig10_jaccard_packages.png** — package ecosystem breakdown for images with highest Jaccard divergence

- juice-shop: largest surface (1125 packages), 99% npm — yet lowest vulnerability count among Group A, reflecting modern dependency hygiene.
- node:14: largest combined deb+npm (874) — explains high total count.
- python images: no npm; all vulnerability counts are OS-level.
- Binary packages (Syft-detected) indicate out-of-package-manager installations.

---

## 8. CWE Analysis

Top 10 CWEs across all 9 images (Trivy + Grype combined):

| CWE | Description | Trivy | Grype | Combined |
|-----|-------------|-------|-------|---------|
| CWE-476 | NULL Pointer Dereference | 855 | 225 | **1080** |
| CWE-416 | Use After Free | 601 | 137 | 738 |
| CWE-125 | Out-of-bounds Read | 396 | 336 | 732 |
| CWE-787 | Out-of-bounds Write | 354 | 328 | 682 |
| CWE-190 | Integer Overflow | 199 | 224 | 423 |
| CWE-119 | Improper Memory Operations | 182 | 221 | 403 |
| CWE-401 | Missing Memory Release | 245 | 107 | 352 |
| CWE-400 | Uncontrolled Resource Consumption | 118 | 137 | 255 |
| CWE-362 | Race Condition | 206 | 28 | 234 |
| CWE-122 | Heap-Based Buffer Overflow | 99 | 104 | 203 |

> **fig7_cwe_top10.png** — top 10 CWE types across all images
> **fig5_fix_rates.png** — fix rate % per image per tool

Memory-safety weaknesses (CWE-476, 416, 125, 787) account for the top four positions — consistent with C/C++ OS package vulnerability patterns. The OS base layer is the dominant risk source across all image groups.

---

## 9. Key Findings

| # | Finding |
|---|---------|
| 1 | Trivy reports 1.2–2.2× more total findings than Grype for Debian OS-heavy images, driven by LOW severity inflation (8–16× more LOW entries). |
| 2 | CRITICAL counts converge across tools (delta ≤3 in 7/9 images) — the most reliable cross-tool signal for policy use. |
| 3 | CVE-level overlap (Jaccard) ranges from 0.14 (python:3.8) to 0.89 (nginx:1.29.7) — tools do not agree on which CVEs to report. |
| 4 | Severity agreement on shared CVEs ranges from 8% (juice-shop) to 96% (nginx:1.19). Trivy rates higher than Grype in 8 of 9 images, reflecting NVD vs vendor advisory score differences. |
| 5 | Fix rate divergence is significant: node:14 Trivy 77% vs Grype 34%; python:3.8 60% vs 41% — same image, same CVEs, different fixability signals. |
| 6 | Trivy is 50–130× faster than Grype and OSV at steady state (30-run benchmark, pre-warmed DB). |
| 7 | Top CWEs are memory-safety weaknesses (CWE-476, 416, 125, 787) — OS base layer dominates risk profile regardless of image group. |
| 8 | P1/P2/P3 policies produce identical outcomes in this dataset. All images with CRITICAL findings had at least one fix available; no tool-specific CRITICAL discrepancies were observed. |
| 9 | OS base age is the primary driver of CRITICAL count — web-dvwa (Debian 9.5, 254 CRITICAL) vs juice-shop (Debian 13.4, 10 CRITICAL), both intentionally vulnerable applications. |
| 10 | OSV-Scanner advisory-level output is not directly comparable to Trivy/Grype CVE-level counts for Debian images. OSV is most comparable for npm/python ecosystems. |
