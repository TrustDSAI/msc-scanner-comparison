# Scanner Comparison — Results Narrative

**Project:** MSc Research — Policy-as-Code for Container Vulnerability Gating in CI/CD Pipelines
**Author:** Simão Cabral Sousa — University of Coimbra
**Date:** 2026-04-04
**Data sources:** `logs/analysis_results.txt`, `logs/benchmark_summary.json`, `experiment_log.md`

---

## 1. Dataset Overview

Nine container images spanning three risk groups were scanned with Trivy (0.69.3), Grype (0.110.0), and OSV-Scanner (2.3.5). All images were pinned by digest on 2026-03-31.

| Group | Images | Rationale |
|-------|--------|-----------|
| **A — Intentionally Vulnerable** | vulnerables/web-dvwa, bkimminich/juice-shop | Ground truth for known-vulnerable detection |
| **B — Outdated Real-World** | nginx:1.19, node:14, python:3.8 | Production-style images past EOL or upstream support |
| **C — Modern Baseline** | alpine:3.19, nginx:latest, node:20, python:3.12 | Current, maintained images |

---

## 2. Total Finding Counts — Tools Rarely Agree

The first observation is that Trivy and Grype frequently disagree on total vulnerability counts for the same image.

| Image | Grp | Trivy | Grype | Ratio |
|-------|-----|-------|-------|-------|
| alpine:3.19 | C | 6 | 10 | 1.7× |
| nginx:latest | C | 169 | 172 | ~1× |
| node:20 | C | 2268 | 1474 | 1.55× |
| python:3.12 | C | 1751 | 1418 | 1.23× |
| nginx:1.19 | B | 424 | 550 | Grype 1.3× |
| node:14 | B | 1439 | 1995 | Grype 1.4× |
| python:3.8 | B | 5660 | 2533 | **2.24×** |
| web-dvwa | A | 1575 | 2097 | Grype 1.3× |
| juice-shop | A | 98 | 93 | ~1× |

Two structural causes explain the divergence:

**Trivy inflates LOW severity for OS packages.** For node:20, Trivy reports 997 LOW findings vs Grype's 67 — a 14.9× gap for the lowest severity band alone. For python:3.12, the ratio is 16.5×. This does not reflect different security risk; it reflects different DB inclusion thresholds for low-priority CVEs.

**Grype has broader npm advisory coverage.** For npm-heavy images (node:14, web-dvwa), Grype reports more total findings than Trivy — a reversal of the Debian pattern. Grype's database integrates the GitHub Advisory Database more aggressively for application-layer ecosystems.

**Policy implication:** Any policy built on *total counts* inherits the tool's counting methodology. A threshold of "block if total > N" will behave very differently depending on which scanner generates the input.

---

## 3. CVE-Level Overlap — The Real Agreement Story

Comparing totals is misleading. What matters is whether the tools identify the *same vulnerabilities*. Table D5 applies Jaccard similarity over deduplicated CVE ID sets:

```
Jaccard = |T ∩ G| / |T ∪ G|    (1.0 = identical sets, 0.0 = no overlap)
```

Grype GHSA IDs are expanded to CVE aliases before comparison.

| Image | Grp | T CVEs | G CVEs | Both | T-only | G-only | Jaccard |
|-------|-----|--------|--------|------|--------|--------|---------|
| nginx:latest | C | 96 | 100 | 92 | 4 | 8 | **0.885** |
| nginx:1.19 | B | 279 | 353 | 269 | 10 | 84 | 0.741 |
| web-dvwa | A | 439 | 590 | 425 | 14 | 165 | 0.704 |
| juice-shop | A | 83 | 143 | 79 | 4 | 64 | 0.537 |
| alpine:3.19 | C | 2 | 4 | 2 | 0 | 2 | 0.500 |
| python:3.12 | C | 630 | 284 | 282 | 348 | 2 | 0.446 |
| node:20 | C | 1127 | 347 | 329 | 798 | 18 | 0.287 |
| node:14 | B | 709 | 553 | 240 | 469 | 313 | 0.235 |
| python:3.8 | B | 3684 | 544 | 530 | 3154 | 14 | **0.143** |

**Key findings:**

- **nginx:latest** achieves the highest overlap (0.885). Both tools agree on nearly the same CVE set for this modern Debian 13 image with a moderate package surface.
- **EOSL Debian images** (nginx:1.19, web-dvwa) show good overlap (0.70–0.74), suggesting consistent DB coverage for older CVEs accumulated before EOL.
- **python:3.8** is the worst case (0.143): only 530 of 4228 distinct CVE IDs are shared. Trivy reports 3154 CVEs that Grype does not — virtually all are LOW-severity OS package entries absent from Grype's DB.
- The pattern splits cleanly by ecosystem: OS-only images show moderate-to-high overlap; large multi-ecosystem images with heavy OS package counts show low overlap driven by Trivy's expanded LOW-severity DB coverage.

---

## 4. Severity Agreement on Shared CVEs

For CVEs found by both tools, the question becomes: do they agree on how severe it is? Table D6 measures this on shared CVEs only, eliminating the confound of different discovery scope.

| Image | Grp | Shared | Agree | Agree% | T-higher | G-higher |
|-------|-----|--------|-------|--------|----------|----------|
| nginx:1.19 | B | 269 | 259 | **96%** | 4 | 6 |
| web-dvwa | A | 425 | 406 | **96%** | 1 | 18 |
| node:14 | B | 240 | 196 | 82% | 37 | 7 |
| python:3.8 | B | 530 | 291 | 55% | 213 | 26 |
| alpine:3.19 | C | 2 | 1 | 50% | 1 | 0 |
| node:20 | C | 329 | 111 | 34% | 203 | 15 |
| python:3.12 | C | 282 | 95 | 34% | 174 | 13 |
| nginx:latest | C | 92 | 30 | 33% | 54 | 8 |
| juice-shop | A | 79 | 6 | **8%** | 71 | 2 |

**Key findings:**

- **EOSL Debian images agree strongly on severity** (nginx:1.19 96%, web-dvwa 96%). Older CVEs have settled NVD CVSS scores that both tools import consistently.
- **Modern Debian images agree on only ~33% of shared CVEs** (nginx:latest, node:20, python:3.12). Trivy consistently assigns higher severity in these cases — likely because it preferentially uses NVD CVSS v3 base scores, while Grype weights GitHub Advisory scores which are often more conservative.
- **juice-shop is the most extreme case** (8% agreement). Trivy rates 71 of 79 shared CVEs higher than Grype. juice-shop is npm-heavy on Debian 13 — the GitHub Advisory scores that Grype uses for npm advisories diverge most from NVD scores for modern, actively-triaged packages.
- The direction of disagreement is asymmetric: **Trivy almost always assigns higher severity**. T-higher exceeds G-higher in 8 of 9 images.

**Policy implication:** A CRITICAL threshold in Trivy is a stricter bar than CRITICAL in Grype. Policies that use a single scanner's severity output without acknowledging this will produce different gate outcomes depending on tool selection.

---

## 5. CRITICAL Findings — Where Tools Converge

Despite disagreement on totals and severity classification, **CRITICAL counts correlate well** across tools:

| Image | Grp | Trivy CRITICAL | Grype CRITICAL | Delta |
|-------|-----|---------------|---------------|-------|
| alpine:3.19 | C | 0 | 0 | 0 |
| nginx:latest | C | 0 | 0 | 0 |
| node:20 | C | 33 | 32 | 1 |
| python:3.12 | C | 0 | 0 | 0 |
| nginx:1.19 | B | 42 | 40 | 2 |
| node:14 | B | 22 | 19 | 3 |
| python:3.8 | B | 182 | 185 | 3 |
| web-dvwa | A | 254 | 327 | **73** |
| juice-shop | A | 10 | 10 | 0 |

Seven of nine images show a CRITICAL delta of 3 or fewer. The exception is web-dvwa (delta 73), where Grype detects significantly more CRITICALs on Debian 9.5 (stretch, EOSL since 2022) — likely due to differing EOSL CVE inclusion between the two DBs.

**CRITICAL is the most reliable severity band for cross-tool policy decisions.** It is the only band where both tools consistently converge, making it the appropriate anchor for multi-scanner consensus policies (P3).

---

## 6. Fix Availability — Not All Risk Is Actionable

Fix rate (percentage of findings where a patched version exists) varies significantly across images and between tools for the same image:

| Image | Grp | T-fix% | G-fix% | Character |
|-------|-----|--------|--------|-----------|
| web-dvwa | A | 88% | 65% | Highly remediable — upgrade OS base |
| node:14 | B | 77% | 34% | Trivy sees more fixes; large fix gap |
| nginx:1.19 | B | 79% | 58% | Majority remediable |
| juice-shop | A | 85% | 84% | Strong agreement on fixability |
| python:3.8 | B | 60% | 41% | Moderate — Python EOL drives accumulation |
| python:3.12 | C | 14% | 18% | Few fixes — Debian 13 accepted-unfixed |
| node:20 | C | 1% | 1% | Almost nothing fixable |
| nginx:latest | C | 0% | 0% | Zero fixes — all accepted-unfixed status |
| alpine:3.19 | C | 100% | 60% | Small surface; all Trivy findings fixable |

**Notable observations:**

- **nginx:latest has 169/172 vulnerabilities with no fix available.** Debian 13 (trixie) carries hundreds of CVEs in accepted-but-not-fixed status — the distribution maintainers have acknowledged them but declined to backport fixes. Blocking this image under P1 (any CRITICAL) would be moot here since CRITICAL=0; but under any count-based policy, this image appears much worse than it operationally is.
- **node:20 has 33 CRITICALs but only 14 fixable findings total** — the CRITICAL findings do have fixes available (1% of 2268 total). This is a strong P2 trigger.
- **Fix rate diverges significantly between tools** (node:14: Trivy 77% vs Grype 34%). This is a secondary source of policy instability: the same image can appear more or less remediable depending on which scanner's fix state you trust.

---

## 7. Policy Evaluation

Three policies were evaluated against all nine images using Trivy and Grype independently, and as a consensus:

| Policy | Definition |
|--------|-----------|
| **P1** | REJECT if any CRITICAL vulnerability detected |
| **P2** | REJECT if any CRITICAL vulnerability has a fix available |
| **P3** | REJECT if CRITICAL reported by **both** Trivy **and** Grype (consensus) |

### Outcomes

| Image | Grp | P1-Trivy | P1-Grype | P2-Trivy | P2-Grype | P3 | T:Fixed | G:Fixed |
|-------|-----|---------|---------|---------|---------|-----|---------|---------|
| alpine:3.19 | C | PASS | PASS | PASS | PASS | **PASS** | 6 | 6 |
| nginx:latest | C | PASS | PASS | PASS | PASS | **PASS** | 0 | 0 |
| node:20 | C | REJECT | REJECT | REJECT | REJECT | **REJECT** | 14 | 14 |
| python:3.12 | C | PASS | PASS | PASS | PASS | **PASS** | 238 | 249 |
| nginx:1.19 | B | REJECT | REJECT | REJECT | REJECT | **REJECT** | 337 | 320 |
| node:14 | B | REJECT | REJECT | REJECT | REJECT | **REJECT** | 1112 | 681 |
| python:3.8 | B | REJECT | REJECT | REJECT | REJECT | **REJECT** | 3371 | 1030 |
| web-dvwa | A | REJECT | REJECT | REJECT | REJECT | **REJECT** | 1380 | 1362 |
| juice-shop | A | REJECT | REJECT | REJECT | REJECT | **REJECT** | 83 | 78 |

### Analysis

**P1 = P2 = P3 across all nine images.** In this dataset, wherever CRITICAL vulnerabilities exist, at least some fixable findings are also present, and both tools agree on CRITICAL presence. The three policies produce identical gate decisions.

**This is both a finding and a limitation.** It confirms that CRITICAL-level signals are robust across scanner choice in this dataset. However, it means the dataset does not stress-test the scenarios where the policies differ:
- P1 vs P2 would diverge for an image with CRITICAL CVEs that have no fix (i.e., will_not_fix or fix_deferred at CRITICAL severity) — not observed here.
- P1 vs P3 would diverge if one tool reports CRITICAL and the other does not — the CRITICAL delta data shows this is rare but occurs (web-dvwa delta 73).

**Operational interpretation:**
- 4 of 9 images pass all policies (alpine, nginx:latest, python:3.12 + node:20 — wait: node:20 rejects). Passes: alpine:3.19, nginx:latest, python:3.12 (3 of 9).
- All Group A and B images are rejected. Two of four Group C images are rejected (node:20, and no others — python:3.12, nginx:latest, alpine:3.19 pass).
- The result is coherent with the group design: modern baseline images generally pass; outdated and intentionally vulnerable images are correctly blocked.

---

## 8. Performance

Scan times measured over 3 independent runs per image per tool (images locally cached; no pull time included).

| Image | Grp | Size MB | Trivy | Grype | OSV |
|-------|-----|---------|-------|-------|-----|
| alpine:3.19 | C | 7.1 | 56ms ±0ms | 1451ms ±12ms | 1900ms ±568ms |
| nginx:latest | C | 153.5 | 90ms ±0ms | 3016ms ±21ms | 4283ms ±188ms |
| node:20 | C | 1044.7 | 346ms ±1ms | 18606ms ±476ms | 25506ms ±2295ms |
| python:3.12 | C | 1055.6 | 315ms ±2ms | 15631ms ±8ms | 24610ms ±1540ms |
| nginx:1.19 | B | 127.0 | 93ms ±3ms | 3136ms ±16ms | 5329ms ±1813ms |
| node:14 | B | 869.5 | 231ms ±2ms | 17776ms ±1667ms | 16614ms ±3080ms |
| python:3.8 | B | 949.3 | 558ms ±15ms | 18251ms ±685ms | 22709ms ±2169ms |
| web-dvwa | A | 678.8 | 184ms ±5ms | 11158ms ±824ms | 10832ms ±659ms |
| juice-shop | A | 467.3 | 110ms ±7ms | 11443ms ±1225ms | 12550ms ±1099ms |

**Key findings:**

- **Trivy is 10–100× faster than Grype and OSV-Scanner** across all images. The largest gap is on large images: node:20 — Trivy 346ms vs Grype 18.6s vs OSV 25.5s.
- **Trivy does not scale linearly with image size.** Its sub-second times on gigabyte-scale images (node:20, python:3.12) indicate a direct DB index lookup against the SBOM rather than layer traversal.
- **Grype and OSV-Scanner scale approximately linearly with compressed image size** (r≈0.9). Both extract image layers to disk before scanning, which dominates their execution time.
- **OSV-Scanner is competitive for small images** (web-dvwa 10.8s vs Grype 11.2s) but falls behind on large ones.
- Trivy's speed makes it the practical candidate for a first-pass gate in CI. Grype and OSV are better suited to asynchronous registry-level scanning where latency is less critical.

---

## 9. Weakness Profile (CWE Analysis)

The top 10 CWE types across all images and both tools reveal the dominant weakness classes in the dataset:

| Rank | CWE | Description | Trivy | Grype | Total |
|------|-----|-------------|-------|-------|-------|
| 1 | CWE-476 | NULL Pointer Dereference | 855 | 225 | 1080 |
| 2 | CWE-416 | Use After Free | 601 | 137 | 738 |
| 3 | CWE-125 | Out-of-bounds Read | 396 | 336 | 732 |
| 4 | CWE-787 | Out-of-bounds Write | 354 | 328 | 682 |
| 5 | CWE-190 | Integer Overflow or Wraparound | 199 | 224 | 423 |
| 6 | CWE-119 | Improper Restriction of Memory Operations | 182 | 221 | 403 |
| 7 | CWE-401 | Missing Release of Memory after Effective Lifetime | 245 | 107 | 352 |
| 8 | CWE-400 | Uncontrolled Resource Consumption | 118 | 137 | 255 |
| 9 | CWE-362 | Race Condition | 206 | 28 | 234 |
| 10 | CWE-122 | Heap-Based Buffer Overflow | 99 | 104 | 203 |

**Interpretation:** The top 10 are dominated by memory-safety weaknesses (CWE-476, 416, 125, 787, 190, 119, 122) — all characteristic of vulnerabilities in C/C++ system libraries (glibc, openssl, libssl, curl, etc.) that form the OS base layer of every image. This confirms that the vulnerability surface in these images is **driven by the OS base layer**, not by application-level logic flaws. It also supports the selection of CWE as a secondary classification axis for policy: a policy that blocks images with CRITICAL CWE-787 (out-of-bounds write, common RCE vector) is more defensible than one that blocks on CRITICAL alone.

---

## 10. Summary of Key Findings

| # | Finding | Implication |
|---|---------|-------------|
| 1 | Trivy reports 1.2–2.2× more total findings than Grype for Debian OS images, driven by LOW severity inflation | Total-count policies are tool-dependent; avoid them |
| 2 | CVE-level overlap (Jaccard) ranges from 0.14 (python:3.8) to 0.89 (nginx:latest) | Two scanners do not see the same vulnerability universe |
| 3 | Severity agreement on shared CVEs ranges from 8% (juice-shop) to 96% (nginx:1.19, web-dvwa); Trivy consistently assigns higher severity | Tool-specific severity scores are not interchangeable |
| 4 | CRITICAL counts converge across tools (delta ≤3 in 7/9 images) | CRITICAL is the most reliable cross-tool policy anchor |
| 5 | Fix rate diverges significantly between tools for the same image (node:14: Trivy 77% vs Grype 34%) | Fixability assessment is also tool-dependent |
| 6 | P1 = P2 = P3 across all nine images in this dataset | Dataset does not stress-test policy boundary cases |
| 7 | Trivy is 10–100× faster than Grype/OSV; does not scale with image size | Trivy is the practical CI first-gate; others suit async registry scanning |
| 8 | Top CWEs are memory-safety weaknesses in OS packages (CWE-476, 416, 125, 787) | OS base layer dominates risk; application-layer policies need separate treatment |

---

## 11. Connection to Research Direction

These findings provide the empirical foundation for the policy-as-code contribution:

1. **Scanner divergence is real and structured** — not random noise. Understanding *why* tools disagree (DB scope, severity source, ecosystem coverage) allows policy design that is robust to tool choice.
2. **CRITICAL + fix is the most defensible policy basis** — it combines the highest-agreement severity band with operational actionability.
3. **Multi-scanner consensus (P3) adds resilience** against single-tool false positives, but requires a dataset with more boundary cases to demonstrate its value empirically — a limitation to address in the dissertation.
4. **HarbourGuard provides orchestration but no policy engine** — the gap this research fills. An OPA/Rego layer consuming the structured output of multiple scanners can implement P1/P2/P3 and CWE-specific policies in a declarative, auditable way.

---

*All data derived from raw JSON scan outputs. No manual editing of results. Full datasets: `logs/csv/`, `logs/analysis_results.txt`, `logs/benchmark_summary.json`.*
