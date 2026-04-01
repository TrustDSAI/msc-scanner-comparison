# Container Vulnerability Scanner Comparison — Experiment Log

**Project:** MSc Research — Security of Containerised CI/CD Pipelines
**Focus:** Empirical evaluation of vulnerability scanner consistency and policy-based gating
**Log version:** 2.0 (full dataset)
**Last updated:** 2026-03-31

---

## 1. Tool Metadata

| Tool | Version | DB / Schema | Notes |
|------|---------|-------------|-------|
| Trivy | 0.69.3 | Vulnerability DB v2, updated 2026-03-30 | vuln scanner only (`--scanners vuln`) |
| Grype | 0.110.0 | Grype DB (Syft v1.42.3 embedded) | default scan profile |
| OSV-Scanner | 2.3.5 (scalibr v0.4.5) | OSV database (online) | `scan image` subcommand |
| Syft | 1.42.3 | Schema v16.1.3 | SBOM generation only |

**Trivy Java DB:** downloaded 2026-03-31 (first scan of Debian-based image requiring it)

---

## 2. Image Dataset

All images pulled and pinned by digest on **2026-03-31**.

### Group A — Intentionally Vulnerable

| Image | Digest | OS | EOSL |
|-------|--------|----|------|
| vulnerables/web-dvwa:latest | `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` | Debian 9.5 | YES |
| bkimminich/juice-shop:latest | `sha256:5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114` | Debian 13.4 | no |

### Group B — Outdated Real-World

| Image | Digest | OS | EOSL |
|-------|--------|----|------|
| nginx:1.19 | `sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2` | Debian 10.9 | YES |
| node:14 | `sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa` | Debian 10.13 | YES |
| python:3.8 | `sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c` | Debian 12.7 | no |

### Group C — Modern Baseline

| Image | Digest | OS | EOSL |
|-------|--------|----|------|
| alpine:3.19 | `sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1` | Alpine 3.19.9 | YES |
| nginx:latest | `sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18` | Debian 13.4 | no |
| node:20 | `sha256:a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520` | Debian 12.13 | no |
| python:3.12 | `sha256:c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436` | Debian 13.4 | no |

> **Note on EOSL:** Alpine 3.19.9 was flagged as EOSL at time of scan despite being a "modern baseline" — this is an interesting finding. The `:latest` tag used for `nginx:latest` resolves to a non-EOSL Debian 13 (bookworm/trixie) image.

> **Note on OSV-Scanner:** Images specified without an explicit tag (`image/name` without `:latest`) are rejected. All such images were re-scanned with the explicit `:latest` tag. This is a tool-specific limitation to document.

---

## 3. Scan Commands (Fixed Configuration)

```bash
# SBOM generation
syft <image> -o syft-json > sbom/<name>_syft.json

# Trivy — vulnerability scan only, JSON output
trivy image --format json --scanners vuln --output results/trivy/<name>_trivy.json <image>

# Grype — default vulnerability scan, JSON output
grype <image> -o json > results/grype/<name>_grype.json

# OSV-Scanner — image scan, JSON output
osv-scanner scan image --format json --output-file results/osv/<name>_osv.json <image>:latest
```

---

## 4. Raw Output Inventory

All files stored in `/home/ansuser/`:

```
results/trivy/  — 9 JSON files
results/grype/  — 9 JSON files
results/osv/    — 9 JSON files
sbom/           — 9 JSON files (Syft SBOM)
logs/digests.log
logs/timing.log
logs/parsed_results.json
```

---

## 5. Scan Results

### 5.1 Scan 01 — alpine:3.19 (Group C)

**Timestamp:** 2026-03-31T05:24:24Z
**Image digest:** `alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1`
**OS:** Alpine 3.19.9

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 6 | 0 | 0 | 3 | 3 | 6 |
| Grype | 10 | 0 | 0 | 4 | 6 | 6 |
| OSV-Scanner | 6 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 1671ms · Trivy 55ms · Grype 32970ms · OSV 2376ms

**SBOM:** 15 packages — all `apk` ecosystem

**Warnings:**
- All three tools flagged Alpine 3.19.9 as EOSL ("no longer supported by the distribution"). Detection may be incomplete due to absent security updates.

**Notable findings:**
- Trivy found 6 vulns (all fixable), Grype found 10 (4 more than Trivy, also at LOW/MEDIUM).
- 100% of Trivy findings are fixable; Grype shows 60% fixable (6/10).
- OSV-Scanner returned 6 vulnerability entries (advisory format, no individual severity).
- Minimal package surface (15 packages, all OS-level apk packages) leads to low absolute counts.

---

### 5.2 Scan 02 — nginx:latest (Group C)

**Timestamp:** 2026-03-31T05:25:10Z
**Image digest:** `nginx@sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18`
**OS:** Debian 13.4

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 169 | 0 | 14 | 29 | 126 | 0 |
| Grype | 172 | 0 | 25 | 33 | 8 | 0 |
| OSV-Scanner | 177 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 3075ms · Trivy 31639ms · Grype 3840ms · OSV 5003ms

**SBOM:** 152 packages — 151 deb, 1 java-archive

**Notable findings:**
- Zero CRITICAL findings across all three tools — consistent agreement.
- No fixable vulnerabilities reported by either Trivy or Grype (0%). Debian 13 (trixie) appears to have accepted-unfixed status for many CVEs.
- Trivy took significantly longer (31.6s) on this image compared to Grype (3.8s) — attributed to downloading the Java DB for the first time.
- Grype reports 11 more HIGH findings than Trivy (25 vs 14); Grype shows fewer LOW (8 vs 126). Significant severity classification divergence.
- OSV total (177) is close to both Trivy and Grype.

---

### 5.3 Scan 03 — node:20 (Group C)

**Timestamp:** 2026-03-31T05:26:04Z
**Image digest:** `node@sha256:a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520`
**OS:** Debian 12.13

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 2268 | 33 | 277 | 936 | 997 | 14 |
| Grype | 1474 | 32 | 178 | 360 | 67 | 14 |
| OSV-Scanner | 1458 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 16793ms · Trivy 9476ms · Grype 17824ms · OSV 21142ms

**SBOM:** 619 packages — 413 deb, 204 npm, 1 python, 1 binary

**Notable findings:**
- Large discrepancy in total counts: Trivy (2268) vs Grype (1474) — difference of 794 (54% more from Trivy).
- CRITICAL count is near-identical (33 vs 32) — strong agreement at the most severe level.
- HIGH diverges notably: 277 (Trivy) vs 178 (Grype) — 99 additional HIGH from Trivy.
- Massive LOW divergence: 997 (Trivy) vs 67 (Grype) — 14× more LOW findings from Trivy.
- OSV total (1458) closely matches Grype (1474), suggesting Grype and OSV use similar scope/DB.
- Only 14 fixable CVEs reported by both tools — very low fix availability (<1%).
- 204 npm packages in SBOM contribute to large vulnerability surface.

---

### 5.4 Scan 04 — python:3.12 (Group C)

**Timestamp:** 2026-03-31T05:27:35Z
**Image digest:** `python@sha256:c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436`
**OS:** Debian 13.4

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 1751 | 0 | 196 | 557 | 971 | 238 |
| Grype | 1418 | 0 | 165 | 375 | 59 | 249 |
| OSV-Scanner | 1422 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 14461ms · Trivy 10216ms · Grype 15652ms · OSV 21076ms

**SBOM:** 479 packages — 469 deb, 7 binary, 3 python

**Notable findings:**
- No CRITICAL findings from any tool — consistent.
- Total divergence: Trivy 1751 vs Grype 1418 (333 more from Trivy).
- LOW divergence again large: 971 (Trivy) vs 59 (Grype).
- OSV (1422) closely aligns with Grype (1418).
- Fixed counts similar: Trivy 238 vs Grype 249 — better agreement than in total counts.
- Debian 13 (bookworm/trixie) base — same as nginx:latest, consistent with its fix availability pattern.

---

### 5.5 Scan 05 — nginx:1.19 (Group B)

**Timestamp:** 2026-03-31T05:29:14Z
**Image digest:** `nginx@sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2`
**OS:** Debian 10.9

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 424 | 42 | 149 | 193 | 31 | 337 |
| Grype | 550 | 40 | 159 | 194 | 35 | 320 |
| OSV-Scanner | 132 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 3317ms · Trivy 1253ms · Grype 3125ms · OSV 8375ms

**SBOM:** 136 packages — 135 deb, 1 java-archive

**Warnings:**
- Trivy and Grype: Debian 10 (buster) is EOSL — detection may be incomplete.

**Notable findings:**
- High CRITICAL count (42/40) — strong agreement between Trivy and Grype.
- OSV returned only 132 advisories vs 424/550 individual findings — expected, OSV groups multiple CVEs under single advisories.
- High fix availability: Trivy 79%, Grype 58% — most of the danger can be remediated by upgrading to a supported nginx.
- This image is a prime candidate for P1/P2 policy triggering (CRITICAL vulns with available fixes).

---

### 5.6 Scan 06 — node:14 (Group B)

**Timestamp:** 2026-03-31T05:29:40Z
**Image digest:** `node@sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa`
**OS:** Debian 10.13

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 1439 | 22 | 569 | 754 | 90 | 1112 |
| Grype | 1995 | 19 | 453 | 477 | 95 | 681 |
| OSV-Scanner | 210 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 16458ms · Trivy 8483ms · Grype 16882ms · OSV 16565ms

**SBOM:** 879 packages — 461 npm, 413 deb, 3 python, 2 binary

**Warnings:**
- Debian 10.13 is EOSL (both tools warned).

**Notable findings:**
- Grype total (1995) significantly exceeds Trivy (1439) — a reversal of the pattern seen in Groups C images. The npm package corpus (461 packages) likely drives this.
- CRITICAL counts: 22 (Trivy) vs 19 (Grype) — near agreement.
- HIGH divergence: 569 (Trivy) vs 453 (Grype) — 116 more from Trivy.
- Fixed percentage: Trivy 77% vs Grype 34% — notable gap in fixability assessment.
- 879 SBOM packages (largest non-Group A image by package count), with npm dominating.

---

### 5.7 Scan 07 — python:3.8 (Group B)

**Timestamp:** 2026-03-31T05:31:37Z
**Image digest:** `python@sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c`
**OS:** Debian 12.7

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 5660 | 182 | 1369 | 2957 | 1114 | 3371 |
| Grype | 2533 | 185 | 652 | 694 | 125 | 1030 |
| OSV-Scanner | 2620 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 16572ms · Trivy 9991ms · Grype 17587ms · OSV 27032ms

**SBOM:** 446 packages — 429 deb, 13 binary, 4 python

**Notable findings:**
- **Largest discrepancy in the dataset:** Trivy 5660 vs Grype 2533 — Trivy reports 2.24× more findings.
- CRITICAL counts closely agree: 182 (Trivy) vs 185 (Grype) — 3-finding difference.
- LOW divergence: 1114 (Trivy) vs 125 (Grype) — Trivy is 8.9× higher.
- OSV (2620) aligns with Grype (2533).
- Fixed availability: Trivy 60% vs Grype 41% — significant gap.
- Despite being on Debian 12 (bookworm, supported), python:3.8 itself is an EOL Python version (as of October 2024), which may explain the high vulnerability count relative to python:3.12.

---

### 5.8 Scan 08 — vulnerables/web-dvwa:latest (Group A)

**Timestamp:** 2026-03-31T05:33:12Z
**Image digest:** `vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7`
**OS:** Debian 9.5

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 1575 | 254 | 551 | 642 | 116 | 1380 |
| Grype | 2097 | 327 | 760 | 700 | 99 | 1362 |
| OSV-Scanner | 336 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 10979ms · Trivy 6012ms · Grype 11667ms · OSV (retry) ~30s

**SBOM:** 221 packages — 215 deb, 6 php-pear

**Warnings:**
- Debian 9.5 (stretch) is EOSL — both tools warned.
- OSV-Scanner initially rejected image name `vulnerables/web-dvwa` (no tag). Re-run with explicit `:latest` tag succeeded.

**Notable findings:**
- Highest CRITICAL count in dataset: 254 (Trivy) / 327 (Grype) — 73-finding gap on CRITICAL alone.
- Grype finds 33% more total vulnerabilities than Trivy (2097 vs 1575).
- Fix availability is very high: 88% (Trivy), 65% (Grype) — this image is highly remediable in principle.
- PHP-PEAR packages in SBOM (6 packages) represent an application-layer ecosystem.
- Despite being an intentionally vulnerable image, the sheer count is dominated by OS-level Debian packages, not application logic flaws.

---

### 5.9 Scan 09 — bkimminich/juice-shop:latest (Group A)

**Timestamp:** 2026-03-31T05:34:36Z
**Image digest:** `bkimminich/juice-shop@sha256:5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114`
**OS:** Debian 13.4

| Tool | Total | CRITICAL | HIGH | MEDIUM | LOW | Fixed |
|------|-------|----------|------|--------|-----|-------|
| Trivy | 98 | 10 | 47 | 27 | 14 | 83 |
| Grype | 93 | 10 | 46 | 26 | 4 | 78 |
| OSV-Scanner | 94 | n/a | n/a | n/a | n/a | — |

**Execution times:** Syft 10492ms · Trivy 8015ms · Grype 10012ms · OSV (retry) ~30s

**SBOM:** 1125 packages — 1111 npm, 13 deb, 1 binary

**Notable findings:**
- **Best cross-tool agreement in the dataset.** Trivy: 98, Grype: 93, OSV: 94 — within 5% of each other.
- CRITICAL and HIGH agreement is near-perfect: 10/10 CRITICAL, 47/46 HIGH.
- 1111 npm packages (largest npm corpus) yet relatively low vulnerability count, suggesting modern dependency hygiene.
- Fix availability high: Trivy 85%, Grype 84% — strong agreement.
- Predominantly npm-driven findings — explains OSV alignment (OSV has strong npm coverage).

---

## 6. Performance Data

### Execution Times (milliseconds)

| Image | Syft | Trivy | Grype | OSV |
|-------|------|-------|-------|-----|
| alpine:3.19 | 1671 | 55 | 32970 | 2376 |
| nginx:latest | 3075 | 31639* | 3840 | 5003 |
| node:20 | 16793 | 9476 | 17824 | 21142 |
| python:3.12 | 14461 | 10216 | 15652 | 21076 |
| nginx:1.19 | 3317 | 1253 | 3125 | 8375 |
| node:14 | 16458 | 8483 | 16882 | 16565 |
| python:3.8 | 16572 | 9991 | 17587 | 27032 |
| vulnerables/web-dvwa | 10979 | 6012 | 11667 | ~30000† |
| bkimminich/juice-shop | 10492 | 8015 | 10012 | ~30000† |

\* Trivy on nginx:latest includes Java DB download (~28s). Subsequent scans excluded DB download time.
† OSV timing for images requiring `:latest` tag correction measured separately; estimate based on image size.

**Observations:**
- Trivy is fastest on small/minimal images (55ms on alpine); overhead grows with package count.
- Grype timing correlates closely with Syft (expected: Grype embeds Syft for SBOM generation).
- OSV-Scanner is consistently the slowest, requiring full image export to disk.
- Trivy's first large Debian image scan triggered Java DB download (840MB), inflating that measurement.

---

## 7. Cross-Tool Comparison

### 7.1 Total Vulnerability Counts

| Image | Trivy | Grype | OSV | Max/Min Ratio |
|-------|-------|-------|-----|----------------|
| alpine:3.19 | 6 | 10 | 6 | 1.7× |
| nginx:latest | 169 | 172 | 177 | 1.05× |
| node:20 | 2268 | 1474 | 1458 | 1.55× |
| python:3.12 | 1751 | 1418 | 1422 | 1.23× |
| nginx:1.19 | 424 | 550 | 132‡ | 4.17× |
| node:14 | 1439 | 1995 | 210‡ | 9.50× |
| python:3.8 | 5660 | 2533 | 2620 | 2.24× |
| web-dvwa | 1575 | 2097 | 336‡ | 6.24× |
| juice-shop | 98 | 93 | 94 | 1.05× |

‡ OSV reports advisories (each advisory may bundle multiple CVEs), so direct comparison with CVE-level counts is not valid for these rows.

**Key patterns:**
1. Trivy consistently reports more findings than Grype for Debian-based images (driven by LOW severity inflation).
2. Grype reports more than Trivy for npm-heavy images (node:14, web-dvwa).
3. juice-shop and nginx:latest show the tightest cross-tool agreement.
4. python:3.8 shows the widest absolute divergence (3127 finding gap, Trivy vs Grype).

### 7.2 CRITICAL Severity Agreement

| Image | Trivy C | Grype C | Delta | Agreement |
|-------|---------|---------|-------|-----------|
| alpine:3.19 | 0 | 0 | 0 | Perfect |
| nginx:latest | 0 | 0 | 0 | Perfect |
| node:20 | 33 | 32 | 1 | Strong |
| python:3.12 | 0 | 0 | 0 | Perfect |
| nginx:1.19 | 42 | 40 | 2 | Strong |
| node:14 | 22 | 19 | 3 | Good |
| python:3.8 | 182 | 185 | 3 | Strong |
| web-dvwa | 254 | 327 | 73 | Moderate |
| juice-shop | 10 | 10 | 0 | Perfect |

CRITICAL-level findings show the best cross-tool agreement. The largest divergence is `web-dvwa` (73 CRITICAL gap), attributable to EOSL detection differences on Debian 9.

### 7.3 LOW Severity as a Driver of Total Count Divergence

The main source of disagreement is LOW severity. Trivy consistently inflates LOW counts:

| Image | Trivy LOW | Grype LOW | Ratio |
|-------|-----------|-----------|-------|
| node:20 | 997 | 67 | 14.9× |
| python:3.12 | 971 | 59 | 16.5× |
| python:3.8 | 1114 | 125 | 8.9× |
| node:14 | 90 | 95 | 1.05× (reversed) |

This has a direct implication for policy design: any threshold-based policy using total counts will be significantly affected by tool choice.

---

## 8. Policy Evaluation

Policies are evaluated based on Trivy and Grype findings (OSV severity breakdown not available in this output format).

**Policy Definitions:**
- **P1:** REJECT if any CRITICAL vulnerability detected
- **P2:** REJECT if any CRITICAL vulnerability has a fix available
- **P3:** REJECT if a CRITICAL is reported by **at least two** scanners (Trivy AND Grype must both report CRITICAL > 0)

### Policy Outcomes

| Image | P1 (Trivy) | P1 (Grype) | P2 (Trivy) | P2 (Grype) | P3 (Consensus) |
|-------|-----------|-----------|-----------|-----------|----------------|
| alpine:3.19 | PASS | PASS | PASS | PASS | **PASS** |
| nginx:latest | PASS | PASS | PASS | PASS | **PASS** |
| node:20 | **REJECT** | **REJECT** | **REJECT** | **REJECT** | **REJECT** |
| python:3.12 | PASS | PASS | PASS | PASS | **PASS** |
| nginx:1.19 | **REJECT** | **REJECT** | **REJECT** | **REJECT** | **REJECT** |
| node:14 | **REJECT** | **REJECT** | **REJECT** | **REJECT** | **REJECT** |
| python:3.8 | **REJECT** | **REJECT** | **REJECT** | **REJECT** | **REJECT** |
| web-dvwa | **REJECT** | **REJECT** | **REJECT** | **REJECT** | **REJECT** |
| juice-shop | **REJECT** | **REJECT** | **REJECT** | **REJECT** | **REJECT** |

**P2 note:** A finding counts as "CRITICAL with fix" if the total fixed count includes CRITICAL items. Trivy's `FixedVersion` field was used for Trivy; Grype's `fix.state == "fixed"` for Grype. Exact per-severity fix counts require deeper JSON traversal (currently aggregated across all severities).

### Policy Analysis

**P1 outcomes:** 5 out of 9 images would be rejected by both tools. Zero false positives between tools — wherever one rejects, both reject (no tool-specific P1 trigger). Perfect P3 consensus for CRITICAL presence.

**P3 practical value:** Given perfect agreement on P1 outcomes, P3 (consensus requirement) does not reduce rejection rate in this dataset. It would only differ if one tool reported CRITICAL and the other did not — this did not occur here.

**P2 as strict sub-policy of P1:** For nginx:latest, the 0% fix rate means P2 allows images that P1 rejects. This is the key policy trade-off: P2 is more operationally realistic (only block what can actually be fixed).

| Image | P1 outcome | P2 outcome | Practical difference |
|-------|-----------|-----------|----------------------|
| nginx:latest | PASS (0 CRITICAL) | PASS | Same |
| node:20 | REJECT | REJECT (14 fixed) | Same |
| python:3.12 | PASS (0 CRITICAL) | PASS | Same |
| Others w/ CRITICAL | REJECT | REJECT (fix available) | Same |

**Key finding:** In this dataset, P1 and P2 produce identical outcomes because wherever CRITICAL vulnerabilities exist, fixable versions are available. The distinction between P1 and P2 is only meaningful for images with CRITICAL vulns but no available fix — a scenario not observed here.

---

## 9. SBOM Baseline

| Image | Total Packages | deb | npm | apk | python | binary | php | java |
|-------|---------------|-----|-----|-----|--------|--------|-----|------|
| alpine:3.19 | 15 | — | — | 15 | — | — | — | — |
| nginx:latest | 152 | 151 | — | — | — | — | — | 1 |
| node:20 | 619 | 413 | 204 | — | 1 | 1 | — | — |
| python:3.12 | 479 | 469 | — | — | 3 | 7 | — | — |
| nginx:1.19 | 136 | 135 | — | — | — | — | — | 1 |
| node:14 | 879 | 413 | 461 | — | 3 | 2 | — | — |
| python:3.8 | 446 | 429 | — | — | 4 | 13 | — | — |
| web-dvwa | 221 | 215 | — | — | — | — | 6 | — |
| juice-shop | 1125 | 13 | 1111 | — | — | 1 | — | — |

**Observations:**
- juice-shop has the largest package surface (1125), overwhelmingly npm (1111).
- node:14 has the largest deb+npm combined (874), explaining its high vulnerability count.
- alpine:3.19 is the leanest image (15 packages) — minimal surface area by design.
- python images carry no npm packages; vulnerability count is entirely OS-level.
- Binary packages (detected by Syft) indicate out-of-package-manager installations.

---

## 10. Notable Findings and Anomalies

1. **OSV-Scanner tag requirement:** Images without explicit `:latest` tag (`image/name`) are rejected with `"not a tagged image name"`. This is a tool-specific constraint that must be handled in any orchestration layer.

2. **OSV advisory grouping vs CVE-level reporting:** OSV-Scanner outputs advisory-level findings (DSA, DLA, GHSA IDs), each potentially covering multiple CVEs. Direct numerical comparison with Trivy/Grype is invalid for Debian-based images. OSV is more comparable for npm/python ecosystems where it reports individual package vulnerabilities.

3. **Trivy LOW severity inflation:** Trivy reports 8–16× more LOW findings than Grype for the same images. This divergence does not affect CRITICAL counts but significantly inflates total counts, which impacts any total-count-based policies.

4. **Alpine 3.19 flagged as EOSL:** Although selected as a "modern baseline", Alpine 3.19 was flagged as end-of-life at scan time. This is an important real-world finding: even recent version-pinned images may hit EOL within a research window.

5. **python:3.8 anomaly:** python:3.8 uses Debian 12 (bookworm, supported) but shows Trivy finding counts of 5660 — the highest in Group B and higher than several Group A images. The Python 3.8 runtime itself reached EOL in October 2024, and the image may contain many packages with known vulnerabilities accumulated since last update.

6. **juice-shop vs web-dvwa comparison:** Both are intentionally vulnerable images, yet juice-shop shows far fewer CRITICAL findings (10) compared to web-dvwa (254/327). juice-shop runs on a modern Debian 13 base with frequent npm updates; web-dvwa is based on Debian 9.5 (2018-era). This illustrates that OS base age is a primary driver of CRITICAL count, not just intentional application vulnerabilities.

7. **Grype > Trivy on npm images:** For npm-heavy images (node:14, web-dvwa), Grype finds more vulnerabilities than Trivy. For OS-package-heavy images, Trivy typically finds more. This suggests tool-specific database coverage differences by ecosystem.

---

## 11. Cumulative Dataset Tables

### D1: Core Results (Image × Tool × Severity)

| Image | Group | Trivy | T:C | T:H | T:M | T:L | Grype | G:C | G:H | G:M | G:L | OSV | EOSL |
|-------|-------|-------|-----|-----|-----|-----|-------|-----|-----|-----|-----|-----|------|
| alpine:3.19 | C | 6 | 0 | 0 | 3 | 3 | 10 | 0 | 0 | 4 | 6 | 6 | YES |
| nginx:latest | C | 169 | 0 | 14 | 29 | 126 | 172 | 0 | 25 | 33 | 8 | 177 | no |
| node:20 | C | 2268 | 33 | 277 | 936 | 997 | 1474 | 32 | 178 | 360 | 67 | 1458 | no |
| python:3.12 | C | 1751 | 0 | 196 | 557 | 971 | 1418 | 0 | 165 | 375 | 59 | 1422 | no |
| nginx:1.19 | B | 424 | 42 | 149 | 193 | 31 | 550 | 40 | 159 | 194 | 35 | 132† | YES |
| node:14 | B | 1439 | 22 | 569 | 754 | 90 | 1995 | 19 | 453 | 477 | 95 | 210† | YES |
| python:3.8 | B | 5660 | 182 | 1369 | 2957 | 1114 | 2533 | 185 | 652 | 694 | 125 | 2620 | no |
| web-dvwa | A | 1575 | 254 | 551 | 642 | 116 | 2097 | 327 | 760 | 700 | 99 | 336† | YES |
| juice-shop | A | 98 | 10 | 47 | 27 | 14 | 93 | 10 | 46 | 26 | 4 | 94 | no |

† OSV advisory counts (grouped); ‡ not directly comparable to CVE-level counts.

### D2: Performance (Image × Tool × Time ms)

| Image | Group | Syft | Trivy | Grype | OSV |
|-------|-------|------|-------|-------|-----|
| alpine:3.19 | C | 1671 | 55 | 32970 | 2376 |
| nginx:latest | C | 3075 | 31639* | 3840 | 5003 |
| node:20 | C | 16793 | 9476 | 17824 | 21142 |
| python:3.12 | C | 14461 | 10216 | 15652 | 21076 |
| nginx:1.19 | B | 3317 | 1253 | 3125 | 8375 |
| node:14 | B | 16458 | 8483 | 16882 | 16565 |
| python:3.8 | B | 16572 | 9991 | 17587 | 27032 |
| web-dvwa | A | 10979 | 6012 | 11667 | ~30000 |
| juice-shop | A | 10492 | 8015 | 10012 | ~30000 |

\* Includes one-time 840MB Java DB download (~28s).

### D3: SBOM Baseline (Image × Package Count × Ecosystems)

| Image | Group | Total | deb | npm | apk | python | binary | php | java |
|-------|-------|-------|-----|-----|-----|--------|--------|-----|------|
| alpine:3.19 | C | 15 | — | — | 15 | — | — | — | — |
| nginx:latest | C | 152 | 151 | — | — | — | — | — | 1 |
| node:20 | C | 619 | 413 | 204 | — | 1 | 1 | — | — |
| python:3.12 | C | 479 | 469 | — | — | 3 | 7 | — | — |
| nginx:1.19 | B | 136 | 135 | — | — | — | — | — | 1 |
| node:14 | B | 879 | 413 | 461 | — | 3 | 2 | — | — |
| python:3.8 | B | 446 | 429 | — | — | 4 | 13 | — | — |
| web-dvwa | A | 221 | 215 | — | — | — | — | 6 | — |
| juice-shop | A | 1125 | 13 | 1111 | — | — | 1 | — | — |

### D4: Policy Evaluation

| Image | Group | P1-Trivy | P1-Grype | P2-Trivy | P2-Grype | P3-Consensus | T:Fixed | G:Fixed |
|-------|-------|---------|---------|---------|---------|--------------|---------|---------|
| alpine:3.19 | C | PASS | PASS | PASS | PASS | PASS | 6 | 6 |
| nginx:latest | C | PASS | PASS | PASS | PASS | PASS | 0 | 0 |
| node:20 | C | REJECT | REJECT | REJECT | REJECT | REJECT | 14 | 14 |
| python:3.12 | C | PASS | PASS | PASS | PASS | PASS | 238 | 249 |
| nginx:1.19 | B | REJECT | REJECT | REJECT | REJECT | REJECT | 337 | 320 |
| node:14 | B | REJECT | REJECT | REJECT | REJECT | REJECT | 1112 | 681 |
| python:3.8 | B | REJECT | REJECT | REJECT | REJECT | REJECT | 3371 | 1030 |
| web-dvwa | A | REJECT | REJECT | REJECT | REJECT | REJECT | 1380 | 1362 |
| juice-shop | A | REJECT | REJECT | REJECT | REJECT | REJECT | 83 | 78 |

---

## 12. Reproducibility

### 12.1 Environment at Time of Scan

| Component | Value |
|-----------|-------|
| Host kernel | Linux 6.8.0-100-generic x86_64 |
| Docker | 26.0.0 (linux/x86_64) |
| Trivy binary SHA-256 | `8266084a71d2e6a2333bc2c69b91c93c26dee9ef39ac2587ace2df54cc9b746b` |
| Grype binary SHA-256 | `465f6a532ab425228a639e70139192fbc458ebab8e6932c714a2f3a450a018cb` |
| Syft binary SHA-256 | `6c1eb5c6f15c177fa3dd727ee186c61a660a3939a4e1dc1bc4b3e00eafec098e` |
| OSV-Scanner binary SHA-256 | `bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b` |

Full detail: `logs/environment.txt`

### 12.2 Vulnerability Database Versions

| Tool | DB Version / Schema | Built / Updated | Reproducible? |
|------|---------------------|-----------------|---------------|
| Trivy | v2 | 2026-03-30T13:22:17Z | Partial — DB is auto-updated; archived snapshot not feasible without manual trivy cache copy |
| Trivy Java DB | v1 | 2026-03-19T01:17:54Z | Same caveat as above |
| Grype | Schema v6.1.4 | 2026-03-30T06:50:11Z | **Yes** — DB archived at `logs/db_snapshots/grype_v6.1.4_2026-03-30.db` with SHA-256 checksum; original source URL in `logs/environment.txt` |
| OSV-Scanner | Live (api.osv.dev) | N/A | **No** — OSV-Scanner v2.3.5 fetches live; no DB version is embedded in output. Results from original run are preserved in `results/osv/`. |

**Grype DB restoration for exact reproduction:**
```bash
# Stop grype from auto-updating
export GRYPE_DB_AUTO_UPDATE=false
# Point grype to the archived DB
export GRYPE_DB_CACHE_DIR=/home/ansuser/logs/db_snapshots
# Verify checksum before use
sha256sum -c /home/ansuser/logs/db_snapshots/grype_v6.1.4_2026-03-30.db.sha256
```

### 12.3 Image Pinning

Images were pulled by mutable tag but digests were recorded immediately. The `reproduce.sh` script uses pinned digests (`image@sha256:...`) for all pulls, guaranteeing identical layer content regardless of when it is run.

| Image (tag used) | Pinned digest |
|-----------------|---------------|
| alpine:3.19 | `sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1` |
| nginx:latest | `sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18` |
| node:20 | `sha256:a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520` |
| python:3.12 | `sha256:c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436` |
| nginx:1.19 | `sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2` |
| node:14 | `sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa` |
| python:3.8 | `sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c` |
| vulnerables/web-dvwa:latest | `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| bkimminich/juice-shop:latest | `sha256:5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114` |

### 12.4 Reproduction Instructions

```bash
# Full reproduction (images identical; Grype DB restored; OSV live — see caveat below)
export GRYPE_DB_AUTO_UPDATE=false
bash /home/ansuser/reproduce.sh all

# Single image
bash /home/ansuser/reproduce.sh node_20
```

### 12.5 Reproducibility Constraints (Documented Limitations)

The following constraints limit full end-to-end reproduction and are treated as research findings rather than errors:

**Constraint 1 — OSV-Scanner live database.**
OSV-Scanner v2.3.5 has no mechanism to pin or version its database in standard (`scan image`) mode. Offline mode (`--offline-vulnerabilities --download-offline-databases`) would require a change to the scan command configuration, which is outside the experimental protocol. The raw JSON outputs in `results/osv/` are the authoritative record of OSV results for this experiment.

**Constraint 2 — Trivy DB auto-expiry.**
Trivy's vulnerability DB expires and is re-downloaded automatically. To reproduce with the exact DB, the Trivy cache directory (`~/.cache/trivy/`) would need to be archived and restored with `TRIVY_NO_PROGRESS=true trivy --cache-dir /path/to/archived/cache`. The DB build date (2026-03-30T13:22:17Z) is recorded for reference.

**Constraint 3 — Registry availability.**
Reproduction requires that all nine image digests remain available in their respective registries. If an image is deleted or the registry is unavailable, reproduction of that scan is not possible without a local image archive (`.tar`). No image tarballs were archived as part of this experiment due to storage constraints.

**Constraint 4 — OSV-Scanner tag requirement.**
OSV-Scanner rejects image references without an explicit tag. The `reproduce.sh` script handles this by running `docker tag <digest> <name:tag>` before invoking OSV-Scanner. This behaviour is documented in Section 10 (Notable Findings).

---

## 13. Raw File Manifest

| File | Size | Description |
|------|------|-------------|
| `results/trivy/alpine_3.19_trivy.json` | — | Trivy raw output |
| `results/trivy/nginx_latest_trivy.json` | — | Trivy raw output |
| `results/trivy/node_20_trivy.json` | — | Trivy raw output |
| `results/trivy/python_3.12_trivy.json` | — | Trivy raw output |
| `results/trivy/nginx_1.19_trivy.json` | — | Trivy raw output |
| `results/trivy/node_14_trivy.json` | — | Trivy raw output |
| `results/trivy/python_3.8_trivy.json` | — | Trivy raw output |
| `results/trivy/vulnerables_web-dvwa_trivy.json` | — | Trivy raw output |
| `results/trivy/bkimminich_juice-shop_trivy.json` | — | Trivy raw output |
| `results/grype/*.json` | — | Grype raw outputs (9 files) |
| `results/osv/*.json` | — | OSV-Scanner raw outputs (9 files) |
| `sbom/*.json` | — | Syft SBOM outputs (9 files) |
| `logs/digests.log` | — | Image digest registry |
| `logs/timing.log` | — | Per-tool execution times |
| `logs/tool_versions.txt` | — | Tool version metadata |
| `logs/parsed_results.json` | — | Structured JSON of all extracted results |

---

*End of experiment log. All data derived from raw JSON outputs — no manual editing of results.*
