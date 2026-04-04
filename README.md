# Container Vulnerability Scanner Comparison

Empirical dataset, analysis tooling, and documentation for an MSc dissertation comparing Trivy, Grype, and OSV-Scanner across nine container images in three risk groups. Results feed into a policy-as-code vulnerability gating layer (OPA/Rego) for CI/CD pipelines.

**Dissertation:** *Policy-as-Code for Container Vulnerability Gating in CI/CD Pipelines: Design, Implementation, and Empirical Evaluation*
**Author:** Simão Cabral Sousa — University of Coimbra, 2026

---

## Repository Structure

```
.
├── scan.sh                    # Scan a single image with all tools
├── reproduce.sh               # Re-run scans using pinned digests
├── parse_results.py           # Extract raw counts → logs/parsed_results.json
├── analysis.py                # 6-table analysis (CVE overlap, CWE, performance, policy)
├── benchmark.sh               # 3-run performance benchmark per image per tool
├── export_csv.py              # Export all analysis tables and datasets to CSV
├── generate_graphs.py         # Generate 8 publication-ready figures (PNG)
├── experiment_log.md          # Full experiment log — methodology, findings, datasets
├── analysis_narrative.md      # Structured narrative walkthrough of all results
│
├── results/
│   ├── trivy/                 # Raw Trivy JSON outputs (9 images)
│   ├── grype/                 # Raw Grype JSON outputs (9 images)
│   └── osv/                   # Raw OSV-Scanner JSON outputs (9 images)
│
├── logs/
│   ├── parsed_results.json    # Structured summary — raw finding counts
│   ├── analysis_tables.json   # Structured summary — analysis outputs (CVE overlap, etc.)
│   ├── analysis_results.txt   # Human-readable analysis table output
│   ├── benchmark.log          # Raw benchmark timing (3 runs × 9 images × 3 tools)
│   ├── benchmark_summary.json # Parsed benchmark means and std devs
│   ├── digests.log            # Image digest registry
│   ├── timing.log             # Per-tool single-run execution times
│   ├── tool_versions.txt      # Tool version metadata
│   ├── environment.txt        # Full environment snapshot (DB versions, binary checksums)
│   ├── csv/                   # CSV exports of all tables and datasets (D1–D7)
│   └── graphs/                # Generated figures (fig1–fig8, PNG)
│
└── sbom/                      # Syft SBOMs — gitignored, regenerate with scan.sh
```

---

## Image Dataset

All images pulled and pinned by digest on **2026-03-31**.

| Image | Group | OS | EOSL |
|-------|-------|----|------|
| `alpine:3.19` | C — Modern baseline | Alpine 3.19.9 | YES |
| `nginx:latest` | C — Modern baseline | Debian 13.4 | no |
| `node:20` | C — Modern baseline | Debian 12.13 | no |
| `python:3.12` | C — Modern baseline | Debian 13.4 | no |
| `nginx:1.19` | B — Outdated real-world | Debian 10.9 | YES |
| `node:14` | B — Outdated real-world | Debian 10.13 | YES |
| `python:3.8` | B — Outdated real-world | Debian 12.7 | no |
| `vulnerables/web-dvwa:latest` | A — Intentionally vulnerable | Debian 9.5 | YES |
| `bkimminich/juice-shop:latest` | A — Intentionally vulnerable | Debian 13.4 | no |

**Group rationale:**
- **A** — intentionally vulnerable images; ground truth for known-vuln detection
- **B** — production-style images past EOL or upstream support
- **C** — current, maintained images; minimal expected findings

---

## Tool Versions

| Tool | Version | DB / Schema | Notes |
|------|---------|-------------|-------|
| Trivy | 0.69.3 | v2, updated 2026-03-30 | `--scanners vuln` only |
| Grype | 0.110.0 | Schema v6.1.4, built 2026-03-30 | default profile |
| OSV-Scanner | 2.3.5 | Live (api.osv.dev) | advisory-level output |
| Syft | 1.42.3 | Schema v16.1.3 | SBOM generation only |

Full environment detail (binary checksums, DB URLs): [`logs/environment.txt`](logs/environment.txt)

---

## Key Findings

| # | Finding |
|---|---------|
| 1 | Trivy reports 1.2–2.2× more total findings than Grype for Debian images, driven by LOW severity inflation |
| 2 | CVE-level overlap (Jaccard) ranges from **0.14** (python:3.8) to **0.89** (nginx:latest) |
| 3 | Severity agreement on shared CVEs ranges from **8%** (juice-shop) to **96%** (nginx:1.19) — Trivy almost always rates higher |
| 4 | CRITICAL counts converge across tools (delta ≤3 in 7/9 images) — the most reliable cross-tool signal |
| 5 | Fix rates diverge significantly between tools for the same image (node:14: Trivy 77% vs Grype 34%) |
| 6 | Trivy is 10–100× faster than Grype and OSV-Scanner across all images |
| 7 | Top CWEs are memory-safety weaknesses (CWE-476, 416, 125, 787) — OS base layer dominates risk |

Full narrative: [`analysis_narrative.md`](analysis_narrative.md)

---

## Usage

### Scan a new image
```bash
./scan.sh <image> <safe_name> <group>
# e.g.
./scan.sh alpine:3.19 alpine_3.19 C
```

### Reproduce original scans (pinned digests)
```bash
./reproduce.sh all          # all 9 images
./reproduce.sh node_20      # single image
./reproduce.sh --list       # list available names
```

For exact Grype DB reproduction:
```bash
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_CACHE_DIR=/path/to/db_snapshots
```

### Parse raw results
```bash
python3 parse_results.py
# → logs/parsed_results.json
```

### Run full analysis (6 tables)
```bash
python3 analysis.py
python3 analysis.py --save   # also writes logs/analysis_tables.json
```

### Run performance benchmark (3 runs per image per tool)
```bash
bash benchmark.sh
# → logs/benchmark.log, logs/benchmark_summary.json
```

### Export all tables to CSV
```bash
python3 export_csv.py
# → logs/csv/*.csv  (13 files: tables 1–6, datasets D1–D7)
```

### Generate figures
```bash
python3 generate_graphs.py
# → logs/graphs/fig1–fig8.png
```

---

## Output Files

### CSV exports (`logs/csv/`)

| File | Contents |
|------|----------|
| `table1_core_counts.csv` | Total findings per image per tool with fix% |
| `table2_fix_status_trivy.csv` | Trivy fix status breakdown (fixed/affected/will_not/deferred) |
| `table2_fix_status_grype.csv` | Grype fix state breakdown (fixed/not-fixed/wont-fix/unknown) |
| `table3_cve_overlap.csv` | CVE-level Jaccard overlap between Trivy and Grype |
| `table4_severity_agreement.csv` | Severity agreement on shared CVEs |
| `table5_cwe_pivot.csv` | Top 10 CWEs across all images |
| `table5_cwe_per_image_trivy.csv` | Per-image CWE breakdown (Trivy) |
| `table5_cwe_per_image_grype.csv` | Per-image CWE breakdown (Grype) |
| `table6_performance.csv` | Benchmark means and std devs |
| `D1_core_results.csv` | Master dataset — all images × tools × severities |
| `D2_performance_original.csv` | Performance benchmark data |
| `D3_sbom_baseline.csv` | SBOM package counts by ecosystem |
| `D4_policy_evaluation.csv` | P1/P2/P3 policy outcomes per image |

### Figures (`logs/graphs/`)

| File | Contents |
|------|----------|
| `fig1_performance.png` | Scan time per tool per image (log scale, mean ± sd) |
| `fig2_total_findings.png` | Total findings grouped bar with divergence ratios |
| `fig3_cve_overlap.png` | Jaccard similarity + CVE set composition |
| `fig4_severity_agreement.png` | Severity agreement on shared CVEs |
| `fig5_fix_rates.png` | Fix rate % per image per tool |
| `fig6_critical_counts.png` | CRITICAL finding counts Trivy vs Grype |
| `fig7_cwe_top10.png` | Top 10 CWE types across all images |
| `fig8_time_vs_size.png` | Scan time vs image size scatter with linear fit |

---

## Reproducibility

See [`experiment_log.md § 12`](experiment_log.md#12-reproducibility) for full details:
- Pinned image digests for all 9 images
- Vulnerability DB versions and archived Grype DB source URL
- Binary SHA-256 checksums for all tools
- Known reproducibility constraints (OSV-Scanner live DB, Trivy DB expiry, registry availability)

**SBOMs** are excluded from this repository (up to 33 MB per image). Regenerate with:
```bash
syft <image> -o syft-json > sbom/<safe_name>_syft.json
```
