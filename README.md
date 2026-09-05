# Container Vulnerability Scanner Comparison

Empirical dataset, analysis tooling, and documentation for an MSc dissertation comparing Trivy, Grype, and OSV-Scanner across nine container images in three risk groups. Results feed into a policy-as-code vulnerability gating layer (OPA/Rego) for CI/CD pipelines.

**Dissertation:** *Policy-as-Code for Container Vulnerability Gating in CI/CD Pipelines: Design, Implementation, and Empirical Evaluation*
**Author:** Simão Cabral Sousa — University of Coimbra, 2026

---

## Repository Structure

```
.
├── data/
│   ├── raw/                   # Immutable scanner outputs (27 JSON files)
│   │   ├── trivy/             # Trivy raw output (9 images)
│   │   ├── grype/             # Grype raw output (9 images)
│   │   └── osv/               # OSV-Scanner raw output (9 images)
│   ├── derived/               # Regeneratable from raw
│   │   ├── parsed_results.json
│   │   ├── analysis_tables.json
│   │   ├── benchmark_summary.json
│   │   └── tables/            # CSV exports (14 files)
│   └── sbom/                  # Syft SBOMs — gitignored, regenerate with scripts/scan.sh
│
├── figures/                   # Generated figures (10 PNG files)
│
├── scripts/                   # Data collection shell scripts
│   ├── scan.sh                # Scan a single image with all tools
│   ├── reproduce.sh           # Re-run scans using pinned digests
│   ├── benchmark.sh           # 30-run performance benchmark
│   └── benchmark_trivy.sh     # Trivy-only re-run with pre-warmed DB
│
├── analysis/                  # Python analysis pipeline
│   ├── parse_results.py       # Extract raw counts → data/derived/parsed_results.json
│   ├── parse_benchmark_log.py # Parse benchmark log → data/derived/benchmark_summary.json
│   ├── analysis.py            # 6-table analysis (CVE overlap, CWE, performance, policy)
│   ├── export_csv.py          # Export all tables → data/derived/tables/
│   ├── generate_graphs.py     # Generate figures → figures/
│   └── harborguard/           # HarbourGuard scanner comparison
│       ├── harborguard_scan.py
│       └── harborguard_analysis.py
│
├── audit/                     # Independent recomputation of every published number
│   ├── README.md              # What each script checks
│   └── *.py                   # Re-derive the metrics from data/raw, not from analysis/
│
└── logs/                      # Runtime execution logs
    ├── benchmark.log          # Raw benchmark timing (30 runs × 9 images × 3 tools)
    ├── benchmark_trivy.log    # Trivy-only re-run log (30 runs, pre-warmed DB)
    ├── timing.log             # Per-tool single-run execution times
    ├── digests.log            # Image digest registry
    ├── tool_versions.txt      # Tool version metadata
    ├── environment.txt        # Environment snapshot (DB versions, binary checksums)
    └── harborguard/           # HarbourGuard scan and analysis logs
```

---

## Image Dataset

All images pulled and pinned by digest on **2026-03-31**.

| Image | Group | OS | EOSL |
|-------|-------|----|------|
| `alpine:3.19` | C — Modern baseline | Alpine 3.19.9 | YES |
| `nginx:1.29.7` | C — Modern baseline | Debian 13.4 | no |
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
| 1 | Total counts diverge by up to **6.9×** on the same image (python:3.8: Trivy 3,684, Grype 537); almost all of the gap is one package, `linux-libc-dev`, which Grype does not enumerate |
| 2 | CVE-level overlap (Jaccard) ranges from **0.14** (python:3.8) to **0.95** (juice-shop) |
| 3 | Severity agreement on shared CVEs ranges from **32.6%** (nginx:1.29.7) to **96.3%** (nginx:1.19); Trivy rates higher in 647 of the 743 disagreements |
| 4 | CRITICAL counts converge across tools — delta ≤3 on 8 of the 9 design images and on 25 of all 30 — the most portable cross-tool signal, with PHP the recurring exception |
| 5 | Fix rates diverge by more than a factor of two on the same image (node:14: Trivy 77.3% vs Grype 34.1%) |
| 6 | Trivy is **38 to 128×** faster than Grype on every image, and near-flat in image size (1 ms/MB against 90 and 92) |
| 7 | Top CWEs are memory-safety weaknesses (CWE-476, 416, 125, 787) — the OS base layer dominates the distribution |
| 8 | `p_gate` blocks 10 of the 30 images where a naive any-CRITICAL gate blocks 26, routing the rest to review |

Every figure above is recomputed from `data/raw/` by the scripts in
[`audit/`](audit/), which re-derive each metric from the raw scanner output
rather than from `analysis/`.


---

## Setup

Tested on **Ubuntu 24.04 LTS** (x86_64).

### Prerequisites

| Tool | Version used | Install method |
|------|-------------|----------------|
| Docker CE | 26.0.0 | dnf / docker-ce repo |
| Trivy | 0.69.3 | install script |
| Grype | 0.110.0 | install script |
| OSV-Scanner | 2.3.5 | GitHub release binary |
| Syft | 1.42.3 | install script |

### 1 — Docker

```bash
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

### 2 — Trivy

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin v0.69.3
```

### 3 — Grype

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b /usr/local/bin v0.110.0
```

### 4 — OSV-Scanner

```bash
curl -fsSL https://github.com/google/osv-scanner/releases/download/v2.3.5/osv-scanner_linux_amd64 \
  -o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner
```

### 5 — Syft (SBOM generation only)

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b /usr/local/bin v1.42.3
```

### Verify

```bash
docker --version
trivy --version
grype version
osv-scanner --version
syft --version
```

### Pull benchmark images

Images must be present locally before running `benchmark.sh` (no pull step inside the benchmark loop). Pull all nine pinned images:

```bash
bash reproduce.sh all   # pulls by digest and runs scans
# or pull only, without scanning:
docker pull alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1
docker pull nginx@sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18
docker pull node@sha256:a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520
docker pull python@sha256:c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436
docker pull nginx@sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2
docker pull node@sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa
docker pull python@sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c
docker pull vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
docker pull bkimminich/juice-shop@sha256:5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114
```

---

## Usage

### Scan a new image
```bash
bash scripts/scan.sh <image> <safe_name> <group>
# e.g.
bash scripts/scan.sh alpine:3.19 alpine_3.19 C
```

### Reproduce original scans (pinned digests)
```bash
bash scripts/reproduce.sh all          # all 9 images
bash scripts/reproduce.sh node_20      # single image
bash scripts/reproduce.sh --list       # list available names
```

For exact Grype DB reproduction:
```bash
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_CACHE_DIR=/path/to/db_snapshots
```

### Parse raw results
```bash
python3 analysis/parse_results.py
# → data/derived/parsed_results.json
```

### Run full analysis (6 tables)
```bash
python3 analysis/analysis.py
python3 analysis/analysis.py --save   # also writes data/derived/analysis_tables.json
```

### Run performance benchmark (30 runs per image per tool)
```bash
bash scripts/benchmark.sh
# → logs/benchmark.log, data/derived/benchmark_summary.json
```

### Export all tables to CSV
```bash
python3 analysis/export_csv.py
# → data/derived/tables/*.csv
```

### Generate figures
```bash
python3 analysis/generate_graphs.py
# → figures/fig1–fig10.png
```

---

## Output Files

### CSV exports (`data/derived/tables/`)

| File | Contents |
|------|----------|
| `table1_core_counts.csv` | Total findings per image per tool with fix% |
| `table2_fix_status_trivy.csv` | Trivy fix status breakdown |
| `table2_fix_status_grype.csv` | Grype fix state breakdown |
| `table3_cve_overlap.csv` | CVE-level Jaccard overlap between Trivy and Grype |
| `table4_severity_agreement.csv` | Severity agreement on shared CVEs |
| `table5_cwe_pivot.csv` | Top 10 CWEs across all images |
| `table5_cwe_per_image_trivy.csv` | Per-image CWE breakdown (Trivy) |
| `table5_cwe_per_image_grype.csv` | Per-image CWE breakdown (Grype) |
| `table6_performance.csv` | Benchmark means and std devs (30 runs) |
| `D1_core_results.csv` | Master dataset — all images × tools × severities |
| `D2_performance_original.csv` | Performance benchmark data |
| `D3_sbom_baseline.csv` | SBOM package counts by ecosystem |
| `D4_policy_evaluation.csv` | P1/P2/P3 policy outcomes per image |

### Figures (`figures/`)

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
| `fig9_scan_boxplot.png` | 30-run distribution box plots per tool |
| `fig10_jaccard_packages.png` | Package ecosystem breakdown for Jaccard divergence |

---

## Reproducibility

- Pinned image digests: [`logs/digests.log`](logs/digests.log), all 30 images
- Vulnerability DB versions, archived Grype DB source URL and binary SHA-256
  checksums: [`logs/environment.txt`](logs/environment.txt)
- Tool versions as the tools reported them: [`logs/tool_versions.txt`](logs/tool_versions.txt)
- Timing runs: [`logs/benchmark.log`](logs/benchmark.log) (Grype, OSV-Scanner)
  and [`logs/benchmark_trivy.log`](logs/benchmark_trivy.log) (Trivy, re-run
  separately against a warmed database)

Known reproducibility limits: OSV-Scanner queries `api.osv.dev` live and has no
pinned database, so its counts are not reproducible from a digest alone; the
policy gate's NVD, OSV, EPSS and KEV enrichment is likewise fetched live, so a
later run of the gate will not reproduce the published verdicts exactly. Trivy's
Java database was cached and past expiry at scan time; no reported finding
depends on it.

**SBOMs** are excluded from this repository (up to 33 MB per image). Regenerate with:
```bash
syft <image> -o syft-json > data/sbom/<safe_name>_syft.json
```
