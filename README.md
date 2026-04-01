# Container Vulnerability Scanner Comparison

Empirical dataset and tooling for an MSc research project comparing Trivy, Grype, and OSV-Scanner across nine container images spanning three groups (intentionally vulnerable, outdated real-world, modern baseline).

Results feed into a policy-as-code evaluation layer (OPA/Rego) for vulnerability gating in CI/CD pipelines.

---

## Repository Structure

```
.
├── scan.sh               # Scan a single image with all tools
├── reproduce.sh          # Re-run scans using pinned digests
├── parse_results.py      # Extract counts and print summary tables
├── experiment_log.md     # Full experiment log (findings, analysis, policies)
├── results/
│   ├── trivy/            # Raw Trivy JSON outputs (9 images)
│   ├── grype/            # Raw Grype JSON outputs (9 images)
│   └── osv/              # Raw OSV-Scanner JSON outputs (9 images)
├── logs/
│   ├── parsed_results.json   # Structured summary (auto-generated)
│   ├── digests.log           # Image digest registry
│   ├── timing.log            # Per-tool execution times
│   ├── tool_versions.txt     # Tool version metadata
│   └── environment.txt       # Full environment snapshot (DB versions, binary checksums)
└── sbom/                 # Syft SBOMs — gitignored, regenerate with scan.sh
```

---

## Image Dataset

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

---

## Tool Versions

| Tool | Version | DB / Schema |
|------|---------|-------------|
| Trivy | 0.69.3 | v2, updated 2026-03-30 |
| Grype | 0.110.0 | Schema v6.1.4, built 2026-03-30 |
| OSV-Scanner | 2.3.5 | Live (api.osv.dev) |
| Syft | 1.42.3 | Schema v16.1.3 |

Full environment detail (binary checksums, DB URLs): [`logs/environment.txt`](logs/environment.txt)

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
# All images
./reproduce.sh all

# Single image
./reproduce.sh node_20

# List available names
./reproduce.sh --list
```

For Grype DB pinning, set before running:
```bash
export GRYPE_DB_AUTO_UPDATE=false
export GRYPE_DB_CACHE_DIR=/path/to/db_snapshots
```

### Parse results and print summary tables
```bash
python3 parse_results.py
```

Output: three summary tables + `logs/parsed_results.json`

---

## Reproducibility

See [`experiment_log.md` § 12](experiment_log.md#12-reproducibility) for full details including:
- Pinned image digests
- Vulnerability DB versions and archived Grype DB source URL
- Known limitations (OSV-Scanner live DB, Trivy DB expiry)

**SBOMs** are excluded from this repository (up to 33 MB per image). Regenerate with:
```bash
syft <image> -o syft-json > sbom/<safe_name>_syft.json
```
