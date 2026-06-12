# Policy-as-Code Gating Layer

Standalone OPA/Rego policy layer for container vulnerability gating in CI/CD pipelines. Consumes raw scanner outputs from Trivy, Grype, and OSV-Scanner; produces a structured gate decision plus an audit-grade classification of every finding.

## Structure

```
policy/
├── normalise.py              Trivy/Grype JSON to unified input schema
├── enrich.py                 P4 enrichment: NVD, OSV, EPSS; cached by CVE
├── rego/                     OPA/Rego policy bundle
│   ├── p1_any_critical.rego
│   ├── p2_critical_with_fix.rego
│   ├── p3_consensus_critical.rego
│   └── p4_enriched_critical.rego
├── tests/                    OPA unit tests (one per policy)
│   ├── p1_test.rego
│   ├── p2_test.rego
│   ├── p3_test.rego
│   └── p4_test.rego
├── examples/                 Sample inputs for manual evaluation
│   └── sample_input.json
└── ci/
    └── github-actions.yml    CI/CD integration example
```

## Policies

| Policy | Block condition | Adds |
|--------|-----------------|------|
| P1 | Any CRITICAL finding | Severity threshold |
| P2 | CRITICAL with fix available | Fixability filter |
| P3 | CRITICAL confirmed by both scanners | Cross-scanner consensus |
| P4 | CRITICAL + NVD-validated + OSV-confirmed + EPSS above threshold | External enrichment, risk-based prioritisation |

See `docs/notes_architectural_decision.md` for the full design rationale.

## Pipeline

```
[scanners] -> normalise.py -> policy_input.json -> [opa eval] -> verdict
                                       |
                                  (P4 only)
                                       v
                                  enrich.py
                                       |
                                       v
                              enriched_input.json -> [opa eval] -> verdict
```

## Quickstart

```bash
# Normalise scanner outputs
python normalise.py \
    --trivy ../data/raw/trivy/python_3.8_trivy.json \
    --grype ../data/raw/grype/python_3.8_grype.json \
    --out policy_input.json

# Run P3 (consensus)
opa eval --input policy_input.json --data rego/ \
    "data.vuln.p3.block_build"

# Enrich and run P4
python enrich.py --in policy_input.json --out enriched_input.json
opa eval --input enriched_input.json --data rego/ \
    "data.vuln.p4.block_build"
```

## Tests

```bash
opa test rego/ tests/
```

## Status

Skeleton only. Implementation pending.
