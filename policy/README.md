# Policy-as-Code Gating Layer

Standalone OPA/Rego policy layer for container vulnerability gating in
CI/CD pipelines. Consumes raw scanner outputs from Trivy and Grype;
enriches with NVD/OSV/EPSS/KEV; produces a tri-state gate decision
(block / review / pass) plus an audit-grade classification of every
finding.

**Full documentation: [`docs/`](./docs/README.md)** — architecture,
the full policy reference, enrichment/retry/caching behavior, and
deployment (CLI / API / GitHub Action / image publishing). This README
is just a quickstart; `docs/` is the code reference, and
[`../CONTEXT.md`](../CONTEXT.md) is the project's domain glossary and
design-decision log.

## Structure

```
policy/
├── policy_gate.py     Main CLI / orchestration (run_gate(), all report formatters)
├── api.py             FastAPI server mode (POST /gate, /gate/verdict, /health)
├── normalisers/        Trivy/Grype adapters -> unified Finding schema
├── classifiers/        layer ("app"/"os"/"unknown") classification: rule | agent (LLM)
├── enrichers/           NVD, OSV, EPSS, KEV; shared retry/cache in _retry.py, cache.py
├── rego/                policy bundle: p_gate.rego (default) + the P1-P7 research lineage
├── exceptions_loader.py  suppression YAML loader (see docs/policy-reference.md)
├── provenance.py        tool-version/bundle-fingerprint self-reporting
├── tests/               OPA unit tests (opa test rego/ tests/) + pytest (test_*.py)
├── docs/                code reference (this directory's documentation)
└── Dockerfile           self-contained image: scanners + opa + this pipeline
```

## P1-P7 vs. p_gate

`rego/p[1-7]*.rego` are the research lineage (Chapter 5's empirical
study, each adding one signal: severity → consensus → fix → enrichment →
layer-awareness → EOL → severity-aware thresholds). `rego/p_gate.rego` is
the delivered tri-state policy that supersedes them — see
[`docs/policy-reference.md`](./docs/policy-reference.md) for its full
logic, and `docs/notes_architectural_decision.md` (repo root) for why
the tri-state design superseded the single deny-set P1-P7 lineage.

## Quickstart

```bash
# Full pipeline, default policy
python3 policy_gate.py --image alpine:3.21 --report-format markdown

# With suppression and a custom config
python3 policy_gate.py --image my-app:latest \
    --policy configs/p_gate.json --exceptions-dir exceptions/

# Tests
opa test rego/ tests/
python3 -m pytest
```

See [`docs/deployment.md`](./docs/deployment.md) for the API server and
GitHub Action modes, and [`docs/architecture.md`](./docs/architecture.md)
for how a single image flows through scan → normalise → classify →
enrich → opa eval → report.
