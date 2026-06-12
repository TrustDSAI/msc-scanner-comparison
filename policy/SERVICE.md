# policy-gate: CI/CD vulnerability gate service

`policy-gate` packages the multi-scanner policy framework into a single
container that a CI/CD pipeline can call as one step. It scans a container
image, enriches findings with external intelligence, and returns a
tri-state verdict.

## Tri-state verdict

| Tier | Meaning | Default exit code |
|------|---------|-------------------|
| **block** | Beyond reasonable doubt. Hard-fail the build. | 1 |
| **review** | Real finding, not slam-dunk. Surface for a human decision. | 2 |
| **pass** | Nothing actionable. | 0 |

A finding reaches **block** only when:

- It is in the **CISA KEV catalog** and a fix is available, or
- It is **CRITICAL**, detected by **both** scanners, has a fix, is
  **NVD-validated**, has an **OSV advisory**, and its **EPSS score
  exceeds 0.5** (exploitation more likely than not in the next 30 days).

Everything else a scanner flags as CRITICAL or HIGH (with a fix and
consensus), plus KEV entries without a fix, reaches **review**. The gate
deliberately keeps the block tier narrow: the empirical study showed that
broad severity-threshold gating produces inconsistent decisions across
tools, so only fully corroborated or authoritatively-confirmed findings
auto-block. The nuance goes to a human, which is where it belongs.

Image end-of-life status is reported as context on every finding but does
not by itself change the tier; acting on EOL is a pipeline-policy decision.

## Quickstart (GitHub Actions)

```yaml
- name: Build image
  run: docker build -t my-app:${{ github.sha }} .

- name: Vulnerability gate
  uses: TrustDSAI/msc-scanner-comparison/.github/actions/policy-gate@main
  with:
    image: my-app:${{ github.sha }}
    fail-on: review
    nvd-api-key: ${{ secrets.NVD_API_KEY }}
```

That is the whole integration. The action runs the bundled container; no
local scanner or OPA installation is required.

## Direct CLI use

```bash
docker run --rm \
  -v "$PWD/.cache:/cache" \
  ghcr.io/<org>/policy-gate:latest \
    --image python:3.8 \
    --fail-on review \
    --report-format sarif \
    --report /workspace/gate.sarif
```

Or run the Python entry point directly (scanners and OPA must be on PATH):

```bash
python3 policy_gate.py --image python:3.8
```

## CLI reference

| Flag | Default | Description |
|------|---------|-------------|
| `--image` | (required) | Container image reference to scan |
| `--policy` | `configs/p_gate.json` | Gate config JSON |
| `--trivy` | (none) | Pre-computed Trivy JSON; skips scanner invocation |
| `--grype` | (none) | Pre-computed Grype JSON; skips scanner invocation |
| `--classifier` | `rule` | Layer classifier: `rule` or `agent` |
| `--report` | stdout | Report output path |
| `--report-format` | `json` | `json`, `markdown`, `sarif`, or `junit` |
| `--fail-on` | `review` | Tiers that fail the build: `block`, `review`, `none` |
| `--cache` | `.cache/enrich` | Enrichment cache directory |

### `--fail-on` semantics

| Value | block findings | review findings |
|-------|----------------|-----------------|
| `block` | fail (exit 1) | pass (exit 0) |
| `review` | fail (exit 1) | fail (exit 2) |
| `none` | report only (exit 0) | report only (exit 0) |

`review` is the default (fail-closed): a CI gate should not silently let
review-tier findings through. Teams that want a softer gate set
`fail-on: block` and route review findings to a separate human workflow.

## Report formats

- **json**: full structured verdict (block + review sets with all fields)
- **markdown**: human-readable tables, good for PR comments
- **sarif**: SARIF 2.1.0 for GitHub code scanning (block = error, review = warning)
- **junit**: JUnit XML for test-report UIs (block = failure, review = skipped)

## Enrichment cache and rate limits

The enrichment step queries NVD, OSV, EPSS, and the CISA KEV catalog. NVD
without an API key is limited to 5 requests per 30 seconds, which dominates
runtime on images with many findings. Two mitigations:

1. **Provide an NVD API key** (`--nvd-api-key` / `NVD_API_KEY`). Raises the
   limit substantially.
2. **Persist the cache.** Enrichment results are cached by CVE ID. The
   GitHub Action persists `.policy-gate-cache` across runs automatically;
   for direct Docker use, mount a volume at `/cache`.

The first run on a new image set is slow; subsequent runs are fast.

## What is bundled

| Component | Pinned version |
|-----------|----------------|
| Trivy | 0.69.3 |
| Grype | 0.110.0 |
| OPA | 1.17.0 |
| Policy bundle | P1-P7 + tri-state gate (Rego) |
| Enrichers | NVD, OSV, EPSS, KEV, EOL |
| Classifiers | rule (default), agent (LLM, optional) |

Versions match the dissertation study for reproducibility.

## Layer classifier: rule vs agent

The default `rule` classifier maps ecosystem strings to app/os layers
deterministically. The optional `agent` classifier uses an LLM to catch
cases the rule classifier misses (notably OS-packaged application code
such as Debian-packaged PHP modules). The agent requires an
`ANTHROPIC_API_KEY` and adds latency and cost; for most pipelines the rule
classifier is sufficient. See the dissertation for the empirical
comparison.

## Not in scope (v1)

- Suppression / exception workflow (planned; see
  `docs/notes_suppression_workflow_design.md`)
- GitLab CI integration (the container and CLI are platform-agnostic; only
  the GitHub Action wrapper is provided)
- Reachability analysis (the gate flags present-and-known vulnerabilities,
  not proven-exploitable ones)
