# Architectural Decision — Policy Layer Design

**Date:** 2026-04-05
**Decision:** Build a standalone OPA/Rego policy layer operating on raw scanner outputs, rather than forking HarbourGuard.
**Status:** Decided

---

## Context

HarbourGuard (github.com/HarborGuard/HarborGuard) was identified as the most representative existing tool for multi-scanner container vulnerability orchestration. It supports Trivy, Grype, OSV-Scanner, Syft, Dockle, and Dive, and provides a web dashboard for visualising results. The dissertation research question asks whether a policy-as-code layer can reliably gate container deployments in CI/CD pipelines based on multi-scanner vulnerability data.

Two architectural options were considered:

1. **Fork HarbourGuard** — add a policy engine directly inside HG's codebase (TypeScript/Next.js + Go sensor binary)
2. **Standalone OPA/Rego layer** — build an independent policy component that consumes raw scanner outputs and integrates with CI/CD directly

---

## Evidence from Empirical Analysis

The decision was informed by running all 9 experimental images through HarbourGuard's API and comparing its output to standalone scanner runs. Three concrete data quality issues were identified that make HG's normalised output unsuitable as a policy input.

### Issue 1 — Fix rate data is unreliable

HarbourGuard runs Trivy and Grype internally but does not consistently propagate fix metadata through its ingestion pipeline. The `fixedVersion` field is null for the majority of findings that the standalone tools correctly mark as fixed:

| Image | HG fix% | Trivy standalone fix% | Grype standalone fix% |
|-------|---------|----------------------|----------------------|
| node:14 | 10% | 77% | 34% |
| python:3.8 | 7% | 60% | 41% |
| web-dvwa | 45% | 88% | 65% |
| nginx:1.19 | 75% | 79% | 58% |

For node:14, HG records only 160 fixable findings out of 1565 total. Trivy standalone records 1112 fixable findings out of 1439. The underlying scanner data is the same — the loss occurs during HG's normalisation and database ingestion.

**Consequence:** Policy P2 (block if CRITICAL with fix available) cannot be reliably implemented against HG's normalised output. On Group B images, it would undercount fixable CRITICAL findings by 60–90%, producing incorrect gate decisions.

### Issue 2 — Per-scanner deduplication collapses attribution

HG deduplicates findings across scanners by CVE ID, assigning each finding to one scanner's record and discarding the others. In practice, this causes one scanner's contribution to collapse near zero for certain images:

| Image | Trivy-in-HG | Trivy standalone | Grype-in-HG | Grype standalone |
|-------|------------|-----------------|------------|-----------------|
| node:20 | 1606 | 2268 | **17** | 1474 |
| python:3.8 | 1569 | 5660 | **31** | 2533 |
| nginx:1.19 | **15** | 424 | 538 | 550 |
| node:14 | 247 | 1439 | 953 | 1995 |

For node:20, Grype contributed 1474 findings in standalone mode but only 17 appear attributed to Grype inside HG. The deduplication logic assigns the CVE to Trivy's record and removes the Grype entry.

**Consequence:** Policy P3 (block only if CRITICAL confirmed by both scanners) is broken inside HG. For node:20, node:14, python:3.8, and web-dvwa, Grype-in-HG reports near-zero findings, so P3 passes images that both standalone tools would reject. The consensus policy — designed to add resilience — is weaker than P1 when applied to HG's per-source counts.

### Issue 3 — Risk score saturates immediately

HarbourGuard computes an aggregated risk score (0–100) per scan. In practice, 8 of 9 images score 100/100. Only alpine:3.19 (6 total findings, 0 CRITICAL) scores below maximum (49/100). The score provides no granularity across the vulnerability spectrum and cannot be used as a policy threshold.

### Issue 4 — No exit codes or CI/CD integration

Confirmed from both the codebase analysis and API behaviour. Every scan completes with `status: SUCCESS` regardless of CRITICAL count. There is no mechanism to trigger a pipeline failure from HG without an external layer consuming its API. HG is a visualisation dashboard, not a gate.

---

## Why Forking HG Would Be Problematic

A fork would require resolving issues 1 and 2 before the policy engine could function reliably. This means:

1. **Fix the fix rate propagation** — trace why `fixedVersion` is lost during `ingestEnvelope()` in the TypeScript ingestion layer, fix the Go sensor CLI output format and/or the `DatabaseAdapter` normalisation logic
2. **Fix the deduplication logic** — redesign how HG stores multi-scanner findings to preserve per-scanner attribution without collapsing one tool's results
3. **Then build the policy engine** — new Prisma models, evaluator service, gate decision logic, API endpoint, CI/CD integration

Steps 1 and 2 are pre-requisites in a codebase written in TypeScript + Go (two languages) that was not designed with policy evaluation in mind. The dissertation contribution would be buried under upstream bug fixes. There is also a timeline risk: HarbourGuard is an active project and the main branch may change.

Furthermore, a policy engine built inside HG would be HG-specific and not generalisable — it could not be used alongside other orchestration tools or in pipelines that invoke scanners directly.

---

## Decision: Standalone OPA/Rego Layer

The policy layer will be implemented as an independent component with the following architecture:

```
┌─────────────────────────────────────────────────────────┐
│  CI/CD Pipeline Stage                                   │
│                                                         │
│  [trivy image -o json] ──┐                              │
│  [grype image -o json]   ├──► normalise.py              │
│  [osv-scanner image]  ───┘         │                    │
│                                    ▼                    │
│                            policy_input.json            │
│                                    │                    │
│                                    ▼                    │
│                         opa eval -d policy/             │
│                                    │                    │
│                          ┌─────────┴──────────┐        │
│                        PASS                 REJECT      │
│                       exit 0               exit 1       │
│                                          + report       │
└─────────────────────────────────────────────────────────┘
```

**Components:**
- `normalise.py` — converts raw Trivy and Grype JSON into a tool-agnostic input schema
- `policy/p1_any_critical.rego` — P1 policy
- `policy/p2_critical_with_fix.rego` — P2 policy
- `policy/p3_consensus_critical.rego` — P3 policy
- `policy/test/` — OPA unit tests for each policy
- GitLab CI / GitHub Actions stage demonstrating integration

**Why this is the right architecture:**

| Criterion | Standalone OPA layer | HG fork |
|-----------|---------------------|---------|
| Fix data reliability | Uses raw scanner output — reliable | Inherits HG's broken fix propagation |
| Per-scanner attribution for P3 | Preserved from raw JSON | Collapsed by HG deduplication |
| CI/CD integration | Native (exit codes, pipeline stages) | Requires adding to HG codebase |
| Language / stack | Python + Rego (minimal) | TypeScript + Go + Prisma |
| Generalisability | Works with any scanner combination | HG-specific |
| Dissertation scope | Achievable | Pre-requisite bug fixes add scope |
| HG relationship | Positioned as filling its gap | Modifying it |

---

## HarbourGuard's Role in the Dissertation

HarbourGuard is not discarded — it serves as the primary **motivating case study** for the gap analysis:

> *HarbourGuard represents the current state of multi-scanner orchestration: capable of aggregating and visualising results from six tools, but with no policy enforcement mechanism. Empirical analysis of its output reveals that its normalised data is unsuitable as a policy input: fix status metadata is not reliably propagated (node:14 fix rate: HG 10% vs Trivy 77%), and per-scanner attribution collapses due to aggressive deduplication, rendering cross-scanner consensus policies unreliable within HG's data model. These findings motivate a policy layer that operates directly on raw scanner outputs, independent of any orchestration tool's normalisation decisions.*

The HarbourGuard analysis (7 comparison tables, 4 documented data quality issues) is empirical evidence that directly motivates and justifies the standalone architecture. It is Chapter 4 motivation, not a fork project.

---

## Positioning the Contribution

The dissertation contribution is:

> A **policy-as-code layer** (OPA/Rego) that consumes raw multi-scanner output, normalises it into a tool-agnostic schema, and enforces declarative vulnerability gate policies (P1/P2/P3) in CI/CD pipelines — addressing gaps empirically identified in existing orchestration tools including HarbourGuard.

This is:
- **Empirically motivated** — by the scanner comparison experiment and HG analysis
- **Technically concrete** — working Rego policies with OPA unit tests and a CI/CD pipeline stage
- **Generalisable** — not tied to any specific orchestration platform
- **Defensible** — the architectural choice is backed by data, not preference

---

*Supporting data: `logs/harborguard_results.json`, `logs/harborguard_analysis.txt`, `HARBORGUARD_ANALYSIS.md`*
*See also: `notes_scanner_internals.md`, `analysis_narrative.md`*
