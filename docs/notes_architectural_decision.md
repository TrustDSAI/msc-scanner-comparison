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
| ----- | ------- | --------------------- | --------------------- |
| node:14 | 10% | 77% | 34% |
| python:3.8 | 7% | 60% | 41% |
| web-dvwa | 45% | 88% | 65% |
| nginx:1.19 | 75% | 79% | 58% |

For node:14, HG records only 160 fixable findings out of 1565 total. Trivy standalone records 1112 fixable findings out of 1439. The underlying scanner data is the same — the loss occurs during HG's normalisation and database ingestion.

**Consequence:** Policy P2 (block if CRITICAL with fix available) cannot be reliably implemented against HG's normalised output. On Group B images, it would undercount fixable CRITICAL findings by 60–90%, producing incorrect gate decisions.

### Issue 2 — Per-scanner deduplication collapses attribution

HG deduplicates findings across scanners by CVE ID, assigning each finding to one scanner's record and discarding the others. In practice, this causes one scanner's contribution to collapse near zero for certain images:

| Image | Trivy-in-HG | Trivy standalone | Grype-in-HG | Grype standalone |
| ----- | ----------- | ---------------- | ----------- | ---------------- |
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

### P1–P3: Scanner-native policies

```ascii
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

### P4: Enrichment-backed policy

P4 extends the pipeline with an enrichment stage that queries three external data sources per finding before OPA evaluation:

```ascii
┌─────────────────────────────────────────────────────────┐
│  CI/CD Pipeline Stage (P4)                              │
│                                                         │
│  [trivy image -o json] ──┐                              │
│  [grype image -o json]   ├──► normalise.py              │
│  [osv-scanner image]  ───┘         │                    │
│                                    ▼                    │
│                            policy_input.json            │
│                                    │                    │
│                                    ▼                    │
│                   enrich.py (async, per CVE)            │
│                  ┌─────────┬────────────────┐           │
│                 NVD       OSV             EPSS          │
│              (status,  (advisory,      (exploitation    │
│              rejected)  fix version,   probability)     │
│                         ecosystem)                      │
│                  └─────────┴────────────────┘           │
│                                    │                    │
│                                    ▼                    │
│                       enriched_input.json               │
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
- `enrich.py` — async enrichment fetcher; queries NVD, OSV, and EPSS APIs per CVE; results cached by CVE ID to avoid redundant calls across images
- `policy/p1_any_critical.rego` — P1 policy
- `policy/p2_critical_with_fix.rego` — P2 policy
- `policy/p3_consensus_critical.rego` — P3 policy
- `policy/p4_enriched_critical.rego` — P4 policy
- `policy/test/` — OPA unit tests for each policy
- GitLab CI / GitHub Actions stage demonstrating integration

---

## Policy Definitions

The four policies form a progression of increasing precision. Each is strictly more selective than the previous, trading recall for signal quality.

**P1 — Block if any CRITICAL**
Bluntest gate. Blocks on any finding reported as CRITICAL by either scanner, regardless of fix availability, cross-scanner confirmation, or external validation. Highest noise, lowest false negative risk.

**P2 — Block if CRITICAL with fix available**
Adds fixability as a required condition. Only blocks when a CRITICAL finding has a fix version recorded in the scanner output. Reduces blocking on findings where no remediation path exists.

**P3 — Block if CRITICAL confirmed by both scanners**
Adds cross-scanner consensus as a required condition. Only blocks when both Trivy and Grype independently detect the same CRITICAL finding. Reduces scanner-specific false positives without external data.

**P4 — Block if CRITICAL confirmed, enriched, and actively exploitable**
Adds external validation via NVD, OSV, and EPSS. Blocks only when all of the following hold:

- Detected by both scanners (P3 baseline)
- NVD status is `Analyzed` and the CVE is neither rejected nor disputed
- OSV carries an advisory for the affected package and ecosystem
- A fix version is recorded in OSV
- EPSS score exceeds the defined threshold (default: 0.1 — top decile of exploited CVEs per FIRST.org percentile distribution)

```rego
package vuln.p4

import future.keywords.if
import future.keywords.in

block_build if {
    some finding in input.findings
    finding.severity == "CRITICAL"
    count(finding.detected_by) > 1
    finding.nvd.status == "Analyzed"
    finding.nvd.rejected == false
    finding.nvd.disputed == false
    finding.osv.advisory_found == true
    finding.osv.fix_version != null
    finding.epss.score > 0.1
}
```

The EPSS threshold is independently justifiable: FIRST.org publish daily percentile distributions for all scored CVEs. A threshold of 0.1 corresponds to the top decile of exploitation probability, meaning P4 gates only on findings that are both confirmed real and statistically likely to be exploited in the next 30 days.

---

## Enrichment Data Sources (P4)

| Source | API | Data provided | Policy use |
| ------ | --- | ------------- | ---------- |
| NVD (NIST) | `services.nvd.nist.gov/rest/json/cves/2.0` | CVE status, disputed/rejected flags | Validity confirmation |
| OSV | `api.osv.dev/v1/query` | Advisory existence, affected ecosystem, fix version | Ecosystem confirmation, fixability |
| EPSS (FIRST.org) | `api.first.org/data/v1/epss` | Exploitation probability score (0–1, daily) | Risk prioritisation |

NVD requires an API key for production use. Enrichment results are cached by CVE ID; the same CVE appearing across multiple images is fetched once.

---

## What P4 Addresses

P1–P3 operate entirely on scanner output and answer the question: *is this finding present and consistent across tools?* They cannot distinguish between a CVE that is filed-but-unvalidated and one that is confirmed-and-actively-exploited.

P4 addresses the false positive problem at two levels:

**Validity false positives** — CVEs that scanners detect but that are rejected, disputed, or not yet analysed by NVD, and have no corresponding ecosystem advisory in OSV. These are real entries in vulnerability databases that do not represent confirmed risk to the scanned package. NVD status and OSV advisory checks filter these out.

**Risk false positives** — CVEs that are confirmed real but have negligible exploitation probability. CVSS severity (the basis for P1–P3) measures theoretical impact, not likelihood of exploitation. The majority of CVEs scored CRITICAL are never exploited in the wild. EPSS provides an empirically-derived exploitation likelihood score that re-prioritises findings by actual attacker behaviour rather than theoretical severity.

The delta between P3 and P4 blocking decisions — measured across the 9 experimental images — is the empirical answer to the false positive reduction question.

---

## Why this is the right architecture

| Criterion | Standalone OPA layer | HG fork |
| --------- | -------------------- | ------- |
| Fix data reliability | Uses raw scanner output — reliable | Inherits HG's broken fix propagation |
| Per-scanner attribution for P3/P4 | Preserved from raw JSON | Collapsed by HG deduplication |
| CI/CD integration | Native (exit codes, pipeline stages) | Requires adding to HG codebase |
| Language / stack | Python + Rego (minimal) | TypeScript + Go + Prisma |
| Generalisability | Works with any scanner combination | HG-specific |
| Dissertation scope | Achievable | Pre-requisite bug fixes add scope |
| HG relationship | Positioned as filling its gap | Modifying it |
| Enrichment extensibility | New signals added to enrich.py + Rego | Requires schema and model changes |

---

## HarbourGuard's Role in the Dissertation

HarbourGuard is not discarded — it serves as the primary **motivating case study** for the gap analysis:

> *HarbourGuard represents the current state of multi-scanner orchestration: capable of aggregating and visualising results from six tools, but with no policy enforcement mechanism. Empirical analysis of its output reveals that its normalised data is unsuitable as a policy input: fix status metadata is not reliably propagated (node:14 fix rate: HG 10% vs Trivy 77%), and per-scanner attribution collapses due to aggressive deduplication, rendering cross-scanner consensus policies unreliable within HG's data model. These findings motivate a policy layer that operates directly on raw scanner outputs, independent of any orchestration tool's normalisation decisions.*

The HarbourGuard analysis (7 comparison tables, 4 documented data quality issues) is empirical evidence that directly motivates and justifies the standalone architecture. It is Chapter 4 motivation, not a fork project.

---

## Positioning the Contribution

The dissertation contribution is:

> A **policy-as-code layer** (OPA/Rego) that consumes raw multi-scanner output, normalises it into a tool-agnostic schema, and enforces declarative vulnerability gate policies (P1/P2/P3/P4) in CI/CD pipelines — addressing gaps empirically identified in existing orchestration tools including HarbourGuard. P4 extends the policy layer with external enrichment (NVD, OSV, EPSS) to demonstrate measurable false positive reduction over scanner-native policies.

This is:

- **Empirically motivated** — by the scanner comparison experiment and HG analysis
- **Technically concrete** — working Rego policies with OPA unit tests and a CI/CD pipeline stage
- **Progressive** — four policies of increasing precision enabling quantitative comparison
- **Generalisable** — not tied to any specific orchestration platform
- **Defensible** — the architectural choice is backed by data, not preference

---

## The Gating Assumption and Its Limits

A foundational assumption underlying P1–P3 is that the correct response to a confirmed vulnerability is to block the build. This is appropriate for findings that are confirmed real, fixable, and actively exploited. It is not appropriate for a substantial portion of what scanners report.

In practice, vulnerable libraries ship to production routinely and often for legitimate reasons: no fix version exists yet, upgrading introduces a breaking change, the vulnerable code path is not reachable in the specific application context, or the base image is end-of-life with no upstream patch. In all of these cases, blocking the build does not resolve the vulnerability — it only delays the ship decision and incentivises teams to suppress findings or lower policy thresholds to restore throughput.

This distinction matters for how the system is framed. The goal is not to prevent vulnerable software from shipping — that is frequently impossible. The goal is to ensure that when it ships, the decision was **conscious rather than accidental**, the risk was **understood rather than ignored**, and there is an **audit trail that can answer the question: did you know?**

This reframes the system's output. A gate that blocks or passes is necessary but not sufficient. What the system also needs to produce is a **risk acceptance workflow**: a governed path for cases where shipping with a known vulnerability is the correct operational decision. Within the scope of this prototype, that workflow is represented by the structured output of the policy evaluation — every finding that does not trigger a block is classified with an explicit reason (unconfirmed, no fix available, below EPSS threshold) rather than silently ignored. This transforms implicit tolerance into documented, reasoned acceptance.

The distinction between **known accepted risk** and **unknown unmanaged risk** is the conceptual contribution that separates this approach from a simple severity threshold gate. It is also the property that makes the system defensible under audit: not "we had no CRITICAL findings" but "here is every finding, here is what we confirmed, here is what we accepted and why."

Full governance of the risk acceptance path — time-bounded exceptions, approval workflows, automatic expiry — is identified as future work and is discussed in the Limitations section below.

---

## Limitations and Future Work

### Scope boundary: dependency analysis only

Trivy and Grype operate at the **package and dependency level**. When scanning a container image they inventory what is installed — OS packages, language runtime dependencies, manifest-declared libraries — and cross-reference those versions against vulnerability databases. They do not parse, traverse, or analyse application source code. For a Python API gateway, this means the contents of `app.py`, `routes.py`, and any application logic are entirely invisible to both scanners and to the policy layer built on top of them.

This is not a property specific to the tools chosen for this prototype. It is a characteristic of the entire class of dependency-level vulnerability scanners. The consequence is a reachability gap: a finding can be correctly detected at the package level while being operationally irrelevant because the vulnerable function in that package is never called by the application. The scanner has no mechanism to determine this. Neither does the policy engine.

This gap is the primary limitation of the prototype and the principal direction for future work.

### Why static analysis was not included in scope

Static analysis of application source code — AST parsing, call graph construction, data flow tracing, and reachability determination — represents the technically correct next layer of precision. Tools in this space include Semgrep, Bandit (Python-specific), CodeQL, and purpose-built reachability analysers such as Endor Labs, Phylum, and Socket. Including this layer would, in principle, allow the system to determine whether a vulnerable function in a flagged dependency is actually invoked by the application, and in what manner.

However, incorporating static analysis into this prototype would constitute a category error in scope for the following reasons.

**It requires a second independent system.** The current pipeline has a coherent input boundary — a container image — and a coherent output — a policy verdict on dependency-level findings. Static analysis operates on source code, not on images, and produces call graph artefacts that do not naturally align with CVE-level findings from Trivy or Grype. Correlating a reachability result from a static analyser with a specific CVE finding — establishing that the vulnerable call signature in `pyjwt 1.7.0` is or is not present in the application's JWT decode invocation — is itself a research problem requiring a purpose-built data model. This correlation layer would need to be designed, implemented, and validated before a single Rego rule could be written against it.

**The experimental dataset does not support it.** The 9 images used in this study were selected as representative container workloads for dependency-level scanning. Evaluating reachability would require access to the source code of those applications, controlled environments with known-vulnerable call patterns, and ground truth labels for whether each flagged dependency function is reachable. None of this is available for the current image set, and constructing it would constitute a new experiment rather than an extension of the existing one.

**The evaluation framework would need to change.** The current evaluation measures how many findings each policy blocks and how that count changes across P1 through P4 — a clean quantitative comparison. Adding reachability would require measuring precision and recall of the reachability determination itself: how many findings were correctly classified as unreachable, how many were missed. This requires ground truth that does not exist for the current dataset and cannot be constructed within the available timeframe.

**The contribution would be diluted.** The current prototype makes a focused, defensible claim: that a policy-as-code layer operating on raw multi-scanner output, enriched with NVD, OSV, and EPSS data, produces measurably better gate decisions than scanner-native severity thresholds. Adding static analysis would introduce a second unvalidated claim — that reachability determination is accurate — without the experimental infrastructure to support it. The result would be a prototype that attempts two things and demonstrates neither convincingly.

### Positioning the reachability gap

The correct treatment of the reachability gap is as a **precisely named limitation** that motivates a research agenda, not as an omission to be apologised for. The dependency analysis layer this prototype operates in is the necessary precondition for reachability analysis: you cannot assess whether a vulnerable code path is called until you have reliably identified which packages are present and which CVEs affect them. This prototype addresses that precondition. Reachability analysis is the tier above it.

The tooling landscape for that tier remains immature. Semgrep and CodeQL analyse application code for known insecure patterns but do not automatically map those patterns to specific CVE-identified vulnerable call signatures in third-party dependencies. Purpose-built reachability tools (Endor Labs, Phylum, Socket) are attempting this mapping but remain proprietary, language-specific, and not yet integrated into the open-source scanner ecosystem that this prototype targets. The problem is active, open, and unsuitable for resolution within the scope of a masters prototype.

This also reinforces the risk acceptance argument made in the preceding section. Because reachability cannot be determined automatically, human judgement about application-level context remains irreplaceable. A developer who knows that their API gateway never follows HTTP redirects can correctly assess that a CVE in `requests` affecting redirect handling is not exploitable in their deployment. The system cannot make that determination. What it can do — and what this prototype does — is ensure that when that judgement is made, it is documented, reasoned, and auditable rather than silent.

### Additional future work

The risk acceptance workflow is implemented at the classification level only — findings that do not trigger a block are categorised with an explicit reason and logged. A production governance layer would extend this with time-bounded exception records, security team approval gates, and automatic re-evaluation on expiry, ensuring that accepted risk is periodically reviewed rather than indefinitely deferred.

EPSS scores are fetched at scan time and reflect exploitation probability on that day. A production system would re-evaluate enriched findings on a schedule, since a CVE accepted at EPSS 0.02 may cross the policy threshold weeks later as exploitation activity increases. Drift detection of this kind is outside the current scope.

---

*Supporting data: `logs/harborguard_results.json`, `logs/harborguard_analysis.txt`, `HARBORGUARD_ANALYSIS.md`*
*See also: `notes_scanner_internals.md`, `analysis_narrative.md`*
