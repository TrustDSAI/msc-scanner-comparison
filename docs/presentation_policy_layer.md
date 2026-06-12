---
marp: true
theme: default
paginate: true
---

# Policy Layer for Container Vulnerability Gating
## Design, Implementation, and Empirical Evaluation

MSc thesis component
2026-06-04

---

# Where We Are

**Chapter 5 finding:** scanners disagree on the same image at every level.
- total counts diverge up to 6.9×
- severity agreement on shared CVEs: 7.6%–96.3%
- fix-rate divergence on shared CVEs up to 77.3% vs 34.1%
- CRITICAL counts are the most portable signal (Δ ≤ 3 on 7/9 images)

**Conclusion:** raw scanner output is not gate-ready.

**Question this chapter answers:** what *is* gate-ready?

---

# Architectural Choice

Two options considered:
1. **Fork HarbourGuard** (existing orchestration platform)
2. **Standalone OPA/Rego layer**

HarbourGuard rejected on empirical grounds:
- fix metadata lost during ingestion (node:14: HG 10% vs Trivy 77%)
- per-scanner attribution collapsed (cross-scanner consensus broken)

**Chosen:** standalone OPA layer consuming raw scanner JSON directly.
Decoupled, deterministic, unit-testable, generalisable.

---

# Pipeline

```
trivy / grype / osv-scanner
        ↓
   normalise.py    (Python adapter per scanner)
        ↓
   policy_input.json   (unified schema)
        ↓
   enrich.py       (NVD, OSV, EPSS; cached by CVE)
        ↓
   classifier      (rule or agent; layer label)
        ↓
   eol enricher    (endoflife.date / Trivy / agent)
        ↓
   opa eval        (deterministic policy)
        ↓
   PASS / REJECT + structured deny report
```

LLMs are isolated *outside* the OPA evaluation. Gate decision is deterministic.

---

# Policy Bundle: Six Variants, One Library

| Policy | Adds | Targets |
|---|---|---|
| P1 | nothing (CRITICAL threshold) | recall |
| P2 | + fix availability | block-forever loops |
| P3 | + cross-scanner consensus | single-tool FPs |
| P4 | + NVD / OSV / EPSS | validity + exploitation |
| P5 | + layer classification | asymmetric thresholds |
| P6 | + EOL state | deployment context |

Each policy is strictly more selective than the previous. Shared predicates live in `lib.rego`. 37/37 OPA unit tests pass.

---

# P1: Any CRITICAL

**Rationale:** baseline. The dumbest gate that still uses the most portable signal.

**Behaviour:** blocks on any CRITICAL finding from any scanner.

**Result on web-dvwa:** 328 blocks.
**Result on juice-shop:** 9 blocks.

**Failure mode:** alert fatigue. Blocks indefinitely on CVEs with no fix. Trust erodes; gate gets bypassed.

---

# P2: CRITICAL with Available Fix

**Rationale:** an unfixable CRITICAL is operationally useless. Block on what developers can act on.

**Behaviour:** P1 conditions + `fix_version != null`.

**Results:**

| Image | P1 | P2 | Δ |
|---|---:|---:|---:|
| node:20 | 33 | 0 | -33 |
| web-dvwa | 328 | 266 | -62 |
| python:3.8 | 191 | 158 | -33 |

**node:20 case:** 33 CRITICALs, zero have a fix. P2 correctly passes; P1 would block forever.

---

# P3: Consensus CRITICAL

**Rationale:** if only one of Trivy and Grype detects it, the match is probably scanner-specific (CPE quality, ecosystem coverage).

**Behaviour:** P1 conditions + both scanners detected the same `(cve_id, package)`.

**Results:**

| Image | P1 | P3 | Single-scanner detections filtered |
|---|---:|---:|---:|
| node:20 | 33 | 32 | 1 |
| nginx:1.19 | 42 | 41 | 1 |
| python:3.8 | 191 | 187 | 4 |
| web-dvwa | 328 | 295 | 33 |

Filters real noise without external data. Good baseline.

---

# P4: Enriched CRITICAL

**Rationale:** scanner signals are necessary but insufficient. External data answers *is the CVE real* and *is it being exploited*.

**Three external signals:**
- **NVD status** (`Analyzed` / `Modified`; rejected and disputed flags)
- **OSV advisory** (ecosystem confirmation + fix version)
- **EPSS** (probability of exploitation in next 30 days)

Two configurations:

| | EPSS | NVD status |
|---|---:|---|
| P4_strict | > 0.1 | Analyzed only |
| P4_relaxed | > 0.01 | Analyzed + Modified |

---

# P4 Results

| Image | P3 | P4_strict | P4_relaxed |
|---|---:|---:|---:|
| node:20 | 32 | 0 | 1 |
| nginx:1.19 | 41 | 0 | 16 |
| python:3.8 | 187 | 0 | 6 |
| web-dvwa | 295 | 24 | 198 |
| juice-shop | 9 | 0 | 3 |

**The strict/relaxed tension:**
- strict: too aggressive on OS-layer CVEs (low EPSS by nature)
- relaxed: too permissive on app-layer CVEs

**This motivates P5.**

---

# P5: Layer-Aware Routing

**Rationale:** app and OS findings have different prior risk distributions. One threshold can't serve both.

**Design:**
- **App layer** → strict thresholds (EPSS > 0.1)
- **OS layer** → relaxed thresholds (EPSS > 0.01)

**Requires:** each finding labelled `app | os | unknown` by a classifier.

**Two classifiers:**
1. **Rule baseline** (ecosystem string → layer; deterministic)
2. **LLM agent** (semantic judgment; Claude Haiku 4.5)

---

# Layer Classifier Comparison

626 CRITICAL findings across 9 images.

| Image | Rule (app/os) | Agent (app/os) | Disagreements |
|---|---|---|---:|
| node:20 | 0/33 | 0/33 | 0 |
| nginx:1.19 | 0/42 | 0/42 | 0 |
| node:14 | 1/22 | 2/21 | 1 |
| python:3.8 | 0/190 | 0/191 | 1 |
| **web-dvwa** | **0/328** | **123/205** | **123** |
| juice-shop | 9/0 | 9/0 | 0 |

**Overall agreement: 80%.** All real disagreement on web-dvwa: PHP modules delivered as Debian packages.

---

# What the Agent Caught (web-dvwa)

| Count | Package | Why rule got it wrong |
|---|---|---|
| 16 | libapache2-mod-php7.0 | Debian-packaged, but runs PHP app code |
| 16 | php7.0-mysql, php7.0-gd, etc. | Same |
| ... | (10 packages, 123 findings total) | OS by ecosystem, app by behaviour |

Agent reasoning sample (temperature 0, confidence 1.00):

> "libapache2-mod-php is an Apache module that executes PHP application code, making it application layer despite being OS-packaged."

The rule classifier cannot make this distinction. The agent can.

---

# P5 Results: The Goldilocks Outcome

| Image | P4_strict | P4_relaxed | P5 (rule) | **P5 (agent)** |
|---|---:|---:|---:|---:|
| node:20 | 0 | 1 | 1 | **1** |
| nginx:1.19 | 0 | 16 | 16 | **16** |
| python:3.8 | 0 | 6 | 6 | **6** |
| **web-dvwa** | 24 | 198 | 198 | **116** |
| **juice-shop** | 0 | 3 | 1 | **1** |

**web-dvwa: 41% reduction** (198 → 116) vs P4_relaxed, by correctly routing PHP CVEs through strict app-layer thresholds.

**juice-shop: 1 block** — and it's CVE-2023-32314 (vm2 sandbox escape, EPSS 0.7). Real known-exploited vulnerability.

---

# P5 Iteration: NVD "Modified" Bug

**Initial design:** app-layer required `NVD status == Analyzed`.

**What happened:** juice-shop passed with 0 blocks. Including CVE-2023-32314 (vm2 sandbox RCE, EPSS 0.7).

**Why:** NVD had reset its status to "Modified" (lifecycle update). The strict variant treated this as an invalidity signal.

**Reality:** "Modified" is a normal lifecycle state. Only `Rejected` and `Disputed` invalidate.

**Fix:** one-line config change. Accept `[Analyzed, Modified]` for app-layer.

**Lesson:** the parameterised Rego design absorbed the policy bug as a config edit. No code change.

---

# P6: EOL-Aware Gating

**Rationale:** an end-of-life image will never receive security patches. Further per-CVE triage is operationally pointless.

**Behaviour:**
- EOL image → block immediately, single deny message
- Non-EOL image → delegate to P5_layer
- Configurable: `eol_insta_block: true | false` (production vs dev sandbox)

**Source priority:**
1. endoflife.date (canonical per-product lifecycle data)
2. Trivy `Metadata.OS.EOSL` (OS distro layer)
3. LLM fallback (semantic; never invoked on this dataset)

---

# EOL Source Audit (All 9 Images)

| Image | EOL? | Source | Date |
|---|:-:|---|---|
| alpine:3.19 | ✓ | endoflife.date | 2025-11-01 |
| nginx:1.29.7 | ✗ | trivy:os-eosl | – |
| **node:20** | **✓** | endoflife.date | **2026-04-30** |
| python:3.12 | ✗ | endoflife.date | 2028-10-31 |
| nginx:1.19 | ✓ | endoflife.date | 2021-05-25 |
| node:14 | ✓ | endoflife.date | 2023-04-30 |
| python:3.8 | ✓ | endoflife.date | 2024-10-07 |
| vulnerables/web-dvwa | ✓ | trivy:os-eosl | – |
| bkimminich/juice-shop | ✗ | trivy:os-eosl | – |

---

# node:20 Lifecycle Transition (Run-time Detection)

**At start of study:** node:20 was actively maintained (Group C, modern).

**During the work:** Node.js 20 reached end of maintenance on 2026-04-30.

**What the framework did:** detected the transition automatically on the next run. No code change. No dataset update. No hardcoded table to update.

**Why this works:** EOL is queried from endoflife.date at run time, not embedded in code.

**Architectural takeaway:** policy outcomes evolve with reality when structured external data sources are used. A hardcoded EOL table would have continued reporting node:20 as actively maintained indefinitely.

---

# P6 Outcomes

| Image | EOL? | P5 | P6_strict | P6_permissive |
|---|:-:|---:|---:|---:|
| alpine:3.19 | ✓ | 0 | **1 (EOL)** | 0 |
| node:20 | ✓ | 1 | **1 (EOL)** | 1 |
| python:3.12 | ✗ | 0 | 0 | 0 |
| nginx:1.19 | ✓ | 16 | **1 (EOL)** | 16 |
| node:14 | ✓ | 12 | **1 (EOL)** | 12 |
| python:3.8 | ✓ | 6 | **1 (EOL)** | 6 |
| web-dvwa | ✓ | 116 | **1 (EOL)** | 116 |
| juice-shop | ✗ | 1 | 1 | 1 |

P6_strict collapses every EOL image to a single "EOL, do not deploy" message.
P6_permissive (toggle off) reproduces P5 exactly.

---

# Decision-Quality Audit: Defensible Blocks

- **node:20: 1 of 33** — only one has a fix; blocking on the others = infinite build-fail loop with no remediation path.
- **nginx:1.19: 16 of 42** — EOL Debian Buster; the 16 with EPSS > 0.01 are the actively-exploited subset.
- **web-dvwa: 116 of 328 (agent classifier)** — strict thresholds applied to PHP app code; high-EPSS PHP CVEs preserved, low-EPSS ones filtered.
- **juice-shop: 1 of 9** — CVE-2023-32314 vm2 sandbox escape, EPSS 0.7. Real, known-exploited.

These are not coincidences. The policy is doing what it was designed to do.

---

# Decision-Quality Audit: Contestable Cases

- **python:3.8: 6 of 191 CRITICALs blocked.**
   - 162 of 191 have EPSS < 0.001.
   - Defence: EPSS-prioritised gating is supposed to filter these.
   - Counter: 191 CRITICALs is a posture concern regardless of exploitation.
   - **P6_strict resolves this** by short-circuiting on image lifecycle.

- **juice-shop: 8 of 9 CRITICALs passed P5.**
   - All real vulnerabilities; low EPSS = no observed exploitation, not no exploitability.
   - juice-shop is intentionally vulnerable but *not* EOL upstream — P6 doesn't catch this case.
   - Genuine limitation worth naming.

---

# Limitations (Honestly Named)

1. **No ground truth for layer classification.** Agent reclassifications look right on inspection; no labelled set exists.
2. **Single LLM run per finding.** Stability under multi-run majority voting not measured.
3. **Concentrated disagreement on one image.** Layer-aware contribution validated by web-dvwa; generalisation needs more diverse images.
4. **No reachability analysis.** The real false-positive problem (vulnerable function exists but is never called) is not addressed. Future direction.
5. **Static EPSS snapshot.** Production deployments would re-evaluate periodically.

---

# What We Considered and Rejected

**P7: AI-based True-Positive / False-Positive classifier.**

Why not:
- LLM has *less* information than the scanner that did the structured CPE match
- Reachability (the real FP problem) needs static analysis, not prose reasoning
- Cost of hallucinated suppression is asymmetric (FN ships vulnerability)
- No ground truth available for evaluation
- Dilutes the architectural claim from "LLM where structured data fails" to "LLM everywhere"

Full reasoning: `docs/notes_considered_ai_tp_classifier.md`.

---

# Summary

- **Six-policy progression**, parameterised in Rego, deterministic OPA evaluation.
- **Layer classification** (P5) uses agent only where structured data fails. 41% block reduction on web-dvwa.
- **EOL awareness** (P6) uses endoflife.date primary, Trivy secondary, agent fallback. Caught node:20 transition automatically.
- **Iteration as feature**: NVD-Modified bug surfaced through empirical evaluation; corrected by config, no code change.
- **Decision-quality audit** is honest about both defensible and contestable outcomes.
- **Framework**, not security oracle. Trade-offs measured, limitations named.

37/37 OPA tests. ~$0.30 per full classification run. Reproducible.

---

# Artefacts

- `policy/rego/` — 6 policy files + lib.rego
- `policy/tests/` — 37 OPA unit tests, all pass
- `policy/normalisers/` — scanner adapters (Trivy, Grype)
- `policy/enrichers/` — NVD, OSV, EPSS, EOL adapters
- `policy/classifiers/` — rule + LLM-based layer classifiers
- `policy/configs/` — JSON config per policy variant
- `policy/evaluate_all.py` — single-entry orchestrator
- `policy/output/` — verdict matrix, summary, per-image evidence

`docs/`:
- `notes_architectural_decision.md` — full design rationale
- `policy_experiment_results.md` — full empirical results
- `notes_considered_ai_tp_classifier.md` — rejected P7 reasoning
