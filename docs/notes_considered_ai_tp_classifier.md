# Considered and Rejected: LLM-based True-Positive / False-Positive Classifier

**Date:** 2026-06-04
**Decision:** Do not implement an LLM-based per-CVE applicability triage policy (proposed as "P7").
**Status:** Rejected

---

## What Was Proposed

An additional policy variant ("P7") in which an LLM agent reads the CVE description, OSV advisory text, and possibly GitHub Security Advisory text, then classifies each blocking finding as `true_positive`, `false_positive`, or `uncertain`. The verdict would either keep or suppress the corresponding block from P5 / P6.

The intent was twofold: reduce noise on legitimate-but-low-applicability findings, and demonstrate a richer agentic use of LLMs in the policy layer beyond binary classification.

---

## Why It Was Rejected

### 1. The LLM has less information than the scanner

For determining whether a CVE applies to a specific package at a specific version, the authoritative inputs are:

- CPE match data (structured product/vendor/version triple)
- Affected version ranges from NVD / OSV / GHSA
- Package metadata (origin, distribution, build flags)

The scanner has all of this. The LLM has the CVE description (mostly free-text prose) and whatever the prompt provides. A natural-language model is being asked to *re-do* a structured-data match that the scanner already performed, with less data than the scanner had. The expected outcome is that the LLM produces a less accurate match than the scanner that fed it.

This is the wrong direction for the agentic layer. The agent should add information the structured pipeline lacks, not relitigate structured matches.

### 2. Reachability is the real false-positive problem, and LLMs cannot do it

The dominant category of operational false positives is reachability: the CVE-affected function exists in the installed package but is never called by the application. Resolving this requires static analysis of the application source code, call-graph construction, and matching against the CVE's vulnerable call signature.

No general-purpose LLM does this. Purpose-built reachability tools (Endor Labs, Phylum, Socket) approach it through dedicated indices and pattern matching, not by reading prose.

A P7 that tried to address reachability would either (a) make claims the LLM cannot defend, or (b) restrict itself to cases the LLM can defend, which by elimination are mostly the cases P4 already handles via NVD and OSV.

### 3. Hallucination cost in security is asymmetric and high

The cost of two policy errors is not symmetric:

- A false positive that the policy keeps (over-blocking) wastes engineering time. Recoverable.
- A false negative that the policy passes (under-blocking) ships a vulnerable image. Not recoverable without an incident.

An LLM that suppresses a block based on a hallucinated chain of reasoning, even rarely, introduces the worse error. The threshold for trusting an LLM verdict to *override* a structured-data signal must be very high to be defensible. With current general-purpose models at temperature 0, that threshold is not met.

### 4. No ground truth exists for evaluation

The framework cannot be honestly evaluated without per-finding ground-truth labels (TP vs FP). Constructing such labels requires:

- Manual triage by a security engineer
- Per-finding source-code review for reachability
- Vendor confirmation for CPE-match correctness

None of this is available for the dataset used in this work and cannot be constructed within the project scope. Any reported "accuracy" for an LLM TP/FP classifier would be measured against itself or against another unvalidated source, not against truth.

The architecture supports running the classifier and reporting suppression rates. Those numbers would be operationally interesting and academically uninterpretable. Publishing them risks legitimising an evaluation method that does not establish what it appears to establish.

### 5. The cost / precision balance favours other layers

For roughly the same complexity and cost budget, the architecture already addresses several false-positive categories more rigorously:

| FP category                                  | Already handled by                                   |
|----------------------------------------------|------------------------------------------------------|
| CVE rejected or disputed by NVD              | P4 NVD status check                                  |
| CVE has no ecosystem advisory                | P4 OSV advisory check                                |
| CVE has no upstream fix                      | P2 / P4 fix-availability check                       |
| CVE not actively exploited                   | P4 EPSS threshold                                    |
| CVE on a base that will never be patched     | P6 EOL short-circuit                                 |
| Code reachability                            | Not handled. Future direction. LLMs do not solve it. |

The remaining LLM-addressable subset (overreaching CPE matches, subtle ecosystem mismatches not caught by OSV) is genuine but narrow. The proposed P7 would target this narrow subset using a method (LLM applicability reasoning) that cannot be evaluated against ground truth and has the asymmetric hallucination risk described above. The cost of building it does not buy a proportionally improved outcome.

### 6. The contribution would dilute the architectural claim

The current contribution of the policy layer is a working, parameterised, configuration-driven framework with measurable cross-tool / cross-context gating outcomes. The LLM is used in two places where its semantic judgment is the only available signal: layer classification (where no structured source distinguishes OS-packaged application code) and EOL fallback (where endoflife.date and Trivy do not cover an image).

Adding an LLM TP/FP classifier on top of this widens the LLM dependency to a third role where its judgment is *not* the only available signal but *competes* with the scanner's structured-data signal. This blurs the architectural story from "policy framework that uses semantic agents where structured data is insufficient" to "we used LLMs wherever we could." The latter is a weaker contribution to a thesis and a less defensible position to a reviewer.

### 7. Reproducibility weakens further

Each agentic component in the architecture is a non-determinism source. The current design contains two: layer classifier and EOL fallback (the EOL fallback is in fact unused on the experimental dataset; structured sources cover all nine images). Adding a third agentic component for TP/FP triage would expand the non-deterministic surface to cover *every blocked finding* on every run.

Suppression verdicts that vary between runs of the same dataset undermine the property that makes the policy layer reviewable: a fixed input produces a fixed output. Caching mitigates this for individual runs but does not address the case where the suppressed finding turns out, weeks later, to be a real vulnerability that was incorrectly waved through.

---

## What Was Kept

The two existing agent-augmentation points remain in scope and are evaluated empirically in Chapter~6:

1. **Layer classification** (used by P5\_layer). Justified because no structured source distinguishes OS-packaged application code from OS-distribution code; the agent fills a real gap, has a falsifiable output (rule-classifier disagreement is auditable), and can be cross-checked against a deterministic baseline.
2. **EOL semantic fallback** (used by P6 when endoflife.date and Trivy OS EOSL both fail). Justified because the structured sources are authoritative when present, and the LLM is invoked only on the long tail. On the experimental dataset, the fallback was never triggered.

Both kept uses are characterised by the same property: the LLM is the only available source for that specific signal, not a competing source against structured data.

---

## What Future Work Could Look Like Instead

The architectural-decision document already identifies reachability analysis as the principal future direction. A reachability-aware policy (P7 or beyond) would address the real false-positive problem the rejected design tried to approach indirectly:

- Integrate a purpose-built reachability tool (Semgrep call-graph analysis, Endor Labs API, or similar) as a finding-level signal
- Map the reachability tool's output to a structured boolean (`function_called: bool | unknown`)
- A new policy variant blocks only when reachable or unknown; suppresses unreachable findings explicitly

This addresses the underlying operational concern (reduce noise on findings that cannot actually be triggered) using a tool designed for the task, with a structured output that policy can act on deterministically.

A separate future direction is governed risk acceptance: an LLM that drafts justification text for a *human* to review and approve as a suppression, rather than the LLM itself making the suppression decision. This places the LLM in an advisory role with a human in the loop, addressing the hallucination-cost asymmetry. The architectural-decision document already notes risk-acceptance governance as future work; an LLM draft-and-review workflow is the natural implementation path.

---

## Summary

LLM-based TP/FP classification was considered as a P7 policy variant and rejected. The proposal asked an LLM to relitigate a structured-data match using less data than the scanner had, in a domain where the cost of hallucinated suppressions is asymmetric and the available ground truth is insufficient for evaluation. Two narrower future directions, reachability-aware gating and human-in-the-loop risk acceptance, address the underlying operational concerns more rigorously and are preserved as scope for follow-on work.

The two existing agentic components in the architecture (layer classification, EOL fallback) remain because they each fill a real gap that no structured source covers, with falsifiable outputs and deterministic baselines for comparison.

---

*See also:*
- `notes_architectural_decision.md` — policy layer design and rejected fork-HarbourGuard alternative
- `policy_experiment_results.md` — empirical results for kept policies P1--P6
