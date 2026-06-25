# Policy Gate

A policy-as-code layer (OPA/Rego) that consumes raw multi-scanner container vulnerability output (Trivy + Grype), enriches it with NVD/OSV/EPSS/KEV, and produces a gate decision that is measurably better than scanner-native severity thresholds — fewer false-positive blocks, without silently dropping real findings.

## Language

**Finding**:
One CVE detected against one package/version in one scanned image. The unit everything else (enrichment, classification, tiering) operates on.
_Avoid_: vulnerability, issue, result

**Tier**:
The outcome (`block` | `review` | `pass`) a single Finding qualifies for. Scoped to one Finding — see **Decision**.
_Avoid_: decision (per-finding), classification, label

**Decision**:
The per-image aggregate outcome: the worst Tier across all of an image's Findings (`block` if any Finding blocks, else `review` if any reviews, else `pass`). Scoped to the whole gate run, never to a single Finding.
_Avoid_: verdict (used interchangeably with decision at the image level, but decision is the canonical term going forward), tier (per-finding, not per-image)

**Corroborated** (Finding):
A Finding where every independent signal agrees: cross-scanner consensus, a fix is available, NVD validates the CVE, and OSV confirms the advisory and fix. Corroboration is the gate's confidence threshold — EPSS is evaluated separately and decides which tier a corroborated Finding lands in, not whether it's corroborated.
_Avoid_: confirmed, validated, verified

**Suppression**:
The act of excluding a Finding from `block`/`review` because it matches an unexpired Exception, recorded instead in a third output set with a `would_have_been` tier for audit.
_Avoid_: exemption, waiver, allowlist

**Exception**:
A YAML record (CVE ID + expiry + approval) that authorizes Suppression of a specific Finding. Distinct from a `gate-override`, which bypasses the build-failure step entirely without touching the gate's own verdict. The `approval` field is an audit-trail record, not an enforcement mechanism — see Decisions below.
_Avoid_: waiver, allowlist entry

## Decisions

- **Block-tier asymmetry is intentional and stays, but the corroborated-CRITICAL review floor is configurable.** Default: a fully Corroborated CRITICAL always reaches `review` regardless of EPSS — a missed real RCE silently passed is worse than a few minutes of reviewer time, and reviewer fatigue is primarily addressed by compressing the queue (the LLM advisor's top-20-by-EPSS batch summary), not by weakening the evidence bar. But `corroborated_critical_min_epss` (default `null` = no floor) lets an operator opt into trading some recall for less review-tier volume if they decide that trade is right for their team — a visible, deliberate config choice, not the gate's default behaviour.

- **Exception/Suppression has no built approval enforcement, and is documented as such, not implied otherwise.** The shipped mechanism is YAML-stored exceptions, the `lib.suppressed` predicate, and expiry-by-date or by-fix-available — the audit-trail half of the design. The governance half (LLM-drafted proposals, auto-opened exception PRs, CODEOWNERS or cryptographic approval verification) was deliberately not built; PR review is the only real control, same scope-boundary treatment as the reachability-analysis gap. `docs/notes_suppression_workflow_design.md` carries an explicit implementation-status note rather than reading as a description of what's running.

- **Layer classification's blast radius is intentionally narrow: one config-gated EPSS floor, nothing else.** It never touches the block tier (explicitly layer-agnostic), the corroborated-critical review path (also layer-agnostic, configurable separately), or the consensus-without-fix review path below (also layer-agnostic). It is not surfaced to the LLM advisor either — `advise_batch()`, the only advisor path actually called, omits layer from its prompt entirely. The classifier's job is bounded to one thing: deciding the noise floor for single-scanner, non-corroborated CRITICALs in review. `ReviewAdvisor.advise()`/`_build_prompt()`/`_USER_TEMPLATE` (the older per-finding path that did pass layer to the LLM) were dead code with no callers and were removed.

- **Cross-scanner consensus alone is enough to bypass the layer floor, even without a fix.** `enable_consensus_review` (default `true`): a CRITICAL detected by both Trivy and Grype that fails `corroborated_critical` only on fix/NVD-status/OSV-advisory (not on consensus) always reaches `review`, EPSS-independent — same rationale as the corroborated-but-low-EPSS case, since two independent tools agreeing is itself a corroboration signal. Added after dissertation review found `php:8.3-apache`'s 9 consensus CRITICALs (no fix yet, NVD `"Deferred"`, EPSS 0.004–0.007) passing cleanly under the layer-floor-only rule, contradicting the gate's own design claim that no-fix/low-EPSS findings are surfaced rather than dropped. The layer floor now governs only single-scanner CRITICALs.

- **All four enrichers retry transient failures uniformly.** Originally only NVD did (added live, after an NVD outage corrupted a dataset run). Generalizing turned out cheap: OSV and EPSS don't use NVD's rate-limit lock at all, so wrapping their fetch in the shared `enrichers/_retry.retry_async()` is a plain wrap; KEV's bulk catalog download uses the sync counterpart. A 404 (a meaningful negative result for OSV) or any other non-transient error still fails on the first attempt, no wasted retries.
