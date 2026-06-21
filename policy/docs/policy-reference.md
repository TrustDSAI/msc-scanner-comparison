# p_gate policy reference

The default policy (`rego/p_gate.rego`, package `vuln.gate`). Produces three
output sets per gate run: `block`, `review`, `suppressed` — see `Tier`/
`Decision` in [`CONTEXT.md`](../../CONTEXT.md) for what each means.

## Block tier (beyond reasonable doubt)

A finding blocks the build if either:

1. **KEV path** — in CISA's Known Exploited Vulnerabilities catalog AND a
   fix is available (`kev_requires_fix: false` blocks without a fix too).
2. **Corroborated-CRITICAL path** — CRITICAL, cross-scanner consensus, fix
   available, NVD status in `nvd_acceptable_statuses`, OSV confirms the
   advisory and a fix, AND EPSS above `block_epss_threshold` (default 0.5).

Both paths require multiple independent signals to agree. This is
deliberate: the gate is biased toward pushing ambiguous findings to
`review` rather than risking a wrongly-blocked build (a missed real RCE
silently passed costs more than a few minutes of reviewer time, but a
wrongly-blocked build has an immediate, visible cost). The block tier is
**layer-agnostic** — a fully corroborated EPSS-0.5+ finding is decisive
regardless of whether it's app or OS layer.

## Review tier

Three independent paths reach `review`:

1. **Corroborated CRITICAL below the block EPSS bar** — same five
   signals as the block path's condition 2, minus the EPSS requirement.
   Reviews **unconditionally** by default — EPSS is a 30-day exploitation
   forecast, not a severity signal, and decays as attacker interest moves
   on; a cross-scanner-confirmed CRITICAL with a confirmed fix doesn't
   stop being real just because this week's score is low. (Observed live:
   `CVE-2023-32314`'s EPSS fell from 0.70 in March to ~0.06 by June with
   no change to the CVE or its fix.) Configurable opt-out:
   `corroborated_critical_min_epss` (default `null` = no floor) lets an
   operator trade some recall for less review-tier volume — a deliberate,
   visible config choice, not the default.
2. **Any other CRITICAL** (single-scanner, no OSV advisory, no fix —
   i.e. NOT fully corroborated) — gated by a **layer-aware EPSS floor**:
   `review_critical_app_min_epss` (default 0.1), `review_critical_os_min_epss`
   (default 0.01), or `review_critical_unknown_min_epss` (default 0.0) when
   `Finding.layer` is missing/unknown. This is the only place layer
   classification has any effect on the gate — see
   [`architecture.md`](./architecture.md). The asymmetry is sourced from
   the P5_layer experiment (Chapter 5, P1-P7 architecture), which showed
   per-layer EPSS asymmetry cuts noise without losing real findings
   (block-tier reduction there: juice-shop 9→1, web-dvwa 198→116). Folding
   the same asymmetry into p_gate's review floor produced an analogous
   effect at the review tier: python:3.8's review count dropped 669→489
   once the floor applied (verified via direct `opa eval` against the
   batch dataset's enriched input, not yet re-run end-to-end through
   `evaluate_all.py`).
3. **HIGH with a fix and consensus** — severity labels are untrustworthy
   across scanners, so HIGH never auto-blocks regardless of evidence
   quality; it's always surfaced. `review_high_min_epss` (default 0.0) can
   raise the bar to suppress noisy low-EPSS HIGH findings.
4. **KEV without a fix** — actively exploited, no remediation path. Can't
   block (the build could never pass), must surface.

## Pass

Everything else. Image EOL is attached as context on every block/review
entry (`lib.make_msg`) but never independently moves a finding between
tiers — acting on EOL is a CI-workflow decision, not a policy decision.

## Suppression

A finding matching an unexpired entry in `input.exceptions` is excluded
from both `block` and `review`, recorded instead in `suppressed` with a
`would_have_been: "block"|"review"` field for audit. See
`exceptions_loader.py` and `docs/notes_suppression_workflow_design.md` at
the repo root — **note that doc's implementation-status block**: only the
YAML loader + suppression predicate + expiry mechanics shipped, not the
LLM-drafted-proposal/auto-PR/approval-verification half of that design.

## Config schema

All keys optional; defaults shown. Pass `--policy <config.json>` to
override any subset.

```json
{
  "block_epss_threshold":             0.5,
  "review_high_min_epss":             0.0,
  "review_critical_app_min_epss":     0.1,
  "review_critical_os_min_epss":      0.01,
  "review_critical_unknown_min_epss": 0.0,
  "corroborated_critical_min_epss":   null,
  "nvd_acceptable_statuses":          ["Analyzed", "Modified"],
  "kev_requires_fix":                 true,
  "enable_kev_block":                 true,
  "enable_critical_block":            true
}
```

## Custom policies

Supply `--rego-dir`/`--policy-package` to replace `p_gate.rego` entirely.
The custom package must expose `block` and `review` (sets of objects with
at least `cve_id`, `package`, `version`, `reason`). `suppressed` is
optional — `opa_eval()`'s `or []` fallback handles an undefined rule.
