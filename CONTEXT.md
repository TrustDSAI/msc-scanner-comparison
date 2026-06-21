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
A YAML record (CVE ID + expiry + approval) that authorizes Suppression of a specific Finding. Distinct from a `gate-override`, which bypasses the build-failure step entirely without touching the gate's own verdict.
_Avoid_: waiver, allowlist entry

## Open questions

- **Block-tier asymmetry.** The gate is biased toward pushing ambiguous Findings to `review` rather than risking a wrongly-blocked build. Not yet resolved whether `review`-tier volume (reviewer fatigue) is a real enough cost to pull some borderline corroborated-but-low-EPSS Findings back toward auto-`pass`.
