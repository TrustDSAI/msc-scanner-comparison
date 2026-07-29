# Real-World Baseline Policies vs p_gate (30 images)

## Question

The thesis compares p_gate against P1, a naive "any CRITICAL blocks"
policy computed on the *merged* (cross-scanner, deduplicated) CRITICAL
count. It doesn't show what the two single-scanner CLI invocations teams
actually run in CI look like: `trivy --severity CRITICAL --exit-code 1`
and `grype --fail-on critical`. Those operate on each tool's own native
CRITICAL findings, not the merged count, and can disagree with each
other on the same image.

## Method

`analysis/baseline_policies.py` reads Trivy's and Grype's native raw
findings (`data/raw/{trivy,grype}/*.json`, no new scans needed — the
data already covers all 30 images) and computes three block/pass
policies per image:

1. `trivy --severity CRITICAL --exit-code 1` — block if Trivy's own
   scan reports any CRITICAL finding.
2. `grype --fail-on critical` — block if Grype's own scan reports any
   CRITICAL finding.
3. fixable-CRITICAL-only — block if either tool reports a CRITICAL
   finding with a fix available.

p_gate's per-image verdict is taken directly from the thesis's Table 5.6
(rule classifier, 2026-06-21 run).

## Result

```
Total images: 30
trivy --severity CRITICAL --exit-code 1  blocks: 24/30
grype --fail-on critical                  blocks: 26/30
fixable-CRITICAL-only (either tool)        blocks: 21/30
p_gate (tri-state, rule classifier)        blocks: 10/30
```

Images where trivy-only and grype-only single-scanner gates disagree
outright on block vs. pass (2/30): `eclipse-temurin:8-jre` and
`eclipse-temurin:21-jre` — Trivy reports zero CRITICAL findings on both
(passes cleanly), Grype reports one CRITICAL on each (blocks). Full
per-image table: run `python3 analysis/baseline_policies.py`.

## Conclusion

This sharpens the thesis's existing "26/30 naive gate vs. 10/30 p_gate"
comparison (Table 5.6, §5.5), which uses the merged CRITICAL count, into
what teams actually run: three *different* real CLI baselines, ranging
24-26/30, all clustered well above p_gate's 10/30. The two Java images
where Trivy and Grype flatly disagree (`eclipse-temurin:8-jre`,
`eclipse-temurin:21-jre`) are a concrete, small-scale illustration of the
exact risk the thesis's RQ4 finding names in the abstract: "a team using
Trivy may apply a substantially different risk threshold than a team
using Grype on the same image, not because their security policies
differ, but because their scanners do" — here literalised as one tool
blocking a build the other tool would pass, on the same image, same day.

Whether to add this as a table in §5.5/§6.3 is a separate, thesis-side
decision — this doc and `analysis/baseline_policies.py` are the evidence
if so.
