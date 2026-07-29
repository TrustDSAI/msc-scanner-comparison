# Day 3: Leave-One-Out Signal Ablation (30 images)

## Question

p_gate corroborates six independent signals (consensus, fix availability,
NVD status, OSV confirmation, EPSS, KEV) plus layer-aware routing.
Which of these actually change the gate's output, and which are along
for the ride?

## Method

`analysis/ablation.py` reuses the already-enriched, already-verified
per-image input files (`policy/output/<safe>_enriched_rule.json`, from
the 2026-06-21 run that produced the thesis's Table 5.6) rather than
re-fetching NVD/OSV/EPSS/KEV live. This holds the dataset and enrichment
fixed and varies only the signal being tested — the same "dataset fixed,
policy varied" methodology the thesis's own P1-P7 development used
(§4.2.1). No network calls; fully reproducible from what's already on
disk.

For each ablation, one signal is neutralised on every finding in every
image (e.g. "disable KEV" sets every finding's KEV status to
not-listed), the tri-state gate is re-evaluated via `opa eval` against
the **unmodified** `p_gate.rego`, and the resulting block/review/pass
counts are compared to the unmodified baseline. The script first
confirms `opa eval` reproduces all 30 published Table 5.6 verdicts
exactly before trusting any ablation delta.

## Result

```
Self-check passed: opa eval reproduces all 30 published Table 5.6 verdicts exactly.

baseline (unmodified)                              BLOCK=10  REVIEW=18  PASS= 2
disable consensus requirement                      BLOCK=11  REVIEW=17  PASS= 2
disable OSV confirmation                           BLOCK=10  REVIEW=18  PASS= 2
disable KEV                                        BLOCK= 7  REVIEW=21  PASS= 2
disable EPSS threshold (block_epss_threshold=0)    BLOCK=16  REVIEW=12  PASS= 2
disable layer routing (app floor = os floor)       BLOCK=10  REVIEW=18  PASS= 2
```

Per-image movement:

- **Consensus**: 1 image moves (`v03_text4shell`, REVIEW→BLOCK).
- **OSV confirmation**: 0 images move.
- **KEV**: 3 images move BLOCK→REVIEW (`v01_log4shell`, `v04_spring4shell`,
  `webgoat_webgoat`) — every image that currently blocks via the KEV path.
- **EPSS threshold**: 6 images move REVIEW→BLOCK (`python_3.8`,
  `bkimminich_juice-shop`, `golang_1.16-alpine`, `dotnet_runtime_3.1`,
  `rust_1.56-slim`, `golang_1.23-alpine`) — the single biggest lever of
  the five.
- **Layer routing**: 0 images move.

## Conclusion

Two of six signals do essentially nothing at this dataset's scale:
**OSV confirmation** never independently blocks or unblocks an image (0
moves), and **layer routing** likewise moves nothing at the 30-image
aggregate (consistent with the thesis's own §5.5 finding that layer
routing changes the deny set on exactly one image, `web-dvwa`, and only
under the LLM classifier — not the rule classifier this ablation used).
**Consensus** is nearly as quiet (1 move). **KEV** and **EPSS
threshold** are where the gate's actual selectivity lives: KEV is the
entire reason the three single-CVE validation images with known
exploits (log4shell, spring4shell, webgoat) reach BLOCK rather than
REVIEW, and the EPSS threshold alone accounts for 6 of the 18
REVIEW-tier images — remove it and the gate's block rate nearly
doubles (10→16/30).

This is evidence for, not against, the design: OSV/consensus/layer
routing being quiet doesn't mean they're dead weight, it means in this
30-image dataset they never became the deciding factor once KEV and
EPSS already resolved most cases — they exist as corroborating evidence
and as protection against the *next* dataset where they might be
decisive, not as always-active filters on this one. Whether this
distinction (signals that are structurally necessary vs. signals that
happened not to bind on this sample) is worth stating explicitly in
§4.2/§6.4 is a separate, thesis-side decision.
