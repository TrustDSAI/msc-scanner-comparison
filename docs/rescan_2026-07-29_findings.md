# Database-Drift Check: 9 Design Images Re-scanned 2026-07-29

## Question

The thesis's original 9-image design-set scan (databases pinned 2026-03-30)
found operating-system-only images agreeing more closely (Jaccard mean 0.71)
than mixed-ecosystem images (mean 0.41, Mann-Whitney U=16, p=0.095,
one-sided). The 21-image extension scan (databases current as of
2026-06-21) found this reversed and non-significant (OS-only mean 0.36 <
mixed mean 0.39). Does the reversal survive re-scanning the *same 9
images, same pinned digests* against today's (2026-07-29) live databases,
or does it disappear — indicating the original pattern was database drift
between the two scan dates, not a genuine ecosystem effect?

## Method

`scripts/rescan_2026-07.sh` re-ran all 9 design-set images (identical
pinned digests to the original scan) against live Trivy/Grype/OSV-Scanner
databases as of 2026-07-29, 1 run per tool per image, output isolated to
`data/raw_rescan_2026-07-29/` (original baseline in `data/raw/` untouched).
Trivy's local vulnerability DB was confirmed to actually update on this
run (fresh 102.79 MiB download, vs. the pinned 2026-03-30 snapshot used
for the original scan).

`analysis/rescan_compare.py` recomputed per-image CVE-level Jaccard
similarity and the OS-only-vs-mixed Mann-Whitney U test (one-sided,
`alternative="greater"`, matching the thesis's own a priori hypothesis
that OS-only images agree more) for both the original and re-scanned
data. It first confirmed it reproduces all 9 published Table 5.3 Jaccard
values from the untouched baseline exactly, and reproduces the thesis's
stated U=16, p=0.095 on the original data exactly, before trusting the
re-scanned numbers.

## Result

```
Self-check passed: recomputed baseline matches published Table 5.3 exactly.

ORIGINAL (2026-03-31 DB) OS-only vs mixed:
  OS-only mean:  0.708 (n=4)
  Mixed mean:    0.415 (n=5)
  Mann-Whitney U=16.0, p=0.095

RE-SCAN (2026-07-29 DB) OS-only vs mixed:
  OS-only mean:  0.769 (n=4)
  Mixed mean:    0.353 (n=5)
  Mann-Whitney U=17.0, p=0.056

Per-image Jaccard drift (original -> re-scan):
  A  vulnerables_web-dvwa         0.704 -> 0.704  (delta +0.000)
  A  bkimminich_juice-shop        0.952 -> 0.957  (delta +0.005)
  B  nginx_1.19                   0.741 -> 0.741  (delta +0.000)
  B  node_14                      0.240 -> 0.246  (delta +0.006)
  B  python_3.8                   0.144 -> 0.148  (delta +0.004)
  C  alpine_3.19                  0.500 -> 0.667  (delta +0.167)
  C  nginx_1.29.7                 0.885 -> 0.966  (delta +0.081)
  C  node_20                      0.291 -> 0.208  (delta -0.083)
  C  python_3.12                  0.448 -> 0.207  (delta -0.241)

Verdict:
  Group-mean ordering held between original and re-scan.
```

## Conclusion

**Reversal does NOT survive same-digest re-scanning — but not in the way
the hypothesis expected.** On this exact 9-image set, the OS-only >
mixed pattern didn't just hold under a newer database, it strengthened
(p: 0.095 -> 0.056; OS-only mean rose to 0.769, mixed mean fell to
0.353). Two of the four OS-only images (`alpine:3.19`, `nginx:1.29.7`)
gained Jaccard under the new DB; two mixed images (`node:20`,
`python:3.12`) lost Jaccard, one substantially (`python:3.12`:
0.448 -> 0.207).

**This rules out the simplest explanation for the thesis's 9-vs-21
discrepancy.** Database drift between March and July, applied to the
*same* 9 images, does not reverse or even weaken the ecosystem-split
pattern — if anything it sharpens it. So the reversal the thesis observed
when moving from the 9-image design set to the 21-image extension is not
a "the world moved on between scans" artifact. It has to trace to
something about the *additional* 21 images specifically — different
ecosystems (Go, Ruby, Java, .NET, Rust), different maintenance-state
composition, or genuine sampling noise from small per-group counts (n=4
to n=13 per the thesis's own §6.1) — not simply the passage of time.

This is a more specific and more interesting finding than the thesis's
current hedge ("neither difference is significant... database drift
between the March design scans and the June extension scans is among the
candidate explanations, though the small group sizes leave the test
underpowered to separate database drift from sampling noise," §6.1): it
positively rules out one of the two named candidate explanations rather
than leaving both open. Revising §6.1 (and the related §5.1 passage) to
state this is a separate, thesis-side task, not part of this plan.
