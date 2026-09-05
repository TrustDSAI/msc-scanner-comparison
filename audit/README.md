# audit/ — independent recomputation scripts

These do **not** import `analysis/` or `policy/`; they re-derive every metric
from `data/raw/`, `logs/` and `policy/output/` directly, from the definitions
in the dissertation's analysis-method section. Two checks reuse repository
code and say so in their own output.

Run from the repository root.

Script names and the table numbers below follow the draft the audit was written
against. The delivered report inserts a chapter, so Chapter 5 there is Chapter 6
here: Table 5.1 below is Tables 6.1 and 6.2 in the report (it was split), 5.2 is
6.3, 5.3 is 6.4, 5.4 is 6.5, 5.5 is 6.6, and 5.6 through 5.10 are 6.7 through
6.11. Figures shift the same way.

| Script | Checks |
|---|---|
| `lib.py` | shared loaders: native unique-CVE counting, Grype canonical-identifier rule |
| `t51.py` | Table 5.1 |
| `t52.py` | Table 5.2, aliased and raw Jaccard |
| `t53.py` | Table 5.3, CRITICAL divergence over all 30 images |
| `t54.py` | Table 5.4 under a max-severity collapse rule |
| `t54b.py` | Table 5.4 under the last-record-wins rule the thesis actually used |
| `t55c.py` | Table 5.5, cell by cell, at n=30 and n=29 |
| `derived55.py` | 38–128×, ms/MB slopes, Pearson r, OSV-vs-Grype spreads |
| `fix.py` | fix rates on the record basis and on the native basis |
| `cwe.py` | Figure 5.4 Σ values and per-tool splits |
| `pkg.py` | linux-libc-dev attribution, GHSA namespace counts |
| `juice.py` | juice-shop GHSA breakdown, node:14 binutils, runtime-binary findings |
| `t56.py` | Table 5.6 from `policy/output/verdict_matrix.csv` |
| `t57.py` | Table 5.7, verdicts and the 4,656 sum |
| `t58.py` | Table 5.8 baselines and the P1 == Grype set identity |
| `stats.py` | ecosystem split, Mann-Whitney, Cohen's d |
| `rescan.py` | the 2026-07-29 re-scan statistic |
| `digests.py` | Appendix A against `logs/digests.log` and the scanned artifact metadata |
| `oldgate.py` | p_gate verdicts under the pre-2026-06-25 rego bundle (needs `opa`) |

`stats.py` and `rescan.py` need `scipy`. `oldgate.py` needs `opa` and a git
checkout (it materialises `260f04a^` into a temp directory; it does not touch
the working tree).
