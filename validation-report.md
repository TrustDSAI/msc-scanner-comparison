# Validation report — dissertation PDF against `~/msc-scanner-comparison`

Audit date: 2026-08-16. Re-checked against the delivered report 2026-09-05.
Document originally under test: `/root/final_delivery.pdf`, 128 PDF pages,
printed pages i–xx then 1–108.
**Page references below are printed page numbers of that document**
(PDF page = printed page + 20) — see the mapping in the next section before
looking anything up in the delivered report.

---

## ⚠️ This report audits a superseded document

**Audited:** `/root/final_delivery.pdf` — 128 pages, created 2026-08-11,
sha256 `54413b03…`

**Delivered:** `_MSI__2025_2026__Simao_Sousa___Final_Report.pdf` (in this repo)
— **130 pages, created 2026-09-03**, sha256 `b4950841…`

These are different documents. A chapter was inserted, so **every page number
and every float reference in the sections below is stale.** The delivered
version also acts on much of this report: six findings are fixed in it.

### Float mapping, audited -> delivered

| audited | delivered | |
|---|---|---|
| Table 4.4 | Table 5.1 | |
| Figures 4.2, 4.3, 4.4 | Figures 5.1, 5.2, 5.3 | |
| Figure 5.1 | Figure 6.1 | |
| Table 5.1 | **Tables 6.1 + 6.2** | split in two |
| Table 5.2 | Table 6.3 | |
| Figures 5.2, 5.3 | Figures 6.2, 6.3 | |
| Table 5.3 | Table 6.4 | |
| Table 5.4 | Table 6.5 | |
| Figures 5.4-5.7 | Figures 6.4-6.7 | |
| Table 5.5 | Table 6.6 | |
| Table 5.6 | Table 6.7 | |
| Figure 5.8 | Figure 6.8 | |
| Tables 5.7-5.10 | Tables 6.8-6.11 | |
| Figures 5.9, 5.10 | Figures 6.9, 6.10 | |
| Table 5.11 | *removed* | |
| Figure 7.1 | Figure 8.1 | |
| — | **Tables 7.1, 7.2** | new in the Discussion chapter |

Chapters: old 5 (Results) -> new 6; old 4 split into 4 and 5; old 6 -> 7;
old 7 -> 8.

### Finding status against the delivered version

| | finding | status in the 2026-09-03 report |
|---|---|---|
| D1 | Table 3.2 "900 scans" vs 810 | **fixed** — reads "30 (30 on …)", and 810 now appears |
| D6 | "detected by Grype alone" | **fixed** — sentence gone |
| D7 | Table 5.10 post-hoc "Spec." | **fixed** — v06/v07 now carry `block†` |
| D8 | "the other seven" | **fixed** — "the other eight" |
| D9 | 11 + 8 of 20 CWE types | **fixed** — "11 … and Grype on 8, with one tie" |
| D10 | "148× larger" | **fixed** — claim removed |
| D11 | "No image … contains Java packages" | **fixed** — claim removed |
| D14 | unreferenced floats | **partly** — Table 3.1 now referenced; Figure 5.2 (the reviewer-advisor, old 4.3) still is not |
| D2 | Figure 6.6 vs Table 6.6 on Grype/alpine | **open** — figure still plots n=29 (~4.4 s), table still tabulates n=30 (6,915 ± 13,911 ms) |
| D3 | Table 6.6 Trivy/alpine 182 ± 25 under an n=30 caption | **open** |
| D5 | Figure 6.5 fix rates use a per-record unit; §4.4 defines "finding" as unique-CVE | **open** |
| D12 | Table 6.5 declares no unit | **open** |
| D13 | Figure 6.6 caption promises annotations the figure lacks | **open** |
| D16 | all-30 Mann-Whitney tail unstated | **open** |
| D17 | "difference of 0.30" from rounded means | **open** |
| D18 | 90 ms/MB holds only at n=29 | **open**, and now self-consistent with Figure 6.7 |
| D4, D15 | run date, severity tie-break | not re-checked |

### New in the delivered version

**N1 (minor) — Table 6.6 groups thousands with `.`, the prose with `,`.**
The table reads `44.004`, `93.746`, `13.911`; the prose on the facing page
writes the same quantities as "98,954 ms" and "16,793 ms". The 2026-08-11
version used commas throughout, so something changed in the table's number
formatting — probably a locale or `siunitx` setting. The `MB` column and
`885` are unaffected because they are not grouped.

Nothing is misread in practice: the values sit beside two- and three-digit
SDs and a figure axis in seconds, and `.` for thousands is the Portuguese
convention anyway. It is a consistency nit within one document, not an
error.

**N2 (minor) — Tables 6.1 and 6.2 are redundant.** Splitting the old Table
5.1 left 6.2 carrying every column of 6.1 except OSV-Scanner. Both reproduce
exactly against the raw data (verified), but a reader meets the same nine
Total pairs twice on one page.

### What was re-verified against the delivered PDF

Tables 6.1 and 6.2 (all 63 values), the finding statuses above, the float
inventory, and the Table 6.6 separator regression. **Everything else below
was verified against the 2026-08-11 document only.** The recomputations in
§4 are against the data and remain valid regardless of which PDF is on the
desk; what needs re-reading is where each number sits in the new document.

---

Recomputation scripts are in [`audit/`](audit/) with a [`audit/README.md`](audit/README.md)
index. They were written from the definitions in Section 4.1.5 and do not import
`analysis/` or `policy/`, except where explicitly stated against a claim.

---

## 1. Summary

| | Count |
|---|---|
| Individual table cells, figure values and prose claims recomputed | **≈628** |
| Numerically reproduced from raw data | **≈624** |
| Values that did not reproduce | **4** (one Table 5.5 cell, two Table 5.10 "Spec." cells, one Figure 5.6 bar) |
| Discrepancies raised (numeric, labelling, provenance and internal-contradiction) | **17** (2 critical, 5 major, 10 minor) |
| Claims that could not be checked | **8** |

Most of the 17 discrepancies are not failed arithmetic. Ten concern a label, a
caption, a date or a unit attached to a number that is itself correct.

**Verdict on submission readiness: submit after fixing D1–D7.** The empirical
core of the dissertation is sound. Tables 5.1, 5.2, 5.3, 5.6, 5.7, 5.8, 5.9 and
Appendix A reproduce cell for cell from the raw scanner output with no
exceptions — that is 347 individually recomputed values with zero
disagreement. Every statistic in Section 5.1.2 and Section 6.2 (Mann-Whitney
U and p on four samples, Cohen's d, the power calculation, both Pearson
correlations) reproduces to the reported precision. All 30 image digests
resolve. The 103 OPA unit tests pass.

The problems are concentrated in provenance and labelling, not in the
measurements: two places where the document contradicts itself (D1, D2), one
table cell computed over n=29 under an n=30 caption (D3), three table captions
that name the wrong run date (D4), a figure using a unit of analysis the
methodology chapter never defines (D5), and one prose statement about the
validation suite that the verdict files contradict (D6). None of these changes
a headline number, but D1, D2 and D6 are the kind of thing an examiner finds by
reading two pages side by side.

### Which data file backs which table

| Table / figure | Backing data | Traced? |
|---|---|---|
| Table 5.1 | `data/raw/{trivy,grype,osv}/*.json` | yes |
| Table 5.2 | same | yes |
| Table 5.3 | same, all 30 images | yes |
| Table 5.4 | same | yes (tie-break rule undocumented, see D15) |
| Table 5.5 | `logs/benchmark.log` (Grype, OSV), `logs/benchmark_trivy.log` (Trivy), `logs/timing.log` (Syft), `data/derived/benchmark_summary.json`, `data/derived/tables/D2_performance_30run.csv` | yes, but the row for `alpine:3.19` mixes two sources — see D2/D3 |
| Figure 5.4 (CWE) | `data/raw/*` `CweIDs` / `vulnerability.cwes` | yes |
| Figure 5.5 (fix rates) | hard-coded `RAW_TRIVY_FIX` / `RAW_GRYPE_FIX` in `analysis/export_figs_pdf.py:102–111`; equals a raw-record recomputation from `data/raw/` | yes, but the unit is undeclared — see D5 |
| Figure 5.6, 5.7 | `data/derived/benchmark_summary.json` via `analysis/export_figs_pdf.py` | yes |
| Table 5.6 | `policy/output/verdict_matrix.csv` | yes |
| Table 5.7 | `policy/output/verdict_matrix.csv` | yes, but not the version dated 2026-06-21 — see D4 |
| Table 5.8 | `data/raw/*` (native CRITICAL) + `verdict_matrix.csv` | yes |
| Table 5.9 | `policy/output/*_enriched_{rule,agent}.json` + `policy/rego/` via `opa eval` | yes (author's `analysis/ablation.py` reused — see note) |
| Table 5.10, Figures 5.9/5.10 | `validation/results/*.json`, `validation/manifest.yml` | yes, plus git history for the pre-run expectations |
| Appendix A | `logs/digests.log` and `Metadata.RepoDigests` in the raw Trivy output | yes |
| Figure 5.1 (severity bands) | hard-coded arrays in `analysis/export_figs_pdf.py` | partly — bar values not machine-readable from the PDF |
| Figure 5.8 (CLI screenshot) | no stored artifact; the 31/742 split it cites is verifiable | partly |
| Figure 7.1 (schedule) | no data file | **no** |
| Table 3.1, Table 3.2 | literature, not data | n/a (but see D1) |

Tables/figures **not traceable to any data file**: Figure 7.1 (project schedule),
Figure 5.8 (terminal screenshot — the underlying split is checkable, the image is
not), Figures 2.1–2.3, 4.1, 4.2, 4.4 (conceptual diagrams).

---

## 2. Discrepancies

### CRITICAL

---

#### D1 — Table 3.2 says "900 scans"; Section 4.1.4 says 810. Both describe the same experiment.

* **Claim:** Table 3.2, "This study … Images (runs each): **30 (30), 900 scans**"
* **Location:** p. 30 (Table 3.2, last row)
* **Contradicted by:** p. 38, §4.1.4 — "Each image was scanned 30 times per tool, yielding **810 total scan executions**"; and p. 35, §4.1.1 — "every one of its **270 scan invocations**" (OSV-Scanner).
* **PDF value:** 30 images × 30 runs = 900 scans
* **Computed value:** **810** timed executions in the 30-run session of `logs/benchmark.log` (9 images × 3 tools × 30). The 21 extension images were scanned **once each**, on 2026-06-21 — they have no repeated-run records anywhere in `logs/`.
* **Command:**
  ```bash
  grep -cE ' run[0-9]+ [0-9]+ms ' logs/benchmark.log        # 892 total
  awk '$1 !~ /^2026-04-04/' logs/benchmark.log | grep -cE ' run[0-9]+ '   # 810
  awk '{print $2}' logs/benchmark.log | sort -u | wc -l     # 9 images, not 30
  ```
* **Assessment:** **§4.1.4 is right, Table 3.2 is wrong.** 270 (OSV) × 3 tools = 810 is internally consistent and matches the log exactly. The Table 3.2 cell conflates "30 images in the dataset" with "30 runs each", which is only true of the nine design images. It also understates the work: counting the separate Trivy re-run (`logs/benchmark_trivy.log`, 270 more executions) the true total is 1,080. Suggested fix: `9 (30) + 21 (1), 810 timed scans`.

---

#### D2 — Figure 5.6 and Table 5.5 disagree on Grype's `alpine:3.19` timing, and the text cites the value the figure does not show.

* **Claim:** p. 63 — "Grype has a high standard deviation on `alpine:3.19` (**13,911 ms**). This is caused by a database initialisation that runs once, on the first run only, and takes 80 s", cross-referenced to Figure 5.6 and Table 5.5.
* **Location:** Table 5.5 p. 65 (row `alpine:3.19`, Grype Mean/SD); Figure 5.6 p. 64; text p. 63.
* **PDF values:** Table 5.5 says Grype `alpine:3.19` = **6,915 ± 13,911 ms**. Figure 5.6 plots the same bar at **≈4.4 s with an error bar of roughly ±1.3 s** (visually 3.0–5.7 s on the log axis).
* **Computed values:** over all 30 runs, mean 6,915 ms, SD 13,911 ms. **Dropping run 1** (the 80,298 ms cold-database run), mean 4,385 ms, SD 1,214 ms.
* **Command:**
  ```bash
  python3 audit/t55c.py                       # both n=30 and n=29 for every cell
  python3 -c "import json,statistics as s; r=[x for x in json.load(open('data/derived/benchmark_summary.json')) if x['safe']=='alpine_3.19'][0]['grype']['runs_ms']; print(round(s.mean(r)),round(s.stdev(r)), round(s.mean(r[1:])),round(s.stdev(r[1:])))"
  # 6915 13911 4385 1214
  ```
* **Root cause:** `analysis/export_figs_pdf.py:124` —
  `runs = b[tool]["runs_ms"][1:] if safe == "alpine_3.19" and tool in ("trivy","grype") else b[tool]["runs_ms"]`.
  The figure path drops the cold run for **both** tools; the table's Grype cell does not. `data/derived/tables/D2_performance_30run.csv` records `4385, 1214` for that cell under `n_runs,30`, while `data/derived/benchmark_summary.json` records `6915, 13911` under `"n": 30`. The repo carries both values, each labelled n=30.
* **Assessment:** **Both cannot be right, and neither artifact is labelled honestly.** The 6,915 ± 13,911 figure is the correct n=30 value and is the one the surrounding argument depends on: the 80 s DB-init story, and the "OSV-Scanner is 64% faster than Grype on `alpine:3.19`" claim on p. 64, which is 63.9% against Grype 6,915 ms but only 43% against 4,385 ms. Fix Figure 5.6 to use n=30, or state in its caption that the first run is excluded for `alpine:3.19` and confine the 13,911 discussion to Table 5.5.

---

### MAJOR

---

#### D3 — Table 5.5, Trivy `alpine:3.19`, is computed over n=29 under a caption that says n=30.

* **Claim:** Table 5.5 caption: "Execution time (mean ± SD, ms, **n = 30**)". Row `alpine:3.19`, Trivy: **182 ± 25**.
* **Location:** p. 65
* **PDF value:** 182 ± 25
* **Computed value:** **189 ± 49** over all 30 runs. 182 ± 25 is the mean and SD over runs 2–30 (**n = 29**), dropping the 416 ms first run.
* **Command:**
  ```bash
  python3 audit/t55c.py | grep alpine
  # alpine:3.19    trivy n30=189±49 n29=182±25 pdf=182±25 -> n=29
  grep alpine_3.19 logs/benchmark_trivy.log | head -1     # run1 = 416ms
  ```
* **Cross-check against the repo's own derived data:** `data/derived/benchmark_summary.json` gives `"trivy": {"n": 30, "mean_ms": 189, "sd_ms": 49}` — it disagrees with the printed table. `data/derived/tables/D2_performance_30run.csv` gives `182, 25` under `n_runs = 30`.
* **Assessment:** **This is the only cell in Table 5.5 that does not reproduce; the other 53 timing cells match exactly at n=30.** Two knock-on effects, both small:
  * "Trivy is **38 to 128×** faster than Grype" (pp. 63, 65, 78, 81, 93) becomes **37 to 128×** at n=30 (6,915 / 189 = 36.6).
  * "node:20 is 148× larger than `alpine:3.19`, but only **5×** slower to scan" (p. 63) becomes 4.6× (877/189) instead of 4.8× (877/182); still "5×" when rounded.
  The cleanest fix is to publish n=29 for the cold-start row in **both** tools with a footnote, which also resolves D2.

---

#### D4 — Tables 5.6, 5.7 and 5.9 are attributed to a "run of 2026-06-21", but the numbers come from a 2026-06-25 re-run under a policy revision committed that day.

* **Claim:** Table 5.6 caption — "(rule classifier, **evaluation run of 2026-06-21**)"; Table 5.7 caption — "(rule classifier, **run of 2026-06-21**)". Table 5.9's baseline row inherits the same run.
* **Location:** pp. 68, 70, 72
* **PDF values (Table 5.7):** 10 block / **18 review** / **2 pass**; Block+Review sum **4,656**; `php:8.3-apache` = **REVIEW, 29**.
* **Values in the artifacts actually committed on 2026-06-21** (`git show 0639bab:policy/output/verdict_matrix.csv`): 10 block / **17 review** / **3 pass**; Block+Review sum **4,343**; `php:8.3-apache` = **PASS, 0**. 17 of the 30 images have a different Block+Review count.
* **Command:**
  ```bash
  git log --format='%ad %h %s' --date=iso -- policy/output/verdict_matrix.csv
  git show 0639bab:policy/output/verdict_matrix.csv | awk -F, '$3=="rule" && $4=="p_gate"'
  python3 audit/oldgate.py     # re-evaluates the same enriched inputs under 260f04a^
  # images differing: 17/30
  # Block+Review total   OLD=4343   NEW=4656 (thesis Table 5.7 reports 4656)
  ```
* **Cause:** commit `260f04a` "Add consensus-without-fix review path to p_gate", **2026-06-25 19:05**, added `enable_consensus_review` (default true). `policy/output/verdict_matrix.csv` and every `*_enriched_rule.json` in the repo are timestamped **2026-06-25 17:51–17:52**.
* **Assessment:** **The printed numbers are correct for the policy the dissertation describes; the date is wrong.** Figure 4.2 (p. 43) already shows the consensus review path, so the design description matches the current bundle, and my independent re-evaluation of the current `policy/rego/` against the stored enriched inputs reproduces all 30 verdicts and the 4,656 total exactly. The fix is to the captions: **2026-06-25** (enrichment snapshot 2026-06-20/21). Table 5.6's P1–P5 columns are unaffected — they are identical in both runs — so only its date needs correcting. Leaving "2026-06-21" in place means a reader who checks out the 2026-06-21 commit gets a different table and, on `php:8.3-apache`, a different verdict.

---

#### D5 — Figure 5.5 and the RQ2 fix-rate prose use a third unit of analysis that Section 4.1.5 does not define and no caption declares.

* **Claim:** p. 61 — "On `node:14`, Trivy reports **77.3%** of findings as fixable, while Grype reports **34.1%**"; Figure 5.5 caption (p. 63) — "Percentage of **findings** with an available fix per image".
* **Location:** pp. 61, 63; repeated pp. 62, 66, 78, 81, 85.
* **Definition in force:** §4.1.5, p. 38 — "A 'finding' here is a unique CVE identifier reported for an image by a given tool: if the same CVE is reported against more than one package in the same image … it is counted once, not once per affected package."
* **PDF values vs both units:**

  | image | PDF (Trivy/Grype) | per-record | native (§4.1.5) |
  |---|---|---|---|
  | web-dvwa | 87.6 / 64.9 | 87.6 / 64.9 | 85.2 / 61.2 |
  | juice-shop | 84.7 / 83.9 | 84.7 / 83.9 | 81.9 / 81.0 |
  | nginx:1.19 | 79.5 / 58.2 | 79.5 / 58.2 | 80.3 / 59.8 |
  | **node:14** | **77.3 / 34.1** | **77.3 / 34.1** | **82.9 / 31.8** |
  | python:3.8 | (60 / 41 in Fig 5.5) | 59.6 / 40.7 | 69.3 / 40.0 |
  | node:20 | (1 / 1) | 0.6 / 0.9 | 1.2 / 4.2 |
  | python:3.12 | (14 / 18) | 13.6 / 17.6 | 3.3 / 11.3 |

* **Command:** `python3 audit/fix.py`
* **Assessment:** **The printed numbers are internally correct for the per-(CVE,package)-record unit — every value in Figure 5.5 matches it to the decimal — but that unit is neither the native unit of Table 5.1 nor the merged unit of Table 5.7.** It is the per-tool multiplicity-preserving count. The dissertation's own rule ("every table reporting either one states which unit it uses") is therefore broken here, and the gap is material: `python:3.12` moves from 14%/18% to 3.3%/11.3% and `node:14` Trivy from 77.3% to 82.9%. The repo confirms the unit — `analysis/export_figs_pdf.py:102–111` hard-codes the values under the name `RAW_*_FIX`, and `analysis/analysis.py`'s own Table 1 reports the *native* percentages (85.2, 61.0, 82.5 …), which are the ones **not** used. Add one sentence to §4.1.5 and to the Figure 5.5 caption naming the unit; the numbers do not need to change.

---

#### D6 — "each is detected by Grype alone on these minimal images" is contradicted by the verdict files: both scanners detect all three CVEs.

* **Claim:** p. 74, §5.5.6 — "`v01-log4shell` (CVE-2021-44228), `v04-spring4shell` (CVE-2022-22965) and `v03-text4shell` (CVE-2022-42889) all carry EPSS scores between 0.942 and 0.945 in this run, and **each is detected by Grype alone on these minimal images**, so none has cross-scanner consensus and none qualifies for the corroborated-CRITICAL block path."
* **Location:** p. 74
* **Computed:** every one of the three CVEs appears **twice** in the corresponding `validation/results/*.json`, once with `detected_by: ["grype"]` and once with `detected_by: ["trivy"]`. Consensus fails not because Trivy misses them, but because the two tools use different package keys, so the `(CVE, package)` merge never unifies them:

  | image | CVE | Grype package key | Trivy package key |
  |---|---|---|---|
  | v01 | CVE-2021-44228 | `log4j-core` | `org.apache.logging.log4j:log4j-core` |
  | v03 | CVE-2022-42889 | `commons-text` | `org.apache.commons:commons-text` |
  | v04 | CVE-2022-22965 | `spring-beans`, `spring-webmvc` | `org.springframework:spring-beans`, `org.springframework:spring-webmvc` |

* **Command:**
  ```bash
  python3 -c "
  import json
  for v,c in [('v01-log4shell','CVE-2021-44228'),('v03-text4shell','CVE-2022-42889'),('v04-spring4shell','CVE-2022-22965')]:
      d=json.load(open(f'validation/results/{v}.json'))
      for t in ('block','review'):
          for f in d.get(t) or []:
              if f.get('cve_id')==c: print(v,t,f['package'],f['detected_by'],f['epss_score'],f['in_kev'])"
  ```
* **Assessment:** **The conclusion survives — none of the three has consensus, EPSS is 0.94251–0.94439, and only v01/v04 are in KEV, so the controlled comparison stands — but the stated reason is wrong.** As written it credits Grype with detections Trivy also made, in a passage the dissertation calls "the clearest evidence for the design decision argued in §4.2.4". Replace with: "each is reported by both scanners, but under different package identifiers (Maven coordinate versus bare artifact name), so the `(CVE, package)` merge does not register consensus". See also O2 — this is a systematic property of Java findings, not an accident of these three images.

---

#### D7 — Table 5.10's "Spec." column shows post-hoc revised expectations for `v06` and `v07` under a caption that says "specified before the run".

* **Claim:** Table 5.10 caption (p. 74) — "the eleven validation images, the condition each isolates, **the tier specified before the run**, and the tier reached". Rows: `v06-crit-low-epss` Spec. **block**, Path **KEV + fix**; `v07-high-only` Spec. **block**, Path **KEV + fix**.
* **Location:** p. 74
* **Computed:** the manifest as committed at `f70bccf`, **2026-06-15 06:57**, ten minutes before the first result file was written (`validation/results/v01-log4shell.json`, 07:07), specifies:
  * `v06-crit-low-epss`: `expected_tier: review`, `gate_path: review_crit`
  * `v07-high-only`: `expected_tier: review`, `gate_path: review_high`
* **Command:**
  ```bash
  git show f70bccf:validation/manifest.yml | grep -E '^  - id:|expected_tier:|gate_path:'
  ls --time-style=full-iso -l validation/results/v01-log4shell.json
  ```
* **Assessment:** **The prose is honest about this — "two of the ten expectations were revised after the first run … The agreement should therefore be read as eight images of eleven, not ten of eleven" (p. 76) — but the table is not.** A reader who reads Table 5.10 alone sees 10/11 agreement with pre-registered expectations, when the pre-registered figure is 8/11. Mark the two revised rows (e.g. `block†`, footnote "expectation revised after the first run; originally `review`"), or add a "Spec. (as first recorded)" column. This is the single change with the largest effect on how the validation result reads.

---

### MINOR

---

#### D8 — "the other seven are exercised only here" should be eight.
* **Location:** p. 74, §5.5.6.
* Eleven validation images minus the three also in the 30-image dataset (`v01`, `v03`, `v04`) leaves **eight**: `v02`, `v05`, `v06`, `v07`, `v08`, `v09`, `v10`, `v11`. Confirmed against `validation/results/` (11 files) and `logs/digests.log`.
* Plain arithmetic slip. Likely written when the suite had ten images and not updated when `v11` was added on 2026-07-30.

#### D9 — "11 of the 20 types and Grype on the other 8" accounts for 19 of 20; CWE-404 is a tie.
* **Location:** p. 60, §5.1.4.
* **Computed:** Trivy higher on 11, Grype higher on 8, **tied on 1** — CWE-404 (Improper Resource Shutdown) at 54 against 54. All 20 Σ values reproduce exactly, including the four quoted (1080, 738, 732, 682) and both quoted splits (CWE-476 855/225, CWE-416 601/137).
* **Command:** `python3 audit/cwe.py`
* Suggested wording: "on 11 of the 20 types and Grype on 8, with one tie".

#### D10 — "node:20 is 148× larger than `alpine:3.19`" does not reproduce from any size recorded in the repo.
* **Location:** p. 63, §5.3.
* **Computed:** 1044.7 / 7.1 = **147×** (the sizes hard-coded in `analysis/analysis.py:47–52` and `analysis/parse_benchmark_log.py:26–35`, and printed in Table 4.2). 1044.6 / 7.0 = **149×** (the sizes in `logs/benchmark.log`). Trivy's own `Metadata.Size` gives 146×. None gives 148.
* **Command:** `python3 audit/derived55.py | grep 'size ratio'`
* Immaterial to the argument; use 147× to match Table 4.2.

#### D11 — "No image in the dataset contains Java packages" is false; the operative conclusion still holds.
* **Location:** p. 37, §4.1.3, justifying the unpinned Trivy Java database.
* **Computed:** Syft finds `/usr/share/java/libintl.jar` in **both** nginx images — `nginx:1.19` (`libintl`, version UNKNOWN) and `nginx:1.29.7` (`libintl` 0.23.1). `logs/environment.txt` itself flags this: "may have been refreshed during scan of `nginx:1.29.7`".
* **Command:**
  ```bash
  python3 -c "
  import json
  for s in ['nginx_1.19','nginx_1.29.7']:
      d=json.load(open(f'data/sbom/{s}_syft.json'))
      print(s,[(a['name'],a['version']) for a in d['artifacts'] if a['type']=='java-archive'])"
  ```
* **Assessment:** the conclusion is right for the right reason — Trivy reports **no** `lang-pkgs` Java findings on any of the nine design images, so no reported finding depends on that database. Reword to "no Java package in the dataset produced a finding, so no reported finding depends on that database".

#### D12 — Table 5.4 declares no unit of analysis.
* **Location:** p. 61.
* Tables 5.1, 5.3, 5.6, 5.7 and 5.8 all state their unit; Table 5.4 ("Severity agreement on CVEs found by both Trivy and Grype") does not. It is **native** — my recomputation on native unique-CVE sets reproduces the Shared-CVEs column exactly on all nine images. The dissertation's own rule at §4.1.5 requires the declaration. One-word fix.

#### D13 — Figure 5.6's caption promises annotations the figure does not have.
* **Location:** p. 64 — "The Trivy mean values are annotated."
* The rendered figure carries no value labels (verified by rasterising PDF page 84 and by `pdftotext` on `figures/fig1_performance.pdf`, which extracts the axis and group labels but no `…ms` strings). `analysis/export_figs_pdf.py:130–132` does write them, so the embedded figure predates that code. Either regenerate the figure or drop the sentence.

#### D14 — Figure 4.3 and Table 3.1 are never referenced from the body text.
* **Locations:** Figure 4.3 p. 49 (reviewer-advisor output); Table 3.1 p. 25 (primary studies mapped to SLR research questions).
* Every other float is referenced at least once, and no `\ref` is unresolved (zero occurrences of `??` in the whole document).
* **Command:** the float/reference census is in §5 below.

#### D15 — Table 5.4 depends on an undocumented tie-break for CVEs carrying two severities within one tool.
* **Location:** p. 61, rows `python:3.8` and `python:3.12`.
* Three CVEs are rated differently against different packages by Grype in the same image: CVE-2025-4516 and CVE-2025-11468 on `python:3.8`, CVE-2025-11468 on `python:3.12` — each `MEDIUM` on one package and `NEGLIGIBLE` on another, against Trivy's `MEDIUM`.
* Collapsing with **last record wins** (what `analysis/analysis.py:477` does, by dict overwrite) reproduces the table exactly: 206/26 and 172/13, agreement 56.2% and 34.4%, total **647 of 743**. Collapsing with **worst severity wins** gives 204/26 and 171/13, agreement 56.6% and 34.8%, total **644 of 740**.
* **Command:** `python3 audit/t54b.py` (last-wins, matches the PDF) and `python3 audit/t54.py` (max-severity).
* **Assessment:** not an error — three cells out of 36, and the qualitative claim is untouched — but "last record encountered in the JSON" is an arbitrary rule that §4.1.5 does not state. Add a sentence, or switch to max-severity for consistency with the merged-count escalation rule the gate uses.

#### D16 — The all-30 Mann-Whitney test does not state its tail.
* **Location:** p. 57, §5.1.2 and p. 80, §6.2 — "across all 30 images the two groups cannot be distinguished statistically (U = 116, p = 0.171)".
* **Computed:** U = 116, **one-tailed** p = 0.1709; two-sided p = 0.3419. The two preceding tests in the same sentence are explicitly labelled one-tailed, so the reading is recoverable, but the value should be labelled where the others are.
* **Command:** `python3 audit/stats.py`

#### D17 — "a difference of 0.30" is the difference of the rounded means, not the rounded difference.
* **Location:** pp. 57, 80.
* **Computed:** exact means 0.7073 and 0.4149, difference **0.2924** → 0.29. The printed 0.71 − 0.41 = 0.30. The held-out figure (0.3953 − 0.3718 = 0.0235 → 0.02) is unaffected.
* Cosmetic; flag only because the gap is quoted as a headline ("the gap narrows from 0.30 to 0.02") in two chapters.

---

## 3. Unverifiable

A claim listed here was **not** checked. It is not a claim that passed.

| # | Claim | Location | What is missing |
|---|---|---|---|
| U1 | "aggregate Jaccard (0.694)" attributed to Churakova et al. (2026); "0.59–0.80" attributed to Kaur et al. (2021) | Table 3.2, p. 30; p. 85 | External publications, not in the replication package. Not checked. |
| U2 | KEV membership of CVE-2021-44228, CVE-2022-22965, CVE-2023-4863, CVE-2023-44487 "at evaluation time"; absence of CVE-2022-42889 and CVE-2024-6387 | pp. 74–76 | The stored verdict files record `in_kev` true/false consistently with every claim, but the KEV catalog snapshot itself is not archived. Live source; drift is expected and the dissertation says so. |
| U3 | `v11-corroborated-critical`'s expectation was recorded **before** its run | Table 5.10, p. 74 | The manifest entry for v11 was committed 2026-07-30 **19:07**; `validation/results/v11-corroborated-critical.json` was written **19:02**, and its provenance block records `scan_timestamp 2026-07-30T23:01:06Z`. Timestamps cannot establish pre-registration here. The manifest note says the CVE was chosen from the June snapshot, which is consistent, but is not independent evidence. (v01–v10 **were** verified as pre-registered — see D7.) |
| U4 | The 2026-06-20/21 enrichment snapshot (NVD status, OSV advisories, EPSS) is what the gate consumed | Tables 5.6–5.9 | The enriched inputs are stored and internally consistent: every `epss.as_of` value across `policy/output/` is one of 2026-06-20, 2026-06-21, 2026-06-02 or 2026-03-29, the last being the score embedded in the March Grype scans, exactly as §4.2.10 describes. No independent snapshot exists to check them against. Live sources. |
| U5 | The Trivy binary SHA-256 corresponds to an authentic Trivy 0.69.3 release | p. 37 | `logs/environment.txt` records `8266084a71d2e6a2333bc2c69b91c93c26dee9ef39ac2587ace2df54cc9b746b`. The claim that it "is recorded in the replication package" is **verified**. Whether it matches an upstream release checksum requires network access to Aqua's release assets; not checked. |
| U6 | Figure 5.8's screenshot shows the run it says it does | p. 69 | Raster image; no stored terminal capture. The quantities it cites (top 6 of 31 block and 742 review on `web-dvwa`) **are** verified independently — see the Verified table. |
| U7 | Figure 5.1's per-severity-band bar values | p. 54 | Log-scale bars with no data labels; the underlying arrays are hard-coded in `analysis/export_figs_pdf.py` rather than derived at plot time. The totals and CRITICAL/HIGH counts the figure shares with Table 5.1 all reproduce; the MEDIUM/LOW bands were not read off the figure. |
| U8 | Figure 7.1, planned versus actual schedule | p. 90 | No backing data file in the repository. |

---

## 4. Verified

Terse. Every row reproduced exactly unless the Notes column says otherwise.

| Claim / table | Values checked | Script | Result |
|---|---|---|---|
| **Table 5.1** (p. 55) — Trivy Total/CRIT/HIGH, Grype Total/CRIT/HIGH, OSV Adv., 9 images | 63 | `audit/t51.py` | all exact |
| Native unit == unique CVE per image per tool | — | `audit/lib.py` | confirmed (alpine: 6 Trivy records → 2 CVEs; 10 Grype matches → 4) |
| `python:3.8` 3,684 vs 537, "6.9×" | 3 | `audit/t51.py` | exact |
| **Table 5.2** (p. 56) — Trivy, Grype, Trivy-only, Both, Jaccard × 9 | 45 | `audit/t52.py` | all exact |
| Grype column of Table 5.2 == Grype total of Table 5.1 on every image | 9 | `audit/t52.py` | confirmed |
| Raw (unaliased) Jaccard: ≤0.03 on eight images, 0.10→0.95 on juice-shop | 9 + 2 | `audit/t52.py` | exact (max other delta 0.029 on node:14; juice-shop 0.102 → 0.952, delta 0.850) |
| OS group 0.50–0.89, application group 0.10–0.45 on raw identifiers, no overlap | 2 | `audit/t52.py` | confirmed |
| **Table 5.3** (p. 58) — 5 rows × (Trivy, Grype, ∆) | 15 | `audit/t53.py` | all exact; 5 violations of 30, "holds on 25 of 30" |
| ∆ ≤ 3 on eight of nine design images | 1 | `audit/t53.py` | confirmed |
| **Table 5.4** (p. 61) — Shared CVEs, Agreement %, Trivy-higher, Grype-higher × 9 | 36 | `audit/t54b.py` | 36/36 exact under the author's collapse rule; 3 cells differ under max-severity (D15) |
| "647 of the 743 disagreements" | 2 | `audit/t54b.py` | exact; also equals the sum of the printed columns |
| **Table 5.5** (p. 65) — 9 images × (MB, Trivy μ/σ, Grype μ/σ, OSV μ/σ, Syft) | 72 | `audit/t55c.py` | 71 exact at n=30; 1 discrepant (D3) |
| n = 30 present per tool per image in the timing data | 27 | `audit/t55c.py` | confirmed (810 records in the 30-run session; Trivy's 270 in `benchmark_trivy.log`) |
| Syft times = `logs/timing.log` (2026-03-31), run once per image | 9 | grep | exact (node:20 16,793 ms) |
| Sizes = `logs/benchmark.log` 2026-04-04 session | 9 | `audit/t55b`/grep | exact to the rounding in Table 4.2 |
| 38–128× Trivy vs Grype | 9 ratios | `audit/derived55.py` | 38.0–127.8 as printed (37 at n=30, see D3) |
| 1 / 90 / 92 ms/MB | 3 | `audit/derived55.py` | slopes 0.80, 89.15, 92.41 |
| Pearson r = 0.98, p < 0.001, Grype and OSV vs size, n = 9 | 4 | `audit/derived55.py` | r = 0.9801 (t = 13.08) and 0.9828 (t = 14.06), df = 7, p ≈ 4e-6 and 2e-6 |
| OSV within 0.6%–21% of Grype on eight images; 64% faster on alpine | 9 | `audit/derived55.py` | exact (0.6% node:20, 21.0% nginx:1.29.7, −63.9% alpine) |
| Grype alpine first run ≈ 80 s, rest ≈ 4 s | 2 | benchmark_summary | 80,298 ms; mean of runs 2–30 = 4,385 ms |
| Syft 16,793 of Grype's 98,954 ms on node:20 | 2 | `logs/timing.log` | exact |
| **Figure 5.4** (p. 62) — 20 CWE Σ values | 20 | `audit/cwe.py` | all exact (1080, 738, 732, 682, 423, 403, 352, 255, 234, 203, 187, 182, 166, 145, 144, 137, 134, 130, 111, 108) |
| CWE-476 855/225, CWE-416 601/137 | 4 | `audit/cwe.py` | exact |
| **Figure 5.5** (p. 63) — 18 bar values, 8 quoted rates | 26 | `audit/fix.py` | all exact on the per-record unit (see D5) |
| **linux-libc-dev**: 464/469, 793/798, 3146/3154, 343/348; 98.6–99.7% | 9 | `audit/pkg.py` | all exact (98.9, 99.4, 99.7, 98.6) |
| linux-libc-dev absent from Grype's inventory on all four | 4 | `audit/pkg.py` | confirmed |
| Trivy `python:3.8` 3,684 → 538 without linux-libc-dev | 1 | `audit/pkg.py` | exact |
| **GHSA namespace**: 28, 14, 7, 2 | 4 | `audit/pkg.py` | exact |
| juice-shop: 93 findings, 82 GHSA, 78 aliased, 64 unique CVEs, 4 unaliased, all 64 also in Trivy | 6 | `audit/juice.py` | all exact |
| node:14 binutils family, 89 CVEs each, absent from Trivy's package list | 8 | `audit/juice.py` | exact |
| Runtime-binary findings: node:14 21, python:3.12 18 (`nvd:cpe`) | 2 | `audit/juice.py` | exact |
| **Table 5.6** (p. 68) — Merged CRIT, P1, P2, P3, P4s, P4r, P5 × 9 | 63 | `audit/t56.py` | all exact |
| P5 web-dvwa 87 → 62 under the LLM classifier; unchanged at 87 under the rule classifier | 2 | `audit/t57.py` | exact |
| P5 eliminates juice-shop's remaining P4r finding (1 → 0) | 1 | `audit/t56.py` | exact |
| **Table 5.7** (p. 70) — 30 × (Merged CRIT, Verdict, Block+Review) | 90 | `audit/t57.py` | all exact |
| Block+Review sums to 4,656 | 1 | `audit/t57.py` | exact |
| 10 block / 18 review / 2 pass; 3 of 9 on the design set | 4 | `audit/t57.py` | exact (web-dvwa, nginx:1.19, node:14) |
| 1,300 CRITICAL findings across 30 images under a naive threshold | 1 | `audit/t58.py` | exact |
| **Table 5.8** (p. 71) — 26, 26, 24, 21, 10 | 5 | `audit/t58.py` | all exact |
| **P1 and `grype --fail-on critical` block the identical 26 images** (not merely the same count) | 1 | `audit/t58.py` | **confirmed — set equality, symmetric difference empty** |
| The two single-tool gates disagree on exactly `eclipse-temurin:8-jre` and `:21-jre` | 2 | `audit/t58.py` | exact |
| **Table 5.9** (p. 72) — 9 rows × (Block, Review, Pass, Moved) | 36 | `analysis/ablation.py` (author's — see note) | all exact |
| Named moves: v03-text4shell (consensus), juice-shop (NVD), nginx:1.29.7 (fix, pass→review), v01/v04/webgoat (KEV) | 8 | `analysis/ablation.py` | all exact |
| "removing KEV leaves seven of the ten blocking images still blocking" | 1 | `analysis/ablation.py` | exact |
| web-dvwa 31 block / 742 review, identical under all four layer-routing configurations | 8 | `analysis/ablation.py` | exact; 31 + 742 = 773 matches Table 5.7 |
| Rule classifier labels 328/0 os/app on web-dvwa; LLM classifier 206/122 | 4 | grep on `*_enriched_*.json` | exact |
| **Table 5.10** (p. 74) — 11 specified tiers, 11 reached tiers | 22 | `validation/results/*.json` | 20 exact; 2 "Spec." cells are post-hoc (D7) |
| **Figure 5.9** (p. 75) — block/review counts for 11 images | 22 | `validation/results/*.json` | all exact (4/0, 8/191, 0/2, 4/2, 0/4, 2/14, 1/3, 0/30, 0/0, 0/0, 0/16) |
| **Figure 5.10** (p. 76) — 5 KEV+fix blocks, 1+1+1 review paths, 2 passes | 6 | derived from the above | consistent, sums to 11 |
| Suite composition: 8 locally built, 3 pinned public; 6 block / 3 review / 2 pass | 5 | `validation/images/`, manifest | exact |
| v04-spring4shell 4 vs 6 findings between the 06-15 and 06-21 runs | 2 | verdict matrix + validation result | exact (4 block in the later run; 4 block + 2 review in the suite run) |
| EPSS drift on CVE-2022-37434: 0.925 (2026-03-29), 0.159 (June), 0.155 (2026-07-30) | 3 | grep on enriched + v11 result | exact (0.92544 / 0.1593 as_of 2026-06-20 / 0.15502) |
| §6.3 EPSS drift 0.700 → 0.081, 2026-03-29 → 2026-07-28 | 2 | raw Grype `epss` blocks | exact — CVE-2023-32314, 0.70028 (2026-03-29) → 0.08127 (2026-07-28) |
| **Statistics** — training U=16 p=0.095, held-out U=39 p=0.549, all-30 U=116 p=0.171, re-scan U=17 p=0.056 | 8 | `audit/stats.py`, `audit/rescan.py` | all exact (0.0952, 0.5493, 0.1709, 0.0556) |
| Group means 0.71/0.41 and 0.40/0.37; sizes n=4, 5, 5, 16 | 8 | `audit/stats.py` | exact (0.7073, 0.4149, 0.3953, 0.3718) |
| Cohen's d = 1.11 | 1 | `audit/stats.py` | 1.1118 |
| Power: n = 14 two-sided, n = 11 one-sided at α=0.05, 80% | 2 | noncentral-t solve | exact (power 0.807 at both) |
| **Appendix A** — 30 image digests | 30 | `audit/digests.py` | all 30 match `logs/digests.log` **and** the digest recorded inside the scanned artifact |
| **Tool versions** — Trivy 0.69.3, Grype 0.110.0, OSV-Scanner 2.3.5 (scalibr 0.4.5), Syft 1.42.3 | 5 | `logs/tool_versions.txt` | exact |
| Grype build embeds Syft v1.42.3, same as standalone | 1 | `logs/tool_versions.txt` | confirmed |
| Trivy binary SHA-256 present in the replication package | 1 | `logs/environment.txt` | confirmed |
| Trivy DB updated 2026-03-30, Grype DB built 2026-03-30, images scanned 2026-03-31 | 3 | environment + `CreatedAt` | exact |
| Sizes recorded 2026-04-04; benchmark 2026-04-25/26 | 2 | `logs/benchmark*.log` headers | exact |
| Validation suite run 2026-06-15; v11 built and evaluated 2026-07-30 | 2 | file mtimes + git | exact |
| Design-set re-scan 2026-07-29 against a freshly downloaded DB | 2 | rescan log + Grype `db.status.built` | exact (Grype DB v6.1.9 built 2026-07-29, `valid: true`) |
| Policy bundle fingerprint recorded in v11's provenance == current `policy/rego/` | 1 | sha256 over sorted (path, bytes) | **exact match** |
| OPA unit tests | 103 | `opa test rego tests` | **PASS 103/103** |
| Documented reproduction commands run | 4 | `parse_results.py`, `ecosystem_holdout.py`, `baseline_policies.py`, `ablation.py` | all run clean and self-check against the published values |
| Every `\ref` resolves | — | `grep -c '??'` | 0 unresolved |
| Every float referenced from the text | 37 | census | 35 yes, 2 no (D14) |
| Every citation resolves; every bibliography entry cited | 73 / 73 | census | both directions clean |
| Abstract and Resumo agree on every figure | 6 | side-by-side | 0.14–0.95, ∆≤3 on 25/30, 26→10, 9 images × 30 runs, 21-image extension, factor-of-two fix rates — all identical |
| Findings 1–5 boxes vs Table 5.11 | 5 | side-by-side | consistent in every quantity |
| Prose counts vs Table 5.7 (10 + 18 + 2 = 30) | 1 | arithmetic | consistent |

**Note on reused code.** Table 5.9 (the ablation) is the one result I did **not**
recompute independently. `analysis/ablation.py` drives `opa eval` against the
unmodified `policy/rego/` and the stored enriched inputs, and self-checks all 30
baseline verdicts against the published values before reporting any delta — so the
check is stronger than a bare re-run, but it does inherit any bug in the mutators
that define "signal removed". I did write an independent driver (`audit/oldgate.py`)
that reproduces the baseline verdicts and the 4,656 total through the same
`opa eval` path, which confirms the baseline row but not the eight ablated rows.

---

## 5. Observations

Not discrepancies. Things an examiner may ask about.

**O1 — Trivy's timings come from a second, separate benchmark pass, and the dissertation does not say so.**
`logs/benchmark.log`'s 810-run session (2026-04-25/26) contains Trivy means of
2,077 / 2,215 / 2,332 / 4,622 / 8,620 / 739 / — / 6,557 / 4,814 ms — 3 to 10×
larger than Table 5.5. The published Trivy column comes from
`logs/benchmark_trivy.log`, a further 270 runs started at 2026-04-26 00:52,
after the main session ended at 00:25. `analysis/parse_benchmark_log.py`'s
docstring explains why ("used when Trivy is re-run separately to fix DB warmup
issues") and Table 4.3's "2026-04-25/26" covers both, but a reader who opens
`logs/benchmark.log` — the obvious file — will find numbers that look nothing
like the table. One sentence in §4.1.4 would remove the trap.

**O2 — cross-scanner consensus is structurally unreachable for Java packages, which bears on the gate's central claim.**
Trivy keys Java findings by Maven coordinate (`org.springframework:spring-beans`)
and Grype by bare artifact name (`spring-beans`), so the gate's `(CVE, package)`
merge never unifies them. On `webgoat/webgoat-8.0`, all 168 Maven-keyed Trivy
findings are single-tool; the same pattern produces D6. Since corroboration is the
design's core idea and one of the two block paths requires consensus, "the gate
cannot corroborate Java findings across these two scanners" is a real limitation
of the instrument that §6.6 does not list. It is also a plausible partial
explanation for the PHP/Java exceptions in Table 5.3 worth a sentence.

**O3 — only one output artifact in the repository carries a provenance block.**
`validation/results/v11-corroborated-critical.json` is the only file with
`policy_bundle_fingerprint`, and it matches the current `policy/rego/` byte for
byte. The 30-image verdicts and the v01–v10 validation results carry none, so the
"the bundle in the repo is the one that produced these verdicts" claim rests on
re-execution (which does reproduce them) rather than on a recorded fingerprint.
Given §4.2.10 argues for provenance-with-every-decision, an examiner may notice
that the study's own outputs mostly predate that feature.

**O4 — several derived artifacts in the repo are stale relative to the published tables.**
`policy/output/summary.csv` (2026-06-02) reports a single `p4` column with
web-dvwa at 24, which is neither Table 5.6's P4s (15) nor P4r (87).
`data/derived/tables/D4_policy_evaluation.csv` stops at P3. Neither is cited by
the dissertation, but both sit in the replication package under names that invite
a reader to check the tables against them.

**O5 — `data/raw/osv/` is missing `webgoat_webgoat_osv.json`.**
29 OSV outputs against 30 Trivy and 30 Grype outputs. OSV appears only in
Table 5.1, which covers the nine design images, so nothing published depends on
it — but the appendix says the replication package holds "the complete raw
scanner outputs".

**O6 — `logs/environment.txt` carries a correction dated 2026-07-30 stating that the snapshot was written up on 2026-05-09 and that its OS line named the wrong machine.**
The dissertation quotes the corrected host (RHEL 9.4) at p. 36. The correction is
honest and the quoted value is the corrected one; noting it only because the
environment snapshot is cited as the provenance record for the host configuration
and it is not, in fact, a contemporaneous capture.

**O7 — Table 4.2's sizes differ from the benchmark log in the first decimal.**
Table 4.2 prints 467.3 / 1044.7 / 949.3 / 7.1; `logs/benchmark.log` recorded
467.2 / 1044.6 / 949.2 / 7.0 on 2026-04-04. The values in the table match the
constants hard-coded in `analysis/analysis.py:47–52`. Table 5.5 rounds both to
the same integers, so nothing downstream is affected.

**O8 — the ecosystem classification rule is only documented in the analysis script.**
`analysis/ecosystem_holdout.py`'s docstring gives the rule precisely (Trivy
`Class == "lang-pkgs"`; Grype `artifact.type` not in `{deb, rpm, apk, ""}`) and
asserts that it reproduces the published training statistics before reporting the
held-out result — good practice. §5.1.2 states it only as "neither scanner reports
a finding against a language-ecosystem package", which is enough to reimplement
(I did, independently, and got the same 4/5 and 5/16 splits) but not enough to
make the `nvd:cpe`-typed runtime-binary findings unambiguous. Worth a footnote.

**O9 — `web-dvwa` counts as operating-system-only despite carrying php-pear packages.**
Syft finds 6 `php-pear` artifacts in the image. The classification is still correct
under the stated rule — neither scanner reports a *finding* against them — and the
dissertation says as much ("whose PHP findings are all packaged by the operating
system", p. 55). Flagging only because it is the one image where "OS-only" is a
property of the findings rather than of the inventory, and it is also the image
that carries the group's mean.
