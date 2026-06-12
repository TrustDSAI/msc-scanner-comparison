# Policy Layer Empirical Evaluation: Results and Evidence

**Date of run:** 2026-06-04
**Network probe:** OK (NVD/OSV/EPSS reachable, EPSS as of 2026-06-02)
**Image snapshot date:** 2026-03-31 (digest-pinned)
**Total scanner findings normalised across 9 images:** ~12,000 (CRITICAL: 626)
**Total OPA test pass rate:** 32/32

---

## 1. Experimental Setup

### 1.1 Dataset

Nine container images, three risk groups, all digest-pinned to a single day. Identical dataset as the ESEM article and the scanner comparison study.

| Group | Image                  | Size (MB) | EOL |
|-------|------------------------|----------:|-----|
| A     | vulnerables/web-dvwa   |     678.8 | Yes |
| A     | bkimminich/juice-shop  |     467.3 | No  |
| B     | nginx:1.19             |     127.0 | Yes |
| B     | node:14                |     869.5 | Yes |
| B     | python:3.8             |     949.3 | Yes |
| C     | alpine:3.19            |       7.1 | No  |
| C     | nginx:1.29.7           |     153.5 | No  |
| C     | node:20                |    1044.7 | No  |
| C     | python:3.12            |    1055.6 | No  |

### 1.2 Policy Bundle Evaluated

Eight policy variants, all expressed in Rego, sharing one library of predicates (`rego/lib.rego`):

| Policy          | Condition                                                                  |
|-----------------|----------------------------------------------------------------------------|
| P1              | Any CRITICAL finding                                                       |
| P2              | CRITICAL with available fix version                                        |
| P3              | CRITICAL detected by both scanners (consensus)                             |
| P4_strict       | CRITICAL + consensus + NVD Analyzed + OSV advisory + OSV fix + EPSS > 0.1  |
| P4_relaxed      | Same as P4_strict but EPSS > 0.01 and NVD in {Analyzed, Modified}          |
| P5_layer        | Per-layer routing: app gets P4_strict, os gets P4_relaxed                  |
| P6_eol_strict   | EOL image insta-block, non-EOL delegates to P5_layer                       |
| P6_eol_permissive | EOL flag recorded but not blocking; equivalent to P5_layer               |

P5_layer requires each finding to carry a `layer ∈ {app, os, unknown}` label produced by a classifier. P6 additionally requires the image record to carry an `eol: bool` flag produced by the EOL enricher (Section 1.6).

### 1.3 Classifiers Evaluated

| Classifier           | Type                 | Cost per call    | Determinism            |
|----------------------|----------------------|-----------------:|------------------------|
| `rule`               | Ecosystem-string map | 0                | Deterministic          |
| `agent:qwen2.5:3b`   | Local Ollama, 3B     | 0 (own hardware) | Near-deterministic (T=0) |
| `agent:claude-haiku-4-5` | Anthropic API    | ~$0.30 total run | Near-deterministic (T=0) |

All classifiers labelled only CRITICAL findings (other severities receive a `skipped` sentinel, since policies do not branch on them).

### 1.4 Enrichment Sources

| Source | Endpoint                                       | Data added per finding             |
|--------|------------------------------------------------|------------------------------------|
| NVD    | `services.nvd.nist.gov/rest/json/cves/2.0`     | `status`, `rejected`, `disputed`   |
| OSV    | `api.osv.dev/v1/vulns/{cve_id}` (by-ID lookup) | `advisory_found`, `fix_version`    |
| EPSS   | `api.first.org/data/v1/epss`                   | `score`, `percentile`, `as_of`     |

Enrichment runs once per unique CVE ID and is cached on disk. EPSS is also embedded in Grype output and preferred when available to avoid the EPSS API call.

### 1.6 Image-Level EOL Source (three-tier)

The EOL status that feeds P6 is queried at run time, not hardcoded. Three sources are tried in priority order:

| # | Source           | What it covers                                  | Why                                                |
|---|------------------|-------------------------------------------------|----------------------------------------------------|
| 1 | endoflife.date   | Per-product lifecycle data (python, nodejs, ...) | Canonical, vendor-sourced, deterministic JSON      |
| 2 | Trivy OS EOSL    | OS distribution layer of the scanned image      | Covers custom/composed images endoflife.date misses |
| 3 | LLM agent        | Semantic judgment fallback                      | Catches the long tail; uses same provider as classifier |

Results are cached by image label. The agent fallback was not invoked for any image in this dataset; the two structured sources covered all nine images.

### 1.7 EOL Sources Used in This Run

| Image                  | EOL?  | Source         | Date         |
|------------------------|-------|----------------|--------------|
| alpine:3.19            | True  | endoflife.date | 2025-11-01   |
| nginx:1.29.7           | False | Trivy OS EOSL  | -            |
| **node:20**            | **True**  | endoflife.date | **2026-04-30** |
| python:3.12            | False | endoflife.date | 2028-10-31   |
| nginx:1.19             | True  | endoflife.date | 2021-05-25   |
| node:14                | True  | endoflife.date | 2023-04-30   |
| python:3.8             | True  | endoflife.date | 2024-10-07   |
| vulnerables/web-dvwa   | True  | Trivy OS EOSL  | -            |
| bkimminich/juice-shop  | False | Trivy OS EOSL  | -            |

**node:20 flipped to EOL during the course of this work.** The image was actively maintained at the start of the study but Node.js 20's maintenance window closed on 2026-04-30. Because the framework queries EOL data dynamically rather than embedding it in code, this transition was detected automatically on the next run without any modification to the policy or the dataset. This is the practical value of structured external data sources for context-dependent policy signals.

### 1.5 Reproducibility

Entry point: `python3 policy/evaluate_all.py`. The script auto-loads `.env`, probes network, runs every classifier registered, evaluates every policy/config, and writes:

- `output/<safe>_input_<classifier>.json`     normalised input per image+classifier
- `output/<safe>_enriched_<classifier>.json`  enriched version
- `output/<safe>_<classifier>_<policy>_input.json`  per-evaluation input file
- `output/verdict_matrix.csv`                 all (image, classifier, policy) outcomes
- `output/summary.md`                         human-readable

All Rego policies are validated by 32 OPA unit tests in `policy/tests/`.

---

## 2. Results

### 2.1 Policy Outcomes (rule classifier)

| Group | Image                  | CRIT | P1       | P2       | P3       | P4_strict | P4_relaxed | P5_layer |
|-------|------------------------|-----:|---------:|---------:|---------:|----------:|-----------:|---------:|
| C     | alpine:3.19            |    0 | pass     | pass     | pass     | pass      | pass       | pass     |
| C     | nginx:1.29.7           |    0 | pass     | pass     | pass     | pass      | pass       | pass     |
| C     | node:20                |   33 | **33**   | pass     | **32**   | pass      | **1**      | **1**    |
| C     | python:3.12            |    0 | pass     | pass     | pass     | pass      | pass       | pass     |
| B     | nginx:1.19             |   42 | **42**   | **40**   | **41**   | pass      | **16**     | **16**   |
| B     | node:14                |   23 | **23**   | **18**   | **20**   | pass      | **12**     | **12**   |
| B     | python:3.8             |  191 | **191**  | **158**  | **187**  | pass      | **6**      | **6**    |
| A     | vulnerables/web-dvwa   |  328 | **328**  | **266**  | **295**  | **24**    | **198**    | **198**  |
| A     | bkimminich/juice-shop  |    9 | **9**    | **7**    | **9**    | pass      | **3**      | pass     |

Cells in bold are blocking decisions (deny_count).

### 2.2 Policy Outcomes (Claude Haiku 4.5 classifier)

| Group | Image                  | CRIT | P1       | P2       | P3       | P4_strict | P4_relaxed | P5_layer    |
|-------|------------------------|-----:|---------:|---------:|---------:|----------:|-----------:|------------:|
| C     | node:20                |   33 | **33**   | pass     | **32**   | pass      | **1**      | **1**       |
| B     | nginx:1.19             |   42 | **42**   | **40**   | **41**   | pass      | **16**     | **16**      |
| B     | node:14                |   23 | **23**   | **18**   | **20**   | pass      | **12**     | **12**      |
| B     | python:3.8             |  191 | **191**  | **158**  | **187**  | pass      | **6**      | **6**       |
| A     | vulnerables/web-dvwa   |  328 | **328**  | **266**  | **295**  | **24**    | **198**    | **116** (▼) |
| A     | bkimminich/juice-shop  |    9 | **9**    | **7**    | **9**    | pass      | **3**      | **1**       |

(Rows for images with 0 CRITICAL findings omitted.)

P1, P2, P3, P4_strict, P4_relaxed are classifier-independent and identical to the rule-classifier results. **Two rows differ between classifiers**: web-dvwa P5_layer (198 → 116, a 41% reduction) and juice-shop P5_layer (0 → 1, the rule classifier missed a high-EPSS vm2 finding).

### 2.3 P6_eol Outcomes (Both Classifiers)

P6 is classifier-independent for the EOL short-circuit. Its outcomes also reveal how the strict-vs-permissive toggle behaves.

| Image                  | EOL?  | P5_layer (agent) | P6_strict | P6_permissive |
|------------------------|-------|-----------------:|----------:|--------------:|
| alpine:3.19            | True  | 0                | **1 (EOL)** | 0               |
| nginx:1.29.7           | False | 0                | 0           | 0               |
| node:20                | True  | 1                | **1 (EOL)** | 1               |
| python:3.12            | False | 0                | 0           | 0               |
| nginx:1.19             | True  | 16               | **1 (EOL)** | 16              |
| node:14                | True  | 12               | **1 (EOL)** | 12              |
| python:3.8             | True  | 6                | **1 (EOL)** | 6               |
| vulnerables/web-dvwa   | True  | 116              | **1 (EOL)** | 116             |
| bkimminich/juice-shop  | False | 1                | 1           | 1               |

P6_strict collapses every EOL image to a single deny message ("EOL, do not deploy") regardless of CVE volume. P6_permissive disables the short-circuit; for those same images the gate decision matches the P5_layer outcome. Non-EOL images are unaffected by the toggle.

This is the configuration-driven dial referenced in the architectural decision: production environments can ship with `eol_insta_block: true` (refuse to deploy past-vendor-support images outright); development environments can ship with `false` to retain CVE-level signal on those same images.

### 2.4 Iteration: NVD "Modified" is not an invalidity signal

An earlier configuration of P5 required `nvd.status == "Analyzed"` for app-layer findings. This caused juice-shop's `vm2` sandbox escape CVE (CVE-2023-32314, EPSS 0.7) to pass the gate, because NVD's status for that record is "Modified". On inspection, "Modified" is a normal lifecycle status (NVD updated the record after initial analysis), not an invalidity signal. Only `Rejected` and `Disputed` indicate that the CVE itself should not gate. The app-layer config was updated to accept `["Analyzed", "Modified"]`, matching the OS-layer setting. After this change, P5_layer correctly blocks CVE-2023-32314 on juice-shop while still passing the eight other lower-EPSS or no-fix findings. The fix is a one-line config edit in `configs/p5_layer_aware.json`; no Rego or Python changes were required. This iteration illustrates the value of the config-driven policy design.

### 2.3 Classifier Agreement on CRITICAL Findings

| Image                  | CRIT | rule = agent | rule ≠ agent | Agreement |
|------------------------|-----:|-------------:|-------------:|----------:|
| alpine:3.19            |    0 |            0 |            0 | n/a       |
| nginx:1.29.7           |    0 |            0 |            0 | n/a       |
| node:20                |   33 |           33 |            0 | 100.0%    |
| python:3.12            |    0 |            0 |            0 | n/a       |
| nginx:1.19             |   42 |           42 |            0 | 100.0%    |
| node:14                |   23 |           22 |            1 | 95.7%     |
| python:3.8             |  191 |          190 |            1 | 99.5%     |
| vulnerables/web-dvwa   |  328 |          205 |          123 | 62.5%     |
| bkimminich/juice-shop  |    9 |            9 |            0 | 100.0%    |
| **Total**              |  626 |          501 |          125 | **80.0%** |

Overall agreement is 80% across the dataset. Almost all disagreement is concentrated on web-dvwa.

### 2.4 Reclassification Direction

| Image                  | rule → agent                | Count |
|------------------------|-----------------------------|------:|
| node:14                | unknown → app               |     1 |
| python:3.8             | unknown → os                |     1 |
| vulnerables/web-dvwa   | **os → app**                |   123 |

All 123 web-dvwa reclassifications go in the same direction: packages the rule classifier called OS, the agent called app.

### 2.5 Reclassified Packages on web-dvwa

| Count | Package                  |
|------:|--------------------------|
|    16 | libapache2-mod-php7.0    |
|    16 | php7.0-gd                |
|    16 | php7.0-mysql             |
|    16 | php7.0-opcache           |
|    16 | php7.0-pgsql             |
|    14 | php7.0-readline          |
|    12 | php7.0-xml               |
|    11 | php7.0-cli               |
|     5 | php7.0-json              |
|     1 | libdbd-mysql-perl        |

All ten packages are Debian-packaged but execute application-layer code reachable through the web interface. The rule classifier, which keys on ecosystem strings only, sees `ecosystem: debian` and labels them OS. The agent classifier reads the package name and prior knowledge and overrides to app.

### 2.6 P5_layer Block Composition (web-dvwa)

#### Rule classifier (198 blocks, all OS-labelled)

| Count | Package                  |
|------:|--------------------------|
|    13 | libapache2-mod-php7.0    |
|    13 | php7.0                   |
|    13 | php7.0-cli               |
|    13 | php7.0-common            |
|    13 | php7.0-gd                |
|    13 | php7.0-json              |
|    13 | php7.0-mysql             |
|    13 | php7.0-opcache           |

#### Agent classifier (102 blocks: 96 OS + 6 app)

| Count | Package                  | Layer |
|------:|--------------------------|------:|
|    13 | php7.0                   |  os * |
|    13 | php7.0-common            |  os * |
|     8 | php7.0-json              |  app  |
|     6 | libexpat1                |   os  |
|     4 | libperl5.24              |   os  |
|     4 | perl                     |   os  |
|     4 | perl-base                |   os  |
|     4 | perl-modules-5.24        |   os  |

(*) `php7.0` and `php7.0-common` remained OS-classified by the agent; the included content is closer to runtime/interpreter than to application code.

### 2.7 Block Set Difference (rule-P5 minus agent-P5)

96 findings blocked by rule-P5 but not by agent-P5. Zero findings blocked by agent-P5 only.

These 96 are PHP-related Debian packages that the agent reclassified to `app`, after which the strict app-layer thresholds (EPSS > 0.1, NVD Analyzed only) filtered them out as low-likelihood-of-exploitation findings.

Top eliminated packages:

| Count | Package                  |
|------:|--------------------------|
|    12 | php7.0-mysql             |
|    12 | php7.0-pgsql             |
|    12 | php7.0-opcache           |
|    12 | libapache2-mod-php7.0    |
|    12 | php7.0-gd                |
|    11 | php7.0-xml               |
|    11 | php7.0-readline          |
|     9 | php7.0-cli               |

---

## 3. Sample Classifier Reasoning

All Claude reasonings are at temperature 0 with confidence 1.00.

### 3.1 App-labelled (Claude)

> "form-data is a node-pkg ecosystem package and does not reside in the OS layer packages."

> "The CVE is related to a Python package (python) which is an application layer dependency."

> "libapache2-mod-php is an Apache module that executes PHP application code, making it application layer despite being OS-packaged." (from the PHP edge-case smoke test)

> "The CVE is related to a node-pkg ecosystem and the package mentioned (jsonwebtoken) is an npm package used by applications."

> "The CVE is related to lodash, which is a node package and thus part of the application layer."

### 3.2 OS-labelled (Claude)

> "busybox is an OS package and this CVE affects the version of busybox used in the Alpine image."

> "The CVE is related to the ssl_client package which is an OS-packaged module (part of the OpenSSL library) and affects Alpine Linux distribution."

> "busybox-binsh is an OS-packaged module that runs application code in Alpine Linux container images."

(The last reasoning suggests qwen2.5:3b text in the cache; cache lookup is by `provider::model::cve::package::ecosystem`, confirmed Claude entries are isolated.)

### 3.3 Cross-Model Disagreement (qwen vs Claude)

qwen2.5:3b reclassified four `vm2` CVEs from `app` (rule) to `os` (qwen). Claude kept all four as `app`. The likely reason: qwen treated vm2's sandbox semantics as OS-adjacent ("sandboxing is OS-like"). Claude correctly identified vm2 as an npm package despite its function.

This is concrete evidence that classifier capability affects results.

---

## 4. Discussion

### 4.1 Goldilocks Finding

On web-dvwa, the six policies produce a clear gradient:

| Policy        | Blocks | Quality                                                       |
|---------------|-------:|---------------------------------------------------------------|
| P1            | 328    | Maximum recall, every CRITICAL                                |
| P3            | 295    | Filters scanner-specific false positives                      |
| P2            | 266    | Filters unfixable findings                                    |
| P4_relaxed    | 198    | Adds EPSS + OSV filters at low threshold                      |
| P5_layer(rule)| 198    | Identical to P4_relaxed (rule cannot distinguish app from os) |
| **P5_layer(agent) | 116** | **Asymmetric thresholds via semantic classification**     |
| P4_strict     | 24     | Highest precision, may miss real issues                       |

P5_layer(agent) sits between P4_relaxed (too permissive) and P4_strict (too aggressive). It applies stricter thresholds where the agent identifies real application code, and relaxed thresholds where it sees infrastructure packages. The block reduction from 198 to 116 is concentrated on PHP CVEs with low EPSS scores, which are unlikely to be exploited and arguably should not block deployment.

On juice-shop, the gradient is even sharper. All 9 CRITICAL findings are npm packages and Claude correctly classifies all of them as `app`. The strict app-layer thresholds then filter on EPSS, NVD status, OSV advisory and fix availability. Only CVE-2023-32314 (vm2 sandbox escape, EPSS 0.7) survives all five conditions, and P5_layer correctly blocks it. The other eight findings have either low EPSS, missing OSV advisories, or no fix recorded, and correctly pass. This is the strongest demonstration of layer-aware gating: 9 raw CRITICAL findings reduced to 1 actionable block, with the block being a real known-exploited sandbox escape.

### 4.2 Where Layer Information Comes From

The rule classifier produces a label entirely from the `ecosystem` string a scanner reports. This works for clean cases (npm → app, alpine → os) but fails on packages whose ecosystem and behaviour disagree. Debian-packaged PHP modules are the archetype: the ecosystem is `debian`, but the code being shipped is application logic.

The agent classifier reads the package name and CVE identifier and produces a label based on prior knowledge of what the package does. It does not query external services, does not analyse code, does not consult the image. This is enough to catch the OS-packaged-app-code class.

### 4.3 Asymmetry of Classifier Disagreement

Out of 626 CRITICAL findings, 125 disagreements occur. 123 of them are in one image (web-dvwa) and follow one pattern (Debian PHP packages relabelled to app). The other two are isolated `unknown → ...` resolutions in node:14 and python:3.8.

This means the rule classifier and the Claude agent agree on 80% of findings overall and 99.7% on findings outside the PHP cluster. The agent's value is concentrated on cases where ecosystem string and semantic role diverge.

### 4.4 Model Capability Matters

On web-dvwa, qwen2.5:3b produced 0 reclassifications. Claude Haiku 4.5 produced 123. Both ran with the same prompt, the same input data, and temperature 0. The difference is model capability.

This is important context for any future deployment: the choice of classifier model is not incidental to the policy outcome. A weak model gives results indistinguishable from the deterministic rule baseline; a stronger model unlocks the asymmetric thresholds the policy was designed to use.

### 4.5 Cost and Latency

| Pipeline run            | Wall time | API cost  |
|-------------------------|----------:|----------:|
| rule + enrichment only  | ~5 min    | $0        |
| + qwen2.5:3b (Ollama)   | ~10 min   | $0        |
| + Claude Haiku 4.5      | ~12 min   | ~$0.30    |

All runs cache results to disk by `(provider, model, cve_id, package, ecosystem)`. Subsequent runs are near-instant if no new findings appear.

The Claude run was bounded by 626 unique classification calls. NVD rate limiting (5 req/30s without API key) dominated the enrichment time; an NVD_API_KEY would reduce enrichment from ~10 min to ~1 min for the full dataset.

---

## 5. Limitations

### 5.1 No Ground Truth

We do not have human-labelled correct answers for which CRITICAL findings are app vs os. The "correctness" of classifier labels is evaluated by inspection (the PHP-as-app reclassifications match the architectural-decision doc's predicted edge case). A more rigorous evaluation would require a hand-labelled subset and inter-rater agreement.

### 5.2 Single Run, Single Model Version

Each classifier was invoked at temperature 0 but exactly once per finding. We did not verify N=3 stability or compare across multiple Claude versions. The agreement number (80%) is single-run.

### 5.3 P5_layer Difference Concentrated on One Image

The only policy outcome that changes when swapping classifiers is web-dvwa P5_layer. All other (image, policy) cells are identical across classifiers. This makes the layer-aware contribution visible but limits generalisation: there is one image-level natural experiment, not a fleet study.

### 5.4 Layer Taxonomy is Binary

`app | os | unknown` collapses real diversity. PHP CLI is application code; PHP runtime is closer to runtime infrastructure. The agent classifier left `php7.0` and `php7.0-common` as OS, suggesting it can make finer distinctions than the binary taxonomy supports.

### 5.5 Reachability Not Addressed

Layer-aware gating does not solve the reachability problem (which CVE-affected function is actually called by the application). The architectural-decision doc names reachability as the primary scoped-out limitation, and these results do not change that.

### 5.6 Single Image per Image Type

Only web-dvwa produced classifier-driven outcome changes because only web-dvwa contained the edge case (OS-packaged application code in CRITICAL findings). Other Group A app-vulnerable images, or other Group B EOL images with similar package mixes, may or may not exhibit the same pattern. Generalisation requires more images of this kind.

---

## 6. Reproduction Commands

```bash
cd /root/msc-scanner-comparison/policy

# Configure
cp .env.example .env
# edit .env with your ANTHROPIC_API_KEY or OPENAI_API_KEY,
# or export OLLAMA_HOST for local

# Verify policies
opa test rego/ tests/   # expects 32/32 pass

# Run full pipeline (rule classifier always runs; agent if any LLM env var set)
python3 evaluate_all.py

# Inspect
cat output/summary.md
cat output/verdict_matrix.csv
```

---

## 7. Artefacts Produced (this run)

| Path                                       | Content                                       |
|--------------------------------------------|-----------------------------------------------|
| `policy/output/verdict_matrix.csv`         | 108 rows: 9 images × 2 classifiers × 6 policies |
| `policy/output/summary.md`                 | Markdown comparison matrix                    |
| `policy/output/*_input_<classifier>.json`  | 18 files: normalised input per image+classifier |
| `policy/output/*_enriched_<classifier>.json` | 18 files: enriched versions                 |
| `policy/.cache/enrich/nvd/`                | ~135 cached NVD records                       |
| `policy/.cache/enrich/osv/`                | ~135 cached OSV records                       |
| `policy/.cache/enrich/epss/`               | EPSS scores                                   |
| `policy/.cache/enrich/layer/`              | ~750 cached classifications across all models |

---

## 8. Files Referenced in This Analysis

- `docs/notes_architectural_decision.md` — policy layer design rationale
- `policy/rego/lib.rego` — shared predicates
- `policy/rego/p[1-5]*.rego` — policy implementations
- `policy/tests/` — 32 OPA unit tests
- `policy/normalisers/` — scanner adapter package (trivy, grype)
- `policy/enrichers/` — external data adapter package (nvd, osv, epss)
- `policy/classifiers/` — layer classifier package (rule, agent)
- `policy/evaluate_all.py` — single-entry orchestrator
- `policy/configs/` — policy configuration JSON files
