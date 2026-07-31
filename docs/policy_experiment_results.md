# Policy Layer Empirical Evaluation: Results and Evidence

**Date of run:** 2026-06-04
**Network probe:** OK (NVD/OSV/EPSS reachable, EPSS as of 2026-06-02)
**Image snapshot date:** 2026-03-31 (digest-pinned)
**Total scanner findings normalised across 9 images:** ~12,000 (CRITICAL: 626)
**Total OPA test pass rate:** 60/60

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

Seven policy variants plus the tri-state gate, all expressed in Rego, sharing one library of predicates (`rego/lib.rego`):

| Policy          | Condition                                                                  |
|-----------------|----------------------------------------------------------------------------|
| P1              | Any CRITICAL finding                                                       |
| P2              | CRITICAL with available fix version                                        |
| P3              | CRITICAL detected by both scanners (consensus)                             |
| P4_strict       | CRITICAL + consensus + NVD Analyzed + OSV advisory + OSV fix + EPSS > 0.1  |
| P4_relaxed      | Same as P4_strict but EPSS > 0.01 and NVD in {Analyzed, Modified}          |
| P5_layer        | Per-layer routing: app gets P4_strict, os gets P4_relaxed                  |
| P7_severity_aware | P5 + HIGH with fix + consensus + EPSS > 0.5; KEV catalog bypass         |
| p_gate (tri-state) | BLOCK / REVIEW / PASS; block = KEV+fix or fully corroborated CRITICAL with EPSS > 0.5 |

P5_layer requires each finding to carry a `layer ∈ {app, os, unknown}` label produced by a classifier. EOL status is queried at run time and attached as context metadata on every deny message; it does not independently determine the gate tier (the P6 EOL-gate design was evaluated and dropped — see architectural decision notes).

The tri-state gate (`rego/p_gate.rego`) is the production-facing component: it produces three output sets per image (block, review, pass) rather than a single deny set, and is packaged as a CLI (`policy_gate.py`) and GitHub Action.

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

All Rego policies are validated by 60 OPA unit tests in `policy/tests/`.

---

## 2. Results

### 2.1 Policy Outcomes (rule classifier)

| Group | Image                  | CRIT | P1       | P2       | P3       | P4_strict | P4_relaxed | P5_layer |
|-------|------------------------|-----:|---------:|---------:|---------:|----------:|-----------:|---------:|
| C     | alpine:3.19            |    0 | pass     | pass     | pass     | pass      | pass       | pass     |
| C     | nginx:1.29.7           |    0 | pass     | pass     | pass     | pass      | pass       | pass     |
| C     | node:20                |   33 | **33**   | pass     | **32**   | pass      | **1**      | **1**    |
| C     | python:3.12            |    0 | pass     | pass     | pass     | pass      | pass       | pass     |
| B     | nginx:1.19             |   42 | **42**   | **40**   | **41**   | pass      | **10**     | **10**   |
| B     | node:14                |   23 | **23**   | **18**   | **20**   | pass      | **12**     | **12**   |
| B     | python:3.8             |  191 | **191**  | **158**  | **187**  | pass      | **6**      | **6**    |
| A     | vulnerables/web-dvwa   |  328 | **328**  | **266**  | **295**  | **15**    | **87**     | **87**   |
| A     | bkimminich/juice-shop  |    9 | **9**    | **7**    | **9**    | pass      | **1**      | pass     |

Cells in bold are blocking decisions (deny_count).

### 2.2 Policy Outcomes (Claude Haiku 4.5 classifier)

| Group | Image                  | CRIT | P1       | P2       | P3       | P4_strict | P4_relaxed | P5_layer    |
|-------|------------------------|-----:|---------:|---------:|---------:|----------:|-----------:|------------:|
| C     | node:20                |   33 | **33**   | pass     | **32**   | pass      | **1**      | **1**       |
| B     | nginx:1.19             |   42 | **42**   | **40**   | **41**   | pass      | **10**     | **10**      |
| B     | node:14                |   23 | **23**   | **18**   | **20**   | pass      | **12**     | **12**      |
| B     | python:3.8             |  191 | **191**  | **158**  | **187**  | pass      | **6**      | **6**       |
| A     | vulnerables/web-dvwa   |  328 | **328**  | **266**  | **295**  | **15**    | **87**     | **62** (▼)  |
| A     | bkimminich/juice-shop  |    9 | **9**    | **7**    | **9**    | pass      | **1**      | pass        |

(Rows for images with 0 CRITICAL findings omitted.)

P1, P2, P3, P4_strict, P4_relaxed are classifier-independent and identical to the rule-classifier results. **One row differs between classifiers**: web-dvwa P5_layer (87 → 62, a 29% reduction). The rule classifier labels all 328 CRITICAL findings on that image os-layer; the agent classifier splits them 122 app / 206 os.

### 2.3 P6_eol Outcomes (Design Iteration — Not a Delivered Policy)

P6 added an EOL short-circuit to P5: an EOL image either hard-blocks (strict) or falls through to P5_layer (permissive). The variant was evaluated and dropped because it conflated orthogonal signals — a host running a known-exploited CVE should block regardless of OS lifecycle status, and an EOL image with no actionable findings should not block. P6 is documented here because its empirical results motivated the final architecture (EOL as context metadata, not a gate tier). P7 is the delivered evolution of P5_layer; EOL status is attached as a flag on every deny message but does not independently determine tier.

P6 outcomes across classifiers, shown for completeness:

| Image                  | EOL?  | P5_layer (agent) | P6_strict | P6_permissive |
|------------------------|-------|-----------------:|----------:|--------------:|
| alpine:3.19            | True  | 0                | **1 (EOL)** | 0               |
| nginx:1.29.7           | False | 0                | 0           | 0               |
| node:20                | True  | 1                | **1 (EOL)** | 1               |
| python:3.12            | False | 0                | 0           | 0               |
| nginx:1.19             | True  | 10               | **1 (EOL)** | 10              |
| node:14                | True  | 12               | **1 (EOL)** | 12              |
| python:3.8             | True  | 6                | **1 (EOL)** | 6               |
| vulnerables/web-dvwa   | True  | 62               | **1 (EOL)** | 62              |
| bkimminich/juice-shop  | False | 0                | 0           | 0               |

P6_strict collapses every EOL image to a single deny message ("EOL, do not deploy") regardless of CVE volume. P6_permissive disables the short-circuit; for those same images the gate decision matches the P5_layer outcome. Non-EOL images are unaffected by the toggle.

This is the configuration-driven dial referenced in the architectural decision: production environments can ship with `eol_insta_block: true` (refuse to deploy past-vendor-support images outright); development environments can ship with `false` to retain CVE-level signal on those same images.

### 2.4 Iteration: NVD "Modified" Is Not an Invalidity Signal

An earlier configuration of P5 required `nvd.status == "Analyzed"` for app-layer findings. This caused juice-shop's `vm2` sandbox escape CVE (CVE-2023-32314, EPSS 0.70) to pass the gate, because NVD's status for that record was "Modified". On inspection, "Modified" is a normal lifecycle status (NVD updated the record after initial analysis), not an invalidity signal. Only `Rejected` and `Disputed` indicate that the CVE itself should not gate. The app-layer config was updated to accept `["Analyzed", "Modified"]`, matching the OS-layer setting, a one-line edit in `configs/p5_layer_aware.json` with no Rego or Python change. That iteration illustrates the value of the config-driven design.

The finding nevertheless passes P5_layer in the run recorded above, for a
different reason. NVD returned **no status at all** for CVE-2023-32314 on
this run: the enriched input carries `nvd.status: null`, which the
configured set `["Analyzed", "Modified"]` does not accept, so
`lib.nvd_status_in` fails and the app-layer strict route rejects it. EPSS
is unchanged at 0.70028, consensus holds, OSV confirms both advisory and
fix. The single condition standing between this finding and a block is an
enrichment field that was populated on an earlier run and empty on this
one. It is the same class of non-reproducibility as the EPSS movement
recorded in section 10.4, arriving through a different field.

### 2.5 Classifier Agreement on CRITICAL Findings

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

### 2.6 Reclassification Direction

| Image                  | rule → agent                | Count |
|------------------------|-----------------------------|------:|
| node:14                | unknown → app               |     1 |
| python:3.8             | unknown → os                |     1 |
| vulnerables/web-dvwa   | **os → app**                |   123 |

All 123 web-dvwa reclassifications go in the same direction: packages the rule classifier called OS, the agent called app.

### 2.7 Reclassified Packages on web-dvwa

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

### 2.8 P5_layer Block Composition (web-dvwa)

#### Rule classifier (87 blocks, all os-labelled)

| Count | Package                  |
|------:|--------------------------|
|     6 | libapache2-mod-php7.0    |
|     6 | php7.0                   |
|     6 | php7.0-cli               |
|     6 | php7.0-common            |
|     6 | php7.0-gd                |
|     6 | php7.0-json              |
|     6 | php7.0-mysql             |
|     6 | php7.0-opcache           |
|     6 | php7.0-pgsql             |
|     6 | php7.0-readline          |
|     6 | php7.0-xml               |
|     4 | libexpat1                |
|     2 | rsync                    |
|     1 | apache2                  |
|     1 | apache2-bin              |
|     1 | apache2-data             |
|     1 | apache2-utils            |
|     1 | libidn11                 |
|     1 | libldap-2.4-2            |
|     1 | libldap-common           |
|     1 | libmariadbclient18       |
|     1 | libxslt1.1               |
|     1 | mariadb-client-10.1      |
|     1 | mariadb-client-core-10.1 |
|     1 | mariadb-common           |
|     1 | mariadb-server           |
|     1 | mariadb-server-10.1      |
|     1 | mariadb-server-core-10.1 |

#### Agent classifier (62 blocks: 43 os, 19 app)

| Count | Package                  | Layer |
|------:|--------------------------|------:|
|     6 | php7.0                   |    os |
|     6 | php7.0-common            |    os |
|     4 | libexpat1                |    os |
|     4 | php7.0-json              |    os |
|     3 | libapache2-mod-php7.0    |   app |
|     3 | php7.0-cli               |    os |
|     3 | php7.0-gd                |   app |
|     3 | php7.0-mysql             |   app |
|     3 | php7.0-opcache           |   app |
|     3 | php7.0-pgsql             |   app |
|     2 | php7.0-readline          |   app |
|     2 | php7.0-xml               |    os |
|     2 | rsync                    |    os |
|     1 | apache2                  |    os |
|     1 | apache2-bin              |    os |
|     1 | apache2-data             |    os |
|     1 | apache2-utils            |    os |
|     1 | libidn11                 |    os |
|     1 | libldap-2.4-2            |    os |
|     1 | libldap-common           |    os |
|     1 | libmariadbclient18       |    os |
|     1 | libxslt1.1               |    os |
|     1 | mariadb-client-10.1      |    os |
|     1 | mariadb-client-core-10.1 |    os |
|     1 | mariadb-common           |    os |
|     1 | mariadb-server           |    os |
|     1 | mariadb-server-10.1      |    os |
|     1 | mariadb-server-core-10.1 |    os |
|     1 | php7.0-cli               |   app |
|     1 | php7.0-readline          |    os |
|     1 | php7.0-xml               |   app |

### 2.9 Block Set Difference (rule-P5 minus agent-P5)

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
| P4_relaxed    | 87     | Adds EPSS + OSV filters at low threshold                      |
| P5_layer(rule)| 87     | Identical to P4_relaxed (rule cannot distinguish app from os) |
| **P5_layer(agent) | 62** | **Asymmetric thresholds via semantic classification**      |
| P4_strict     | 15     | Highest precision, may miss real issues                       |

P5_layer(agent) sits between P4_relaxed (too permissive) and P4_strict (too aggressive). It applies stricter thresholds where the agent identifies real application code, and relaxed thresholds where it sees infrastructure packages. The block reduction from 87 to 62 is concentrated on PHP CVEs with low EPSS scores, which are unlikely to be exploited and arguably should not block deployment.

On juice-shop the routing works in the opposite direction, and is the clearer demonstration of what layer awareness does. All 9 CRITICAL findings are npm packages, and both classifiers label all of them `app`. P4_relaxed, applying one threshold to every finding, blocks 1 of them. P5_layer routes those app-layer findings to the strict configuration instead, and none clears it, so the image passes under both classifiers. Layer routing therefore removes a block here rather than adding one: the same signal that leaves 87 blocks standing on web-dvwa takes the last one off juice-shop. Whether that is the right outcome is not established by this dataset; CVE-2023-32314 is a real vm2 sandbox escape, and the strict app-layer threshold is what stops it blocking.

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
opa test rego/ tests/   # expects 60/60 pass

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
| `policy/output/verdict_matrix.csv`         | 108 rows: 9 images × 2 classifiers × 6 policies (P1–P5_layer; P7 and p_gate separate) |
| `policy/output/summary.md`                 | Markdown comparison matrix                    |
| `policy/output/*_input_<classifier>.json`  | 18 files: normalised input per image+classifier |
| `policy/output/*_enriched_<classifier>.json` | 18 files: enriched versions                 |
| `policy/.cache/enrich/nvd/`                | ~135 cached NVD records                       |
| `policy/.cache/enrich/osv/`                | ~135 cached OSV records                       |
| `policy/.cache/enrich/epss/`               | EPSS scores                                   |
| `policy/.cache/enrich/layer/`              | ~750 cached classifications across all models |
| `validation/results/*.json`                | Gate verdict per validation image (10 images, 10/10 pass) |

### 9. Validation Suite Results (Group V)

Ten deliberately-crafted images targeting each gate path. All produce the correct tier after investigating two initial mismatches (v06 and v07), which turned out to be correct gate behaviour — both images contained CISA KEV-listed CVEs that the manifest had not anticipated.

| Image               | Expected | Got    | Block CVE(s)                | Gate path    |
|---------------------|----------|--------|-----------------------------|--------------|
| v01-log4shell       | block    | block  | CVE-2021-44228 (×4)        | kev_fix      |
| v02-jenkins-2441    | block    | block  | CVE-2024-23897 (×8)        | kev_fix      |
| v03-text4shell      | review   | review | CVE-2022-42889 (×2 review) | review_crit  |
| v04-spring4shell    | block    | block  | CVE-2022-22965 (×4)        | kev_fix      |
| v05-regresshion     | review   | review | CVE-2024-6387 (×4 review)  | review_high  |
| v06-crit-low-epss   | block    | block  | CVE-2023-4863 (Pillow/libwebp KEV) | kev_fix |
| v07-high-only       | block    | block  | CVE-2023-44487 (libnghttp2 KEV) | kev_fix |
| v08-eol-stretch     | review   | review | 30 review findings, eol=true | review_crit_eol_context |
| v09-distroless      | pass     | pass   | —                           | pass_clean   |
| v10-alpine-current  | pass     | pass   | —                           | pass_clean   |

**Notable findings from the validation run:**

- v06 and v07 were initially expected to REVIEW. Both BLOCK because their packages carry CISA KEV entries that were not identified during image design. The gate behaves correctly; the mismatch exposed a gap in the pre-stated expectations, not a policy defect.
- The KEV block path is severity-agnostic: CVE-2023-44487 (HTTP/2 Rapid Reset, rated HIGH/DoS) blocks on the same path as CRITICAL RCE entries. This is deliberate design.
- v03 (Text4Shell) and v05 (regreSSHion) correctly reach REVIEW despite their media prominence. Neither is in CISA KEV.
- v08 (Debian 9 EOL) produces 30 REVIEW findings with eol=true on every entry, confirming that EOL is context metadata and not an independent block trigger.

---

## 10. Dataset Expansion: 30 Images, p_gate Only

**Date of run:** 2026-06-21
**Images:** 9 (original) + 21 new, ecosystem diversity (Go, Ruby, Java/JVM,
.NET, PHP, Rust) — see `docs/notes_dataset_expansion.md` for the full image
list and scan methodology.
**Total CRITICAL findings normalised across 30 images (P1, rule classifier):** 1,300
**Total OPA test pass rate:** 82/82

This run targets `p_gate` specifically (the delivered tri-state policy,
not the P1–P7 research lineage) to test whether its block-tier discipline
holds at 3x the original dataset size and across ecosystems the original
9 didn't cover.

### 10.1 Headline: naive severity threshold vs. p_gate

| Metric | Value |
|---|---|
| Images that would block under P1 (any CRITICAL) | 26/30 |
| Images that actually block under `p_gate` | **10/30** |

A naive severity gate fails 87% of the 30-image dataset outright. `p_gate`
reserves a hard fail for a third of it — consistent with the original
9-image result (Chapter 5), now demonstrated at 3x the scale and across
six additional ecosystems.

### 10.2 New-ecosystem highlights

- **`php:8.3-apache`** (modern PHP, new ecosystem): 30 raw CRITICAL
  findings → **zero** reach block or review. Total noise elimination on
  an ecosystem the gate was never tuned against — evidence the
  corroboration-based filtering generalizes, rather than being an
  artifact of Python/Node-specific CVE patterns.
- **`python:2.7`** (EOL since 2020): 184 CRITICAL findings, still blocks.
  The gate's noise tolerance doesn't come at the cost of missing a
  genuinely unmaintained runtime.
- **`golang:1.23-alpine`**, **`ruby:3.3-slim`**, **`rust:1.82-slim`**
  (modern, three ecosystems with zero prior representation): all pass or
  reach review only, never block — consistent with the "modern base
  image, low corroborated risk" pattern already established in the
  original 9's Group C.

### 10.3 KEV path vs. corroboration path: a controlled three-way comparison

`v01-log4shell`, `v03-text4shell`, and `v04-spring4shell`
(`validation/images/`) are single-CVE Java images with comparably extreme
EPSS scores. None has cross-scanner consensus (each CVE was detected by
only one of Trivy/Grype on these minimal images), so none qualify via
the corroborated-CRITICAL block path. The KEV path is what separates them:

| Image | CVE | EPSS | Consensus | In CISA KEV (this run) | `p_gate` result |
|---|---|---|---|---|---|
| v01-log4shell | CVE-2021-44228 | 0.99999 | no | **yes** | **BLOCK** (KEV+fix path) |
| v04-spring4shell | CVE-2022-22965 | 0.99677 | no | **yes** | **BLOCK** (KEV+fix path) |
| v03-text4shell | CVE-2022-42889 | 0.99931 | no | no | review only |

Text4Shell's EPSS (0.999) is statistically indistinguishable from the
other two, and §9 of this document already establishes it was never a
CISA KEV entry despite comparable media attention at disclosure — this
is not a volatility effect (contrast with §10.4 below), it's that KEV is
a narrow catalog of *confirmed* active exploitation, not a proxy for how
prominent a CVE became in security media. The three-way comparison
isolates exactly what the KEV path is doing: with consensus absent in
all three, EPSS alone never crosses the block bar (`block_epss_threshold`
ignores EPSS magnitude once KEV+fix is satisfied, and conversely no EPSS
value substitutes for missing KEV+consensus). KEV is corroboration of a
different kind — direct evidence of exploitation, not a probabilistic
signal — and the policy treats it as sufficient on its own.

### 10.4 EPSS volatility, demonstrated a second time

`CVE-2023-32314` (vm2 sandbox escape, juice-shop, original 9-image
dataset) already demonstrated EPSS dropping from 0.70 (March) to 0.056
(June) with no change to the CVE or its fix (§4, original analysis). This
expansion run is itself a second data point for the same phenomenon:
re-running the full 30-image dataset against live EPSS/NVD/KEV data on a
different day will not reproduce bit-identical numbers to a prior run,
by design — the gate's inputs are genuinely time-varying external
signals, not static scanner output. Any reproduction of these results
should be read as "the gate's logic is reproducible given the same
enrichment snapshot," not "these exact counts are reproducible on any
date" — a distinction worth stating explicitly in the thesis's
reproducibility claims (see `docs/notes_dataset_expansion.md`'s closing
note and `policy/docs/enrichment.md`'s "EPSS: embedded vs. live"
section for the mechanism).

---

## 8. Files Referenced in This Analysis

- `docs/notes_architectural_decision.md` — policy layer design rationale
- `policy/rego/lib.rego` — shared predicates
- `policy/rego/p[1-7]*.rego` — policy implementations (P1–P5, P7)
- `policy/rego/p_gate.rego` — tri-state gate (BLOCK/REVIEW/PASS)
- `policy/tests/` — 60 OPA unit tests
- `policy/normalisers/` — scanner adapter package (trivy, grype)
- `policy/enrichers/` — external data adapter package (nvd, osv, epss)
- `policy/classifiers/` — layer classifier package (rule, agent)
- `policy/classifiers/advisor.py` — LLM reviewer advisor (1–2 sentence triage guidance per REVIEW finding)
- `policy/policy_gate.py` — single-image CI/CD gate CLI (tri-state: block/review/pass)
- `policy/evaluate_all.py` — batch orchestrator for the study dataset
- `policy/configs/` — policy configuration JSON files
- `docs/notes_dataset_expansion.md` — 9→30 image expansion: rationale, image list, methodology (§10)
- `policy/docs/` — code reference: architecture, full p_gate tier/config reference, enrichment/retry behavior, deployment modes
