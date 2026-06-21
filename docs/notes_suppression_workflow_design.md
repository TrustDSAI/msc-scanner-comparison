# Suppression Workflow: Design and Implementation Plan

**Date:** 2026-06-04
**Decision:** Implement governed risk acceptance with LLM advisor, YAML-stored exceptions, expiry automation, and GitHub Actions integration.
**Status:** Approved for build

**Implementation status (as of this commit):** Only the data model and
enforcement mechanics shipped -- YAML exception files, the `lib.suppressed`
Rego predicate, expiry-by-date or expiry-by-fix-available, and the
`suppressed` audit output with `would_have_been`. **Not built:** the
LLM-drafted suppression proposal (§4-5), the auto-opened exception PR
(§10 success criterion 4), and any CODEOWNERS-based or cryptographic
approval verification (§2.2, §11). What exists today is "suppress via a
hand-written, PR-reviewed YAML file" -- the actual approval enforcement
is GitHub branch protection on that PR, not anything this gate checks.
Read this document as the Phase 2 design target, not a description of
what's running; the gap is intentional and called out as future work
in `notes_architectural_decision.md`'s Limitations section.

---

## 1. What We Are Building

A workflow that turns gate failures into *governed* risk-acceptance decisions, with three properties:

1. The LLM is **advisory, not authoritative**. It writes a structured suppression proposal for a human to review. The LLM never blocks or unblocks anything by itself.
2. Every approved suppression has a **written justification, an approver, and an expiry**. Suppressions auto-revoke when they expire.
3. Exceptions live as YAML in the repo, **version-controlled together with the policy that they except**. Reviewed via the same PR process as code.

This is the implementation of the "risk-acceptance workflow" identified as future work in `notes_architectural_decision.md` (section: "The Gating Assumption and Its Limits").

---

## 2. Architectural Decisions (Settled)

### 2.1 Exception store: YAML in the repo

**Decision.** Approved exceptions are checked-in YAML files under `policy/exceptions/`.

**Rationale.**
- Version-controlled (full audit trail in git history).
- PR-based review (no new approval UI to build; uses existing code review).
- Greppable, diffable, portable (no database).
- Suppressions and the policy that produced them sit in the same repo.

**Trade-off.**
- Does not scale to thousands of exceptions across many repos. For thesis demonstration this is fine; for a multi-team production deployment a centralised store would be the next step.

### 2.2 Approval mechanism: PR-based

**Decision.** When the gate blocks a PR, the CI job creates (or updates) an exception-proposal PR carrying the YAML the human edits. Merging that PR into the main branch applies the suppression. Reviewers are determined by the repo's existing CODEOWNERS.

**Rationale.**
- No new UI, no new auth, no new permissions model.
- The actual security review happens through the team's existing code-review workflow.
- The git history *is* the audit log.

**Trade-off.**
- Tightly coupled to GitHub flow. GitLab Merge Requests behave identically. Other platforms (Bitbucket, Gitea) need adapter shims, but the YAML format and Rego layer are platform-agnostic.

### 2.3 Expiry granularity: ISO date + open-ended flag

**Decision.** Each exception carries one of:
- `expires: 2026-09-01` (ISO date)
- `expires_when: fix_available` (re-evaluates each run; suppresses until a fix version is recorded)

Multiple modes can be combined: the exception applies until the earliest of the criteria is met.

**Rationale.**
- ISO dates are unambiguous and machine-checkable.
- `fix_available` covers the most common operational case (we know there is no patch yet; revisit when there is one) without forcing the operator to guess a date.
- Explicit expiry beats "permanent" because permanent suppressions become unaudited risk over time.

**Trade-off.**
- Adds two date / time concepts to Rego (current date + expiry comparison). OPA supports this via `time.now_ns()` and `time.parse_rfc3339_ns()`. Cleanly testable.

### 2.4 CI platform for the end-to-end demo: GitHub Actions only

**Decision.** Build one CI integration end-to-end (GitHub Actions). Document GitLab CI shape but do not implement it.

**Rationale.**
- GitHub Actions is free for public repos; no infrastructure to provision for the thesis demo.
- The composite-action shape is portable; the YAML translates mechanically to GitLab.
- Two CI integrations is engineering breadth, not research depth.

**Trade-off.**
- GitLab users would need to re-implement the workflow file. That cost is well-understood and documented in the thesis as such.

### 2.5 No Jira integration

**Decision.** Jira is not implemented in this work. The PR-based flow is the system of record.

**Rationale.**
- Jira integration is REST-API plumbing, not novel research.
- Adding it would push the work from 3 days to 4-5 with no thesis-defensible benefit.
- If Jira is desired post-thesis, the YAML exception file is the source of truth; a sync job that mirrors exception PRs to Jira tickets is straightforward and clearly out-of-scope here.

---

## 3. Component Plan

### 3.1 LLM Suppression Advisor

**File.** `policy/agents/suppression_advisor.py`

**Responsibility.** Given a deny set from an OPA evaluation, produce a structured suppression-proposal report (Markdown + JSON).

**Input.**
```python
{
  "image":    {label, eol, eol_source, ...},
  "findings": [             # the deny list
    {cve_id, package, version, layer, severity,
     epss_score, nvd_status, fix_version,
     reason, ...}
  ]
}
```

**Output.**

A Markdown report and a parallel JSON document. One entry per blocking finding, each with:

```yaml
cve_id: CVE-2023-32314
package: vm2
version: 3.9.17
recommendation: PATCH_NOW         # PATCH_NOW | ACCEPT_WITH_REVIEW | INVESTIGATE
reasoning: |
  vm2 sandbox escape with EPSS 0.7 indicates active exploitation activity.
  Fix is available in 3.9.18. Upgrade path is direct. Accepting this risk
  is not recommended.
suggested_expiry: until_fix_available
suggested_mitigations:
  - Upgrade vm2 to 3.9.18 in package.json
evidence:
  epss_score: 0.7003
  nvd_status: Modified
  osv_advisory_found: true
  detected_by: [trivy, grype]
```

**Prompt design (sketch).** System prompt: "You are a security engineering advisor. Given a blocked vulnerability finding, propose a suppression decision with structured reasoning. Use the provided enrichment data; do not invent additional context."

User prompt template: image + finding fields + the policy reason it was blocked.

Output: strict JSON.

**Determinism.** Temperature 0. Cached on disk by (provider, model, cve_id, package, version, image_label).

**Failure handling.** On agent error, emit a stub entry with `recommendation: REVIEW_REQUIRED` and the agent error in `reasoning`. The report is still useful; the human just has to do more work for that finding.

### 3.2 Exception Rule Format

**Directory.** `policy/exceptions/`

**File per exception** (or grouped by image / team / CVE). Format:

```yaml
# policy/exceptions/CVE-2023-37466-vm2.yaml
exception:
  cve_id:        CVE-2023-37466
  package:       vm2
  version_range: "<3.9.18"        # semver range or null = any version
  image:         bkimminich/juice-shop   # null = any image
  scope:         single_image     # single_image | image_family | global

  expires:       2026-09-01       # ISO date OR null
  expires_when:  null              # fix_available | null

  approval:
    approver:   alice@example.org
    approved_at: 2026-06-15
    pr:         https://github.com/org/repo/pull/47
    reasoning: >
      vm2 EPSS 0.05; CVE-2023-37466 affects code path
      not used by this application. Re-review on fix release.
```

**Rego treats an exception as matched** when:
- `cve_id` matches the finding's CVE, AND
- (`package` is null OR matches the finding's package), AND
- (`version_range` is null OR finding's version satisfies the range), AND
- (`image` is null OR matches the input image label), AND
- The exception has not expired (date in past OR `fix_available` and `osv.fix_version != null`)

### 3.3 Rego Composition

**New library file.** `policy/rego/exceptions.rego`

Exposes one predicate:

```rego
suppressed(finding, image) if {
    some exc in data.exceptions
    exc.cve_id == finding.cve_id
    matches_package(exc, finding)
    matches_image(exc, image)
    not expired(exc)
}
```

**Policy composition.** Each existing policy (P1-P7) wraps its `deny` rule:

```rego
deny contains msg if {
    some finding in input.findings
    is_blocking(finding)
    not lib.suppressed(finding, input.image)
    msg := lib.make_msg(finding, "p7", ...)
}
```

Suppressed findings disappear from `deny` but are still recorded under a new `suppressed` rule for the audit trail:

```rego
suppressed contains entry if {
    some finding in input.findings
    is_blocking(finding)
    lib.suppressed(finding, input.image)
    entry := {
        "cve_id":     finding.cve_id,
        "package":    finding.package,
        "exception":  matching_exception_id(finding),
    }
}
```

The verdict surface gains a `suppressed_count` alongside `deny_count`.

### 3.4 Expiry Automation

**Date check at policy evaluation time.**

```rego
expired(exc) if {
    exc.expires != null
    time.parse_rfc3339_ns(exc.expires) < time.now_ns()
}

expired(exc) if {
    exc.expires_when == "fix_available"
    some finding in input.findings
    finding.cve_id == exc.cve_id
    finding.osv.fix_version != null
}
```

**Garbage collection.** A separate utility (`policy/agents/expire_exceptions.py`) iterates the exceptions directory, removes (or marks expired) entries past their dates, and opens a PR to clean them up. Runs on cron / scheduled CI job. Not a blocker; can be added in a second pass.

### 3.5 GitHub Actions Integration

**File.** `.github/workflows/security-gate.yml`

Flow:

```
PR opened
   |
   v
Build container image
   |
   v
Run trivy / grype scans (existing scanner workflow)
   |
   v
Run policy gate (evaluate_all.py against PR's image)
   |
   v
If deny_count > 0:
   - Run suppression_advisor on the deny list
   - Post the Markdown report as a PR comment
   - Open a draft "exceptions/proposed-pr-NNN.yaml" PR with proposed entries
     for the human to edit / approve / discard
   - Fail the build with exit 1
If deny_count == 0:
   - Pass the build
```

**Approval flow.**

1. Reviewer reads the advisor's report (PR comment) and the proposed YAML PR.
2. Reviewer edits the YAML (adjusting expiry, narrowing scope, adding their own reasoning).
3. Reviewer approves and merges the exception PR.
4. On next gate run, the merged exception is consulted by Rego and the finding is suppressed.

**Auth.** No new tokens. Uses the default `GITHUB_TOKEN` provided to Actions, which has rights to comment on PRs and open new PRs in the same repo.

**Cost.** Free on public repos. Self-hosted runners or paid plans for private.

### 3.6 GitLab CI: Documented, Not Implemented

A section in the docs describing the equivalent `.gitlab-ci.yml` shape and Merge Request API calls. No code.

---

## 4. File Layout (Additions)

```
policy/
├── agents/
│   ├── suppression_advisor.py    NEW
│   └── expire_exceptions.py      NEW (deferred, optional)
├── exceptions/
│   ├── README.md                  NEW (format spec, examples)
│   └── example-vm2.yaml           NEW (sample for testing)
├── rego/
│   ├── exceptions.rego            NEW (matching predicates)
│   ├── p1_any_critical.rego       MODIFIED (use exceptions library)
│   ├── ... (all policy files)     MODIFIED
│   └── lib.rego                   MODIFIED (export suppressed predicate)
├── tests/
│   ├── exceptions_test.rego       NEW (~6 unit tests)
│   └── (existing test files)      MODIFIED to verify suppression flow
└── configs/                        unchanged

.github/workflows/
└── security-gate.yml              NEW

docs/
├── notes_suppression_workflow_design.md   THIS DOCUMENT
└── notes_jira_integration_sketch.md       NEW (the documented-not-implemented adapter)
```

---

## 5. Data Model (Exception YAML Schema, JSON Schema notation)

```json
{
  "exception": {
    "cve_id":         {"type": "string", "pattern": "^CVE-\\d{4}-\\d+$", "required": true},
    "package":        {"type": "string", "required": false},
    "version_range":  {"type": "string", "required": false},
    "image":          {"type": "string", "required": false},
    "scope":          {"enum": ["single_image", "image_family", "global"], "default": "single_image"},
    "expires":        {"type": "string", "format": "date", "required": false},
    "expires_when":   {"enum": ["fix_available"], "required": false},
    "approval": {
      "approver":    {"type": "string", "required": true},
      "approved_at": {"type": "string", "format": "date", "required": true},
      "pr":          {"type": "string", "format": "uri", "required": false},
      "reasoning":   {"type": "string", "required": true}
    }
  }
}
```

At least one of `expires` or `expires_when` must be present. An exception with neither is rejected at policy-load time.

---

## 6. Test Plan

### 6.1 Rego unit tests (`policy/tests/exceptions_test.rego`)

- Exception with date in past does not suppress (expired).
- Exception with date in future suppresses.
- `expires_when: fix_available` suppresses while `osv.fix_version` is null.
- `expires_when: fix_available` stops suppressing when `osv.fix_version` is non-null.
- Image-scoped exception only suppresses findings on that image.
- Package mismatch does not suppress.
- Version-range mismatch does not suppress.

### 6.2 Suppression advisor tests (`tests/test_suppression_advisor.py`)

- Given a deny list with one finding, produces one report entry.
- Given a deny list with N findings, produces N entries.
- Cached call does not re-invoke the LLM.
- Agent-failure path produces a `REVIEW_REQUIRED` entry rather than crashing.

### 6.3 End-to-end test

A scripted scenario:
1. Run pipeline against juice-shop. Confirm 1 block (CVE-2023-32314 vm2).
2. Run advisor against that deny set. Confirm a Markdown report and JSON.
3. Apply an exception YAML for CVE-2023-32314 with `expires_when: fix_available`.
4. Re-run pipeline. Confirm `deny_count == 0` and `suppressed_count == 1`.
5. Modify the enriched input to add `osv.fix_version: "3.9.18"`.
6. Re-run pipeline. Confirm the exception is treated as expired and `deny_count == 1`.

---

## 7. Day-by-day Execution

### Day 1: Advisor + Rego suppression

- Write `agents/suppression_advisor.py` with prompt, output schema, caching.
- Write `rego/exceptions.rego` with matching and expiry predicates.
- Update `lib.rego` to expose `suppressed` predicate.
- Modify all six existing policies to filter their `deny` rules through suppression.
- Write 7 unit tests for `exceptions.rego`. All pass.

### Day 2: Exception YAML pipeline + end-to-end test

- Define YAML schema and write loader (`evaluate_all.py` reads `exceptions/*.yaml` into `input.exceptions`).
- Implement the end-to-end test scenario from section 6.3.
- Run `evaluate_all.py` on the full 9-image dataset with one example exception applied. Verify suppression appears in the verdict matrix.
- Add a `suppressed_count` column to `summary.md`.

### Day 3: GitHub Actions workflow + documentation

- Write `.github/workflows/security-gate.yml`.
- Write composite action: `.github/actions/post-suppression-report/action.yml`.
- Test the workflow shape with a dry-run (mocked PR; uses local test fixtures).
- Update `notes_architectural_decision.md` with the suppression workflow design.
- Write `notes_jira_integration_sketch.md` (documented-not-implemented).
- Update Chapter 6 of the thesis with a section on governed risk acceptance.

---

## 8. Risks and Mitigations

### Risk: LLM hallucinates a recommendation

**Mitigation.** Recommendation is a constrained enum (`PATCH_NOW | ACCEPT_WITH_REVIEW | INVESTIGATE`). The reasoning field is freeform but human-reviewed before any suppression takes effect. The advisor is advisory only; no policy change happens without human approval. This is the central architectural property.

### Risk: Exception expiry not enforced

**Mitigation.** Expiry is checked at every policy evaluation, not via a separate cron. As long as the gate runs (on every PR), expired exceptions stop suppressing the moment they expire.

### Risk: Exception scope too broad (matches more than intended)

**Mitigation.** Default scope is `single_image`. Wider scopes require explicit declaration. The schema validation rejects unscoped exceptions. The advisor's suggested YAML defaults to the narrowest scope that covers the finding.

### Risk: Exception governance becomes shadow IT (people merging exception PRs without security review)

**Mitigation.** Out of scope for this work to enforce; suggest that real deployments configure CODEOWNERS or required reviewers on `policy/exceptions/` so the security team must approve exception merges. Documented in the workflow notes.

### Risk: Re-running advisor regenerates different reasoning (LLM non-determinism)

**Mitigation.** Cached by (provider, model, cve_id, package, version, image_label). Cache survives across runs. Output text is also frozen once a human reviews it: the YAML carries the human-edited reasoning, not the LLM's draft.

### Risk: Exception file conflicts / merge problems

**Mitigation.** One file per exception (named `<cve_id>-<package>.yaml`) avoids merge conflicts on shared files. The exception files are small; conflict probability is low.

---

## 9. What Is Explicitly Out of Scope

- Multi-platform CI implementations beyond GitHub Actions.
- Jira / ServiceNow / Linear ticket sync.
- A web UI for browsing or editing exceptions.
- A centralised exception store (database) across multiple repos.
- Cryptographic signing of exception PRs or approvers (use git's existing signed-commit support if desired).
- Real-time KEV catalog updates between runs (KEV is read at run time; if it changes mid-day the next gate run picks it up).

These are sensible production-grade additions but not thesis-defensible deliverables.

---

## 10. Success Criteria

The implementation is complete and ready for thesis defence when:

1. `opa test rego/ tests/` passes including the new exception suite (target: 44/44).
2. `evaluate_all.py` produces a verdict matrix that includes `suppressed_count`.
3. A juice-shop scenario demonstrates: advisor report generation, YAML exception application, suppression in the next run, expiry on `osv.fix_version` becoming non-null.
4. The GitHub Actions workflow runs end-to-end against a test PR in a fresh repo, posting a suppression report and opening an exception PR.
5. Chapter 6 of the thesis is updated with a section on the governance workflow, referencing this design document.
6. `notes_considered_ai_tp_classifier.md` is updated to point at this work as the legitimate LLM advisory role (contrasted with the rejected authoritative role).

---

## 11. Followups (Post-Thesis)

- Jira sync adapter
- Real-time KEV catalog enricher (P7 dependency, separable from this work)
- GitLab CI workflow file
- Slack / email digest of expiring exceptions
- Exception governance dashboard
- Multi-repo exception store (centralised)
- Cryptographic approval verification (signed commits / approvers)

---

*See also:*
- `notes_architectural_decision.md` — the rejected fork-HarbourGuard decision and the architectural property of LLM-isolated-outside-OPA that this work extends.
- `notes_considered_ai_tp_classifier.md` — the rejected P7 (LLM-as-FP-classifier) that motivates the advisory role chosen here.
- `policy_experiment_results.md` — the empirical evaluation of policies P1--P6 that this workflow plugs into.
