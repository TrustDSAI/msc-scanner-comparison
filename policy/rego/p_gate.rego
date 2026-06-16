# p_gate: tri-state gating decision for CI/CD integration.
#
# Unlike P1 through P7, which produce a single deny set (block or pass),
# p_gate produces THREE outcomes per finding so a pipeline can react
# proportionally:
#
#   block  -> beyond reasonable doubt. Hard-fail the build. A human should
#             not have to confirm; the evidence is unambiguous.
#   review -> real finding, not slam-dunk. Surface to a human for a
#             decision. The pipeline does not silently pass it.
#   pass   -> nothing actionable.
#
# Design rationale
# ----------------
# The empirical study (Chapter 5) showed that severity labels diverge
# wildly across scanners and that total-count thresholds are unreliable.
# The block tier is therefore deliberately narrow: only findings where
# every independent signal aligns, or where an authoritative external
# catalog confirms in-the-wild exploitation, qualify. Everything else a
# scanner flags is real enough to warrant a human look but not enough to
# block a build automatically. That nuance is exactly what a human should
# see, so it goes to review rather than being silently dropped or
# automatically blocked.
#
# Block conditions (beyond reasonable doubt)
# ------------------------------------------
#   1. CVE in CISA KEV catalog AND a fix is available.
#      KEV is direct empirical evidence of exploitation (not a model
#      estimate), and a fix means there is a remediation path. Strongest
#      signal in the framework.
#   2. CRITICAL AND cross-scanner consensus AND fix available AND NVD
#      validated AND OSV advisory confirmed AND EPSS > block_epss_threshold
#      (default 0.5, "exploitation more likely than not in 30 days").
#      Every independent signal aligned at the highest confidence tier.
#
# There is intentionally no layer asymmetry in the block tier. Layer-aware
# thresholds (P5) are a review-quality filter; for the hard-block tier a
# fully corroborated EPSS-0.5+ finding is beyond reasonable doubt
# regardless of layer.
#
# Review conditions
# -----------------
#   - Any CRITICAL finding not already in block (e.g. lower EPSS, missing
#     OSV advisory, single-scanner).
#   - Any HIGH finding with a fix and consensus (severity label is
#     untrustworthy across tools, so HIGH never auto-blocks; it is shown
#     to a human).
#   - KEV membership WITHOUT a fix (actively exploited but no remediation
#     path; cannot block because the build could never pass, must surface).
#
# Pass
# ----
#   Everything else.
#
# Image lifecycle (EOL) is attached as context on every block and review
# entry via lib.make_msg, but does not by itself move a finding between
# tiers. Acting on EOL is a CI-workflow decision, not a Rego decision.
#
# Config schema (all keys optional; defaults shown)
# -------------------------------------------------
# {
#   "block_epss_threshold":    0.5,     # EPSS floor for the CRITICAL block path
#   "review_high_min_epss":    0.0,     # EPSS floor for HIGH to reach review (0 = any)
#   "nvd_acceptable_statuses": ["Analyzed", "Modified"],
#   "kev_requires_fix":        true,    # false = block KEV even without a fix
#   "enable_kev_block":        true,    # false = disable the KEV block path entirely
#   "enable_critical_block":   true     # false = disable the corroborated-CRITICAL path
# }
#
# Custom policy: supply --rego-dir and --policy-package to replace this
# file entirely. The custom package must expose:
#   block, review   (sets of objects with at least cve_id, package, version, reason)
#   suppressed      (optional; best-effort -- undefined evaluates to no
#                     suppression, the Python caller's opa_eval() already
#                     handles an undefined query gracefully)
# The enrichment pipeline and report formatters are unchanged.
#
# Suppression (--exceptions-dir)
# -------------------------------
# A finding matching an unexpired entry in input.exceptions (see
# lib.suppressed) is excluded from both block and review, and recorded
# instead in a third output set, `suppressed`, carrying a
# `would_have_been: "block"|"review"` field for audit -- suppressing a
# hard block is a different governance decision than suppressing a
# softer review, and that distinction is kept visible rather than
# collapsed. See docs/notes_suppression_workflow_design.md.

package vuln.gate

import data.vuln.lib
import future.keywords.if
import future.keywords.in

block_epss_threshold    := lib.config_value("block_epss_threshold",  0.5)
review_high_min_epss   := lib.config_value("review_high_min_epss",   0.0)
enable_kev_block       := lib.config_value("enable_kev_block",       true)
enable_critical_block  := lib.config_value("enable_critical_block",  true)
kev_requires_fix_cfg   := lib.config_value("kev_requires_fix",       true)

nvd_acceptable_statuses := s if {
    s := input.config.nvd_acceptable_statuses
} else := ["Analyzed", "Modified"]

# Defaulted so lib.suppressed(finding, gate_image) never receives an
# undefined argument when input.image is absent (e.g. test fixtures using
# fx.wrap() with no image block) -- an undefined function argument makes
# the whole call (and thus `not lib.suppressed(...)`) undefined rather
# than false, which would silently empty out block/review.
gate_image := object.get(input, "image", {})

# --- Decision per finding ---------------------------------------------

# A finding's decision is the highest tier it qualifies for.
decision(finding) := "block"  if is_block(finding)
decision(finding) := "review" if {
    not is_block(finding)
    is_review(finding)
}
decision(finding) := "pass" if {
    not is_block(finding)
    not is_review(finding)
}

# --- Block tier (beyond reasonable doubt) -----------------------------

is_block(finding) if {
    enable_kev_block
    kev_block(finding)
}
is_block(finding) if {
    enable_critical_block
    critical_block(finding)
}

# Condition 1: KEV catalog + fix available (or fix not required per config).
kev_block(finding) if {
    lib.in_kev(finding)
    lib.has_fix(finding)
}
kev_block(finding) if {
    lib.in_kev(finding)
    not kev_requires_fix_cfg
}

# Condition 2: fully corroborated CRITICAL above the high-confidence EPSS bar.
critical_block(finding) if {
    lib.is_critical(finding)
    lib.is_consensus(finding)
    lib.has_fix(finding)
    lib.nvd_status_in(finding, nvd_acceptable_statuses)
    lib.osv_confirms_advisory(finding)
    lib.osv_has_fix(finding)
    lib.epss_above(finding, block_epss_threshold)
}

# --- Review tier ------------------------------------------------------

# Any CRITICAL not already blocked.
is_review(finding) if {
    lib.is_critical(finding)
}

# HIGH with a fix and consensus: real, but severity label untrustworthy.
# review_high_min_epss can raise the bar (e.g. 0.1 to suppress noisy LOW-EPSS HIGH findings).
is_review(finding) if {
    lib.is_severity(finding, "HIGH")
    lib.has_fix(finding)
    lib.is_consensus(finding)
    lib.epss_above(finding, review_high_min_epss)
}

# KEV without a fix: actively exploited, no remediation path.
is_review(finding) if {
    lib.in_kev(finding)
    not lib.has_fix(finding)
}

# --- Output sets ------------------------------------------------------

block contains msg if {
    some finding in input.findings
    is_block(finding)
    not lib.suppressed(finding, gate_image)
    msg := lib.make_msg(finding, "gate", block_reason(finding),
        {"tier":       "block",
         "epss_score": object.get(finding.epss, "score", null),
         "in_kev":     object.get(finding.kev, "in_kev", false)})
}

review contains msg if {
    some finding in input.findings
    not is_block(finding)
    is_review(finding)
    not lib.suppressed(finding, gate_image)
    msg := lib.make_msg(finding, "gate", review_reason(finding),
        {"tier":       "review",
         "epss_score": object.get(finding.epss, "score", null),
         "in_kev":     object.get(finding.kev, "in_kev", false)})
}

# Findings that would have reached block or review but matched an
# unexpired exception. Recorded for audit; never counted toward
# block_build / review_required.
suppressed contains msg if {
    some finding in input.findings
    is_block(finding)
    lib.suppressed(finding, gate_image)
    msg := lib.make_msg(finding, "gate", block_reason(finding),
        {"tier":             "suppressed",
         "would_have_been":  "block",
         "epss_score":       object.get(finding.epss, "score", null),
         "in_kev":           object.get(finding.kev, "in_kev", false)})
}

suppressed contains msg if {
    some finding in input.findings
    not is_block(finding)
    is_review(finding)
    lib.suppressed(finding, gate_image)
    msg := lib.make_msg(finding, "gate", review_reason(finding),
        {"tier":             "suppressed",
         "would_have_been":  "review",
         "epss_score":       object.get(finding.epss, "score", null),
         "in_kev":           object.get(finding.kev, "in_kev", false)})
}

# --- Reason strings ---------------------------------------------------

block_reason(finding) := "KEV catalog: actively exploited, fix available" if {
    kev_block(finding)
}
block_reason(finding) := "CRITICAL fully corroborated, EPSS above block threshold" if {
    not kev_block(finding)
    critical_block(finding)
}

review_reason(finding) := "KEV catalog: actively exploited, no fix available" if {
    lib.in_kev(finding)
    not lib.has_fix(finding)
}
review_reason(finding) := "CRITICAL, needs human decision" if {
    lib.is_critical(finding)
    not lib.in_kev(finding)
}
review_reason(finding) := "HIGH with fix and consensus, needs human decision" if {
    not lib.is_critical(finding)
    lib.is_severity(finding, "HIGH")
}

# --- Aggregate gate verdict -------------------------------------------

# block_build is true when there is at least one block-tier finding.
default block_build := false
block_build if count(block) > 0

# review_required is true when there are review-tier findings (and the
# CLI may map this to a distinct exit code).
default review_required := false
review_required if count(review) > 0
