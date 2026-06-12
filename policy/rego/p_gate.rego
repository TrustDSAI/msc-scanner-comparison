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
# Config schema
# -------------
# {
#   "block_epss_threshold":    0.5,
#   "review_high_min_epss":    0.0,    # HIGH goes to review at any EPSS by default
#   "nvd_acceptable_statuses": ["Analyzed", "Modified"],
#   "kev_requires_fix":        true
# }

package vuln.gate

import data.vuln.lib
import future.keywords.if
import future.keywords.in

block_epss_threshold := lib.config_value("block_epss_threshold", 0.5)

nvd_acceptable_statuses := s if {
    s := input.config.nvd_acceptable_statuses
} else := ["Analyzed", "Modified"]

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

is_block(finding) if kev_block(finding)
is_block(finding) if critical_block(finding)

# Condition 1: KEV catalog + fix available.
kev_block(finding) if {
    lib.in_kev(finding)
    lib.has_fix(finding)
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
is_review(finding) if {
    lib.is_severity(finding, "HIGH")
    lib.has_fix(finding)
    lib.is_consensus(finding)
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
    msg := lib.make_msg(finding, "gate", block_reason(finding),
        {"tier":       "block",
         "epss_score": object.get(finding.epss, "score", null),
         "in_kev":     object.get(finding.kev, "in_kev", false)})
}

review contains msg if {
    some finding in input.findings
    not is_block(finding)
    is_review(finding)
    msg := lib.make_msg(finding, "gate", review_reason(finding),
        {"tier":       "review",
         "epss_score": object.get(finding.epss, "score", null),
         "in_kev":     object.get(finding.kev, "in_kev", false)})
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
