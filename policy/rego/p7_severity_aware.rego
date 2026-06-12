# P7: Severity-aware gating with independent corroboration.
#
# P7 extends P5 by adding two new gate triggers:
#   1. HIGH severity findings with strong independent exploitation evidence.
#   2. CVEs listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.
#
# The CRITICAL gate and layer routing are inherited from P5. P7 does not
# re-implement that logic; it delegates and composes.
#
# Image lifecycle (EOL) is reported on every deny message via the make_msg
# helper but does not trigger blocks. Downstream CI policy decides how to
# act on the EOL flag. Mixing lifecycle state with the CVE gate destroyed
# both signals when attempted in an earlier P6 design.
#
# Rationale
# ---------
# Chapter 5 found that severity assignments diverge wildly between scanners
# on shared CVEs (7.6 to 96.3 percent agreement). The CRITICAL tier is the
# only severity label where cross-tool agreement is reliable. P1 through P5
# therefore gate only on CRITICAL.
#
# That is the right defensive choice for empirical comparability and the
# wrong operational choice for a production gate: HIGH severity routinely
# covers RCE, authentication bypass, and privilege escalation. Ignoring
# those because "the tools disagree on the label" ships real risk.
#
# P7 compensates for the untrustworthy HIGH severity label by requiring
# *stronger* independent evidence (higher EPSS threshold) before gating.
#
# Why EPSS 0.5 for HIGH specifically
# -----------------------------------
# EPSS thresholds map to percentiles:
#   > 0.1  approximately top 5 percent
#   > 0.2  approximately top 2 percent
#   > 0.5  approximately top 1 percent ("exploitation is more likely than
#          not in the next 30 days")
#
# For CRITICAL we already have high cross-tool confidence in the severity
# label; the P5 thresholds (0.1 for app, 0.01 for os) are calibrated
# against that confidence. For HIGH the severity label is untrustworthy
# across scanners, so we require much stronger independent evidence
# (EPSS > 0.5) before gating. This is asymmetric trust expressed as
# asymmetric thresholds.
#
# Why KEV bypasses severity
# --------------------------
# The CISA KEV catalog is built from observed exploitation telemetry, not
# from theoretical severity. Membership is empirical evidence, not a
# probabilistic estimate. The severity assigned by NVD or vendor advisories
# may be wrong; KEV membership is not. KEV with a fix available always
# blocks. KEV without a fix passes (no actionable remediation path), but
# the finding remains in the audit trail.
#
# Config schema
# -------------
# Inherits the P5 config schema (app{...}, os{...}) and adds:
#   {
#     "high_epss_threshold":   0.5,    # threshold for HIGH severity gating
#     "kev_requires_fix":      true    # if false, KEV blocks regardless of fix
#   }

package vuln.p7

import data.vuln.lib
import data.vuln.p5
import future.keywords.if
import future.keywords.in

default block_build := false

high_epss_threshold := lib.config_value("high_epss_threshold", 0.5)
kev_requires_fix    := lib.config_value("kev_requires_fix", true)

# --- Block conditions: P5 (inherited) plus two new disjuncts ----------

# Inherited: P5 handles CRITICAL with layer routing.
block_build if p5.block_build

# Added: HIGH severity with consensus + fix + high EPSS.
block_build if {
    some finding in input.findings
    is_high_blocking(finding)
}

# Added: CVE in CISA KEV catalog (with fix, by default).
block_build if {
    some finding in input.findings
    is_kev_blocking(finding)
}

# --- Helper predicates ------------------------------------------------

is_high_blocking(finding) if {
    lib.is_severity(finding, "HIGH")
    lib.has_fix(finding)
    lib.is_consensus(finding)
    lib.epss_above(finding, high_epss_threshold)
}

is_kev_blocking(finding) if {
    lib.in_kev(finding)
    kev_fix_ok(finding)
}

kev_fix_ok(finding) if not kev_requires_fix
kev_fix_ok(finding) if lib.has_fix(finding)

# --- Deny: forward P5's messages and add HIGH/KEV entries -------------

deny contains msg if {
    some d in p5.deny
    msg := object.union(d, {"policy": "p7", "delegated_from": "p5"})
}

deny contains msg if {
    some finding in input.findings
    is_high_blocking(finding)
    msg := lib.make_msg(finding, "p7",
        "HIGH with fix, consensus, and high EPSS",
        {"epss_score": lib.epss_score(finding),
         "trigger":    "high_with_epss"})
}

deny contains msg if {
    some finding in input.findings
    is_kev_blocking(finding)
    msg := lib.make_msg(finding, "p7",
        "CISA KEV catalog: actively exploited",
        {"kev_date_added":     finding.kev.date_added,
         "kev_ransomware_use": finding.kev.ransomware_use,
         "trigger":            "kev_catalog"})
}
