# P5: Layer-aware blocking with per-layer thresholds.
#
# Routes each finding to one of two sub-policies based on input.layer:
#   app -> strict gate (P4 strict)
#   os  -> relaxed gate (lower EPSS, accept "Analyzed" + "Modified")
#   unknown -> conservative: do not block on unknowns alone
#
# Config schema:
#     {
#       "app": { ... same fields as P4 config ... },
#       "os":  { ... same fields as P4 config ... }
#     }
#
# Defaults reproduce the asymmetric thresholds informed by the empirical
# finding that OS-layer CVEs cluster at low EPSS and frequently sit in
# NVD "Modified" status.

package vuln.p5

import data.vuln.lib
import future.keywords.if
import future.keywords.in

default block_build := false

app_config := c if {
    c := input.config.app
} else := {
    "epss_threshold":          0.1,
    "nvd_acceptable_statuses": ["Analyzed"],
    "require_consensus":       true,
    "require_osv_advisory":    true,
    "require_osv_fix":         true,
}

os_config := c if {
    c := input.config.os
} else := {
    "epss_threshold":          0.01,
    "nvd_acceptable_statuses": ["Analyzed", "Modified"],
    "require_consensus":       true,
    "require_osv_advisory":    true,
    "require_osv_fix":         true,
}

block_build if {
    some finding in input.findings
    is_blocking(finding)
}

is_blocking(finding) if {
    lib.is_app(finding)
    matches_config(finding, app_config)
}

is_blocking(finding) if {
    lib.is_os(finding)
    matches_config(finding, os_config)
}

matches_config(finding, cfg) if {
    lib.is_critical(finding)
    consensus_ok(finding, cfg)
    lib.nvd_status_in(finding, cfg.nvd_acceptable_statuses)
    osv_advisory_ok(finding, cfg)
    osv_fix_ok(finding, cfg)
    lib.epss_above(finding, cfg.epss_threshold)
}

consensus_ok(finding, cfg) if not cfg.require_consensus
consensus_ok(finding, cfg) if lib.is_consensus(finding)

osv_advisory_ok(finding, cfg) if not cfg.require_osv_advisory
osv_advisory_ok(finding, cfg) if lib.osv_confirms_advisory(finding)

osv_fix_ok(finding, cfg) if not cfg.require_osv_fix
osv_fix_ok(finding, cfg) if lib.osv_has_fix(finding)

deny contains msg if {
    some finding in input.findings
    is_blocking(finding)
    msg := lib.make_msg(finding, "p5",
        "layer-aware: per-layer policy matched",
        {"epss_score": lib.epss_score(finding),
         "nvd_status": finding.nvd.status,
         "layer":      finding.layer})
}
