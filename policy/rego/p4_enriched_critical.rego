# P4: Block CRITICAL findings that are confirmed, NVD-validated,
# OSV-confirmed, and exceed an EPSS threshold.
#
# All thresholds are config-driven so the same policy file produces multiple
# variants by swapping the input.config block. Defaults reproduce the strict
# behaviour documented in the architectural decision record.
#
# Config schema:
#     {
#       "epss_threshold":          0.1,            # float
#       "nvd_acceptable_statuses": ["Analyzed"],   # list[str]
#       "require_consensus":       true,           # bool
#       "require_osv_advisory":    true,           # bool
#       "require_osv_fix":         true            # bool
#     }

package vuln.p4

import data.vuln.lib
import future.keywords.if
import future.keywords.in

default block_build := false

epss_threshold := lib.config_value("epss_threshold", 0.1)

nvd_acceptable_statuses := s if {
    s := input.config.nvd_acceptable_statuses
} else := ["Analyzed"]

require_consensus     := lib.config_value("require_consensus", true)
require_osv_advisory  := lib.config_value("require_osv_advisory", true)
require_osv_fix       := lib.config_value("require_osv_fix", true)

block_build if {
    some finding in input.findings
    is_blocking(finding)
}

is_blocking(finding) if {
    lib.is_critical(finding)
    consensus_ok(finding)
    lib.nvd_status_in(finding, nvd_acceptable_statuses)
    osv_advisory_ok(finding)
    osv_fix_ok(finding)
    lib.epss_above(finding, epss_threshold)
}

consensus_ok(finding) if not require_consensus
consensus_ok(finding) if lib.is_consensus(finding)

osv_advisory_ok(finding) if not require_osv_advisory
osv_advisory_ok(finding) if lib.osv_confirms_advisory(finding)

osv_fix_ok(finding) if not require_osv_fix
osv_fix_ok(finding) if lib.osv_has_fix(finding)

deny contains msg if {
    some finding in input.findings
    is_blocking(finding)
    msg := lib.make_msg(finding, "p4",
        "CRITICAL, confirmed, with fix and EPSS above threshold",
        {"epss_score": lib.epss_score(finding),
         "nvd_status": finding.nvd.status})
}
