# P3: Block if a CRITICAL finding is confirmed by multiple scanners.
# Composed from vuln.lib predicates: is_critical, is_consensus.

package vuln.p3

import data.vuln.lib
import future.keywords.if
import future.keywords.in

default block_build := false

block_build if {
    some finding in input.findings
    is_blocking(finding)
}

is_blocking(finding) if {
    lib.is_critical(finding)
    lib.is_consensus(finding)
}

deny contains msg if {
    some finding in input.findings
    is_blocking(finding)
    msg := lib.make_msg(finding, "p3", "CRITICAL confirmed by multiple scanners", {})
}
