# P1: Block if any CRITICAL finding is present.
# Composed from vuln.lib predicates: is_critical.

package vuln.p1

import data.vuln.lib
import future.keywords.if
import future.keywords.in

default block_build := false

block_build if {
    some finding in input.findings
    is_blocking(finding)
}

is_blocking(finding) if lib.is_critical(finding)

deny contains msg if {
    some finding in input.findings
    is_blocking(finding)
    msg := lib.make_msg(finding, "p1", "CRITICAL severity", {})
}
