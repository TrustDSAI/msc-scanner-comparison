# P2: Block if a CRITICAL finding has an available fix.
# Composed from vuln.lib predicates: is_critical, has_fix.

package vuln.p2

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
    lib.has_fix(finding)
}

deny contains msg if {
    some finding in input.findings
    is_blocking(finding)
    msg := lib.make_msg(finding, "p2", "CRITICAL with fix available", {})
}
