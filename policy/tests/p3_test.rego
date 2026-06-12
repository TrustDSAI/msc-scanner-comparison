package vuln.p3_test

import data.vuln.p3
import data.vuln.fixtures as fx
import future.keywords.if

# Positive cases -------------------------------------------------------

test_blocks_on_critical_confirmed_by_both if {
    p3.block_build with input as fx.wrap([fx.critical_full])
}

test_blocks_when_at_least_one_consensus_critical if {
    p3.block_build with input as fx.wrap([fx.critical_single_scanner, fx.critical_full])
}

test_deny_carries_detected_by if {
    msgs := p3.deny with input as fx.wrap([fx.critical_full])
    some m in msgs
    m.detected_by == ["trivy", "grype"]
    m.policy == "p3"
}

# Negative cases -------------------------------------------------------

test_does_not_block_critical_single_scanner if {
    not p3.block_build with input as fx.wrap([fx.critical_single_scanner])
}

test_does_not_block_high_even_with_consensus if {
    not p3.block_build with input as fx.wrap([fx.high_consensus])
}

test_does_not_block_on_empty if {
    not p3.block_build with input as fx.wrap([])
}
