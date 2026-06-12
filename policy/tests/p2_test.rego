package vuln.p2_test

import data.vuln.p2
import data.vuln.fixtures as fx
import future.keywords.if

# Positive cases -------------------------------------------------------

test_blocks_on_critical_with_fix if {
    p2.block_build with input as fx.wrap([fx.critical_full])
}

test_blocks_when_at_least_one_critical_fixable if {
    p2.block_build with input as fx.wrap([fx.critical_no_fix, fx.critical_full])
}

test_deny_includes_fix_version if {
    msgs := p2.deny with input as fx.wrap([fx.critical_full])
    some m in msgs
    m.fix_version == "1.1.1l"
    m.policy == "p2"
}

# Negative cases -------------------------------------------------------

test_does_not_block_critical_without_fix if {
    not p2.block_build with input as fx.wrap([fx.critical_no_fix])
}

test_does_not_block_high_with_fix if {
    not p2.block_build with input as fx.wrap([fx.high_consensus])
}

test_does_not_block_on_empty if {
    not p2.block_build with input as fx.wrap([])
}
