package vuln.p1_test

import data.vuln.p1
import data.vuln.fixtures as fx
import future.keywords.if

# Positive cases -------------------------------------------------------

test_blocks_on_any_critical if {
    p1.block_build with input as fx.wrap([fx.critical_full])
}

test_blocks_when_critical_among_others if {
    p1.block_build with input as fx.wrap([fx.low_finding, fx.critical_full, fx.high_consensus])
}

test_deny_emits_message_per_critical if {
    second := fx.mutate("/cve_id", "CVE-2024-AAAB")
    msgs := p1.deny with input as fx.wrap([fx.critical_full, second])
    count(msgs) == 2
}

test_deny_msg_carries_cve_id if {
    msgs := p1.deny with input as fx.wrap([fx.critical_full])
    some m in msgs
    m.cve_id == "CVE-2024-AAAA"
    m.policy == "p1"
}

# Negative cases -------------------------------------------------------

test_does_not_block_on_high_only if {
    not p1.block_build with input as fx.wrap([fx.high_consensus])
}

test_does_not_block_on_low_only if {
    not p1.block_build with input as fx.wrap([fx.low_finding])
}

test_does_not_block_on_empty if {
    not p1.block_build with input as fx.wrap([])
}
