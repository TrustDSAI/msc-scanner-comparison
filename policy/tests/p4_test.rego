package vuln.p4_test

import data.vuln.p4
import data.vuln.fixtures as fx
import future.keywords.if

# Positive ------------------------------------------------------------

test_blocks_when_all_conditions_met if {
    p4.block_build with input as fx.wrap([fx.critical_full])
}

test_threshold_override_can_pass_otherwise_blocking if {
    # critical_full has EPSS 0.42; threshold 0.5 means no block.
    not p4.block_build with input as fx.wrap_with_config([fx.critical_full], {"epss_threshold": 0.5})
}

test_threshold_override_can_block_otherwise_passing if {
    # critical_full has EPSS 0.42; threshold 0.01 still blocks.
    p4.block_build with input as fx.wrap_with_config([fx.critical_full], {"epss_threshold": 0.01})
}

test_deny_carries_epss_score if {
    msgs := p4.deny with input as fx.wrap([fx.critical_full])
    some m in msgs
    m.epss_score == 0.42
    m.policy == "p4"
}

# Negative: each condition individually --------------------------------

test_high_severity_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/severity", "HIGH")])
}

test_single_scanner_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.critical_single_scanner])
}

test_nvd_awaiting_analysis_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/nvd/status", "Awaiting Analysis")])
}

test_nvd_rejected_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/nvd/rejected", true)])
}

test_nvd_disputed_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/nvd/disputed", true)])
}

test_osv_no_advisory_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/osv/advisory_found", false)])
}

test_osv_no_fix_version_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/osv/fix_version", null)])
}

test_epss_below_threshold_does_not_block if {
    not p4.block_build with input as fx.wrap([fx.mutate("/epss/score", 0.05)])
}

test_does_not_block_on_empty if {
    not p4.block_build with input as fx.wrap([])
}
