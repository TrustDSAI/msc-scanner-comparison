package vuln.p5_test

import data.vuln.fixtures as fx
import data.vuln.p5
import future.keywords.if

# P5's defining behaviour is layer routing: the same finding is held to a
# stricter bar in the app layer than in the os layer. The tests that matter
# are therefore the ones where the two layers disagree about one finding.
#
# Default thresholds (p5_layer_aware.rego):
#   app -> EPSS > 0.1,  NVD in {Analyzed}
#   os  -> EPSS > 0.01, NVD in {Analyzed, Modified}
#
# fx.critical_full is layer "os", EPSS 0.42, NVD "Analyzed".

as_app(finding) := json.patch(finding, [
	{"op": "replace", "path": "/layer", "value": "app"},
])

with_epss(finding, score) := json.patch(finding, [
	{"op": "replace", "path": "/epss/score", "value": score},
])

with_nvd(finding, status) := json.patch(finding, [
	{"op": "replace", "path": "/nvd/status", "value": status},
])

# Positive -------------------------------------------------------------

test_blocks_os_layer_when_all_conditions_met if {
	p5.block_build with input as fx.wrap([fx.critical_full])
}

test_blocks_app_layer_when_all_conditions_met if {
	# EPSS 0.42 clears the stricter app threshold of 0.1 as well.
	p5.block_build with input as fx.wrap([as_app(fx.critical_full)])
}

# The layer split ------------------------------------------------------

test_epss_between_thresholds_blocks_in_os_layer if {
	# 0.05 is above the os threshold of 0.01.
	p5.block_build with input as fx.wrap([with_epss(fx.critical_full, 0.05)])
}

test_epss_between_thresholds_does_not_block_in_app_layer if {
	# The same 0.05 is below the app threshold of 0.1. Same finding, same
	# evidence, different layer, opposite outcome. This is P5.
	not p5.block_build with input as fx.wrap([as_app(with_epss(fx.critical_full, 0.05))])
}

test_nvd_modified_blocks_in_os_layer if {
	p5.block_build with input as fx.wrap([with_nvd(fx.critical_full, "Modified")])
}

test_nvd_modified_does_not_block_in_app_layer if {
	# The app layer accepts "Analyzed" only.
	not p5.block_build with input as fx.wrap([as_app(with_nvd(fx.critical_full, "Modified"))])
}

# Unknown layer --------------------------------------------------------

test_unknown_layer_does_not_block if {
	# is_blocking requires is_app or is_os; a finding with neither is not
	# blocked on its own, however strong its other signals.
	unknown := json.patch(fx.critical_full, [{"op": "remove", "path": "/layer"}])
	not p5.block_build with input as fx.wrap([unknown])
}

# Config override ------------------------------------------------------

test_config_can_raise_os_threshold_to_pass if {
	cfg := {"os": {
		"epss_threshold": 0.5,
		"nvd_acceptable_statuses": ["Analyzed", "Modified"],
		"require_consensus": true,
		"require_osv_advisory": true,
		"require_osv_fix": true,
	}}
	not p5.block_build with input as fx.wrap_with_config([fx.critical_full], cfg)
}

test_config_can_drop_consensus_requirement if {
	cfg := {"os": {
		"epss_threshold": 0.01,
		"nvd_acceptable_statuses": ["Analyzed", "Modified"],
		"require_consensus": false,
		"require_osv_advisory": true,
		"require_osv_fix": true,
	}}
	p5.block_build with input as fx.wrap_with_config([fx.critical_single_scanner], cfg)
}

# Negative: each condition individually ---------------------------------

test_high_severity_does_not_block if {
	not p5.block_build with input as fx.wrap([fx.high_consensus])
}

test_single_scanner_does_not_block if {
	not p5.block_build with input as fx.wrap([fx.critical_single_scanner])
}

test_osv_without_fix_version_does_not_block if {
	not p5.block_build with input as fx.wrap([fx.critical_no_fix])
}

test_epss_below_os_threshold_does_not_block if {
	not p5.block_build with input as fx.wrap([with_epss(fx.critical_full, 0.005)])
}

test_nvd_rejected_does_not_block if {
	not p5.block_build with input as fx.wrap([with_nvd(fx.critical_full, "Rejected")])
}

test_does_not_block_on_empty if {
	not p5.block_build with input as fx.wrap([])
}

# Deny message ----------------------------------------------------------

test_deny_carries_layer_and_policy if {
	msgs := p5.deny with input as fx.wrap([fx.critical_full])
	some m in msgs
	m.policy == "p5"
	m.layer == "os"
	m.epss_score == 0.42
}
