package vuln.gate_test

import data.vuln.gate
import data.vuln.fixtures as fx
import future.keywords.if


# ----- Helpers --------------------------------------------------------

with_kev(f, kev) := json.patch(f, [{"op": "replace", "path": "/kev", "value": kev}])

kev_present := {
    "in_kev": true, "date_added": "2022-03-25",
    "due_date": "2022-04-15", "ransomware_use": "Known",
}
kev_absent := {
    "in_kev": false, "date_added": null,
    "due_date": null, "ransomware_use": null,
}

# critical_full: CRITICAL, consensus, fix, NVD Analyzed, OSV advisory+fix,
# EPSS 0.42, layer os, kev absent.

# Block condition 2 needs EPSS > 0.5; raise it.
crit_block := with_kev(
    json.patch(fx.critical_full, [{"op": "replace", "path": "/epss/score", "value": 0.6}]),
    kev_absent,
)

# Same but EPSS below the block threshold -> review, not block.
crit_review := with_kev(
    json.patch(fx.critical_full, [{"op": "replace", "path": "/epss/score", "value": 0.2}]),
    kev_absent,
)

# KEV present + fix -> block.
kev_with_fix := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity",   "value": "MEDIUM"},
        {"op": "replace", "path": "/epss/score", "value": 0.01},
    ]),
    kev_present,
)

# KEV present, no fix -> review (no remediation path).
kev_no_fix := json.patch(kev_with_fix, [
    {"op": "replace", "path": "/fix_version",     "value": null},
])

# HIGH with fix + consensus -> review.
high_review := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity",   "value": "HIGH"},
        {"op": "replace", "path": "/epss/score", "value": 0.9},
    ]),
    kev_absent,
)

# MEDIUM, nothing special -> pass.
medium_pass := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity",   "value": "MEDIUM"},
        {"op": "replace", "path": "/epss/score", "value": 0.3},
    ]),
    kev_absent,
)

# LOW -> pass.
low_pass := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity", "value": "LOW"},
    ]),
    kev_absent,
)


# ----- Block tier -----------------------------------------------------

test_kev_with_fix_blocks if {
    gate.block_build with input as fx.wrap([kev_with_fix])
}

test_fully_corroborated_critical_above_threshold_blocks if {
    gate.block_build with input as fx.wrap([crit_block])
}

test_block_set_contains_kev_finding if {
    msgs := gate.block with input as fx.wrap([kev_with_fix])
    some m in msgs
    m.tier == "block"
    m.in_kev == true
}

test_block_decision_label if {
    gate.decision(kev_with_fix) == "block" with input as fx.wrap([kev_with_fix])
}


# ----- Review tier ----------------------------------------------------

test_critical_below_block_threshold_is_review if {
    not gate.block_build with input as fx.wrap([crit_review])
    gate.review_required with input as fx.wrap([crit_review])
}

test_kev_without_fix_is_review_not_block if {
    not gate.block_build with input as fx.wrap([kev_no_fix])
    gate.review_required with input as fx.wrap([kev_no_fix])
}

test_high_with_fix_and_consensus_is_review if {
    not gate.block_build with input as fx.wrap([high_review])
    gate.review_required with input as fx.wrap([high_review])
}

test_review_decision_label if {
    gate.decision(crit_review) == "review" with input as fx.wrap([crit_review])
}

test_kev_no_fix_review_reason if {
    msgs := gate.review with input as fx.wrap([kev_no_fix])
    some m in msgs
    m.reason == "KEV catalog: actively exploited, no fix available"
}


# ----- Pass tier ------------------------------------------------------

test_medium_passes if {
    not gate.block_build with input as fx.wrap([medium_pass])
    not gate.review_required with input as fx.wrap([medium_pass])
}

test_low_passes if {
    not gate.block_build with input as fx.wrap([low_pass])
    not gate.review_required with input as fx.wrap([low_pass])
}

test_pass_decision_label if {
    gate.decision(medium_pass) == "pass" with input as fx.wrap([medium_pass])
}


# ----- Mixed input ----------------------------------------------------

test_mixed_input_separates_tiers if {
    inp := fx.wrap([kev_with_fix, crit_review, high_review, medium_pass, low_pass])
    count(gate.block)  == 1 with input as inp
    count(gate.review) == 2 with input as inp
    gate.block_build      with input as inp
    gate.review_required  with input as inp
}


# ----- Config override ------------------------------------------------

test_lowering_block_threshold_promotes_review_to_block if {
    # crit_review has EPSS 0.2; lower block threshold to 0.1 so it blocks.
    inp := fx.wrap_with_config([crit_review], {"block_epss_threshold": 0.1})
    gate.block_build with input as inp
}


# ----- Empty ----------------------------------------------------------

test_empty_passes if {
    not gate.block_build with input as fx.wrap([])
    not gate.review_required with input as fx.wrap([])
}
