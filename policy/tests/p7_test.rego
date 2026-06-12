package vuln.p7_test

import data.vuln.p7
import data.vuln.fixtures as fx
import future.keywords.if


# ----- Helpers --------------------------------------------------------

# fixtures.critical_full lacks a kev block; extend it.
with_kev(f, kev) := json.patch(f, [{"op": "add", "path": "/kev", "value": kev}])

kev_present := {
    "in_kev": true,
    "date_added": "2024-05-01",
    "due_date": "2024-05-22",
    "ransomware_use": "Unknown",
}

kev_absent := {
    "in_kev": false,
    "date_added": null,
    "due_date": null,
    "ransomware_use": null,
}

# Canonical CRITICAL finding with empty KEV (won't trigger KEV path).
crit := with_kev(fx.critical_full, kev_absent)

high_consensus_high_epss := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity",     "value": "HIGH"},
        {"op": "replace", "path": "/epss/score",   "value": 0.65},
    ]),
    kev_absent,
)

high_consensus_low_epss := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity",     "value": "HIGH"},
        {"op": "replace", "path": "/epss/score",   "value": 0.05},
    ]),
    kev_absent,
)

high_no_fix := json.patch(high_consensus_high_epss, [
    {"op": "replace", "path": "/fix_version", "value": null},
])

medium_in_kev := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/severity", "value": "MEDIUM"},
    ]),
    kev_present,
)

medium_in_kev_no_fix := json.patch(medium_in_kev, [
    {"op": "replace", "path": "/fix_version", "value": null},
])


# ----- Inherited from P6: CRITICAL with full enrichment --------------

test_blocks_critical_via_p6_delegation if {
    p7.block_build with input as fx.wrap([crit])
}

test_high_with_low_epss_does_not_block if {
    not p7.block_build with input as fx.wrap([high_consensus_low_epss])
}

test_critical_path_deny_is_tagged_delegated_from_p5 if {
    msgs := p7.deny with input as fx.wrap([crit])
    some m in msgs
    m.delegated_from == "p5"
}


# ----- Disjunct 2: HIGH path -----------------------------------------

test_blocks_high_with_consensus_fix_and_high_epss if {
    p7.block_build with input as fx.wrap([high_consensus_high_epss])
}

test_high_without_fix_does_not_block if {
    not p7.block_build with input as fx.wrap([high_no_fix])
}

test_high_below_default_threshold_does_not_block if {
    # EPSS 0.3 sits below the default 0.5 HIGH threshold
    finding := json.patch(high_consensus_high_epss, [
        {"op": "replace", "path": "/epss/score", "value": 0.3},
    ])
    not p7.block_build with input as fx.wrap([finding])
}

test_high_epss_threshold_override if {
    # critical_full has EPSS 0.42; HIGH variant with same EPSS, threshold 0.3 blocks.
    finding := json.patch(high_consensus_high_epss, [
        {"op": "replace", "path": "/epss/score", "value": 0.42},
    ])
    p7.block_build with input as fx.wrap_with_config(
        [finding],
        {"high_epss_threshold": 0.3, "critical_epss_threshold": 0.1},
    )
}


# ----- Disjunct 3: KEV path ------------------------------------------

test_blocks_kev_with_fix_regardless_of_severity if {
    p7.block_build with input as fx.wrap([medium_in_kev])
}

test_kev_without_fix_does_not_block_by_default if {
    not p7.block_build with input as fx.wrap([medium_in_kev_no_fix])
}

test_kev_without_fix_blocks_when_fix_not_required if {
    p7.block_build with input as fx.wrap_with_config(
        [medium_in_kev_no_fix],
        {"kev_requires_fix": false},
    )
}


# ----- Deny message content ------------------------------------------

test_deny_carries_trigger_for_high if {
    msgs := p7.deny with input as fx.wrap([high_consensus_high_epss])
    some m in msgs
    m.trigger == "high_with_epss"
}

test_deny_carries_trigger_for_kev if {
    msgs := p7.deny with input as fx.wrap([medium_in_kev])
    some m in msgs
    m.trigger == "kev_catalog"
}


# ----- Empty input ---------------------------------------------------

test_does_not_block_on_empty if {
    not p7.block_build with input as fx.wrap([])
}
