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
    gate.tier(kev_with_fix) == "block" with input as fx.wrap([kev_with_fix])
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
    gate.tier(crit_review) == "review" with input as fx.wrap([crit_review])
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
    gate.tier(medium_pass) == "pass" with input as fx.wrap([medium_pass])
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


# ----- Layer-aware review floor (P5_layer folded into review tier) ----
#
# The floor only applies to CRITICALs that are NOT fully corroborated --
# a fully corroborated one always reviews regardless of EPSS (see the
# corroborated-critical tests below). These fixtures break consensus
# (single-scanner) to exercise the floor path on purpose.

# app layer needs EPSS > 0.1; below that, no review.
crit_app_low_epss := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/epss/score",   "value": 0.05},
        {"op": "replace", "path": "/layer",        "value": "app"},
        {"op": "replace", "path": "/detected_by",  "value": ["trivy"]},
    ]),
    kev_absent,
)

crit_app_high_epss := json.patch(crit_app_low_epss, [
    {"op": "replace", "path": "/epss/score", "value": 0.15},
])

# os layer needs EPSS > 0.01; 0.05 clears it even though it would fail
# the app floor.
crit_os_low_epss := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/epss/score",   "value": 0.05},
        {"op": "replace", "path": "/layer",        "value": "os"},
        {"op": "replace", "path": "/detected_by",  "value": ["trivy"]},
    ]),
    kev_absent,
)

# unknown layer keeps the unconditional 0.0 floor (never silently dropped).
crit_unknown_layer := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/epss/score",   "value": 0.001},
        {"op": "replace", "path": "/layer",        "value": "unknown"},
        {"op": "replace", "path": "/detected_by",  "value": ["trivy"]},
    ]),
    kev_absent,
)

test_app_layer_below_floor_does_not_review if {
    not gate.review_required with input as fx.wrap([crit_app_low_epss])
    gate.tier(crit_app_low_epss) == "pass" with input as fx.wrap([crit_app_low_epss])
}

test_app_layer_above_floor_reviews if {
    gate.review_required with input as fx.wrap([crit_app_high_epss])
    gate.tier(crit_app_high_epss) == "review" with input as fx.wrap([crit_app_high_epss])
}

test_os_layer_lower_floor_reviews_where_app_would_not if {
    gate.review_required with input as fx.wrap([crit_os_low_epss])
}

test_unknown_layer_uses_zero_floor if {
    gate.review_required with input as fx.wrap([crit_unknown_layer])
}

test_layer_floor_configurable if {
    # Raise the os floor above 0.05 -> crit_os_low_epss no longer reviews.
    inp := fx.wrap_with_config([crit_os_low_epss], {"review_critical_os_min_epss": 0.1})
    not gate.review_required with input as inp
}


# ----- Corroborated CRITICAL below block EPSS: always review ----------
#
# Same evidence as critical_block (consensus, fix, NVD validated, OSV
# advisory + fix) but EPSS has dropped below block_epss_threshold and
# below what the app-layer floor would require. Must still review --
# the layer floor must never suppress a fully-evidenced finding.

crit_corroborated_low_epss_app := with_kev(
    json.patch(fx.critical_full, [
        {"op": "replace", "path": "/epss/score", "value": 0.05},
        {"op": "replace", "path": "/layer",      "value": "app"},
    ]),
    kev_absent,
)

test_corroborated_critical_reviews_even_below_layer_floor if {
    # 0.05 < review_critical_app_min_epss (0.1) -- would fail the floor,
    # but corroboration bypasses it.
    gate.review_required with input as fx.wrap([crit_corroborated_low_epss_app])
    gate.tier(crit_corroborated_low_epss_app) == "review"
        with input as fx.wrap([crit_corroborated_low_epss_app])
}

test_corroborated_critical_review_reason if {
    msgs := gate.review with input as fx.wrap([crit_corroborated_low_epss_app])
    some m in msgs
    m.reason == "CRITICAL fully corroborated, below block EPSS threshold"
}

test_non_corroborated_critical_still_uses_layer_floor if {
    # Same EPSS (0.05), same layer (app), but single-scanner -> not
    # corroborated -> floor applies -> does not review.
    not gate.review_required with input as fx.wrap([crit_app_low_epss])
    gate.tier(crit_app_low_epss) == "pass" with input as fx.wrap([crit_app_low_epss])
}


# ----- Configurable corroborated-critical floor (opt-in) --------------

test_corroborated_critical_floor_default_is_unconditional if {
    # No config override -> reviews even at near-zero EPSS.
    inp := fx.wrap([crit_corroborated_low_epss_app])
    gate.review_required with input as inp
}

test_corroborated_critical_floor_can_be_configured if {
    # Operator opts into a floor above 0.05 -> falls to pass.
    inp := fx.wrap_with_config(
        [crit_corroborated_low_epss_app],
        {"corroborated_critical_min_epss": 0.1},
    )
    not gate.review_required with input as inp
    gate.tier(crit_corroborated_low_epss_app) == "pass" with input as inp
}

test_corroborated_critical_floor_configured_below_epss_still_reviews if {
    # Floor set but this finding's EPSS still clears it.
    inp := fx.wrap_with_config(
        [crit_corroborated_low_epss_app],
        {"corroborated_critical_min_epss": 0.01},
    )
    gate.review_required with input as inp
}
