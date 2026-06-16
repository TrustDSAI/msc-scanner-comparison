package vuln.exceptions_test

import data.vuln.gate
import data.vuln.fixtures as fx
import future.keywords.if


# ----- Helpers --------------------------------------------------------

kev_present := {
    "in_kev": true, "date_added": "2022-03-25",
    "due_date": "2022-04-15", "ransomware_use": "Known",
}
kev_absent := {
    "in_kev": false, "date_added": null,
    "due_date": null, "ransomware_use": null,
}

with_kev(f, kev) := json.patch(f, [{"op": "replace", "path": "/kev", "value": kev}])

# A finding that would BLOCK on its own merits (consensus CRITICAL,
# EPSS above the 0.5 default threshold, fix available, no KEV needed).
would_block := with_kev(
    json.patch(fx.critical_full, [{"op": "replace", "path": "/epss/score", "value": 0.6}]),
    kev_absent,
)

# A finding that would only reach REVIEW (EPSS below the block threshold).
would_review := with_kev(
    json.patch(fx.critical_full, [{"op": "replace", "path": "/epss/score", "value": 0.2}]),
    kev_absent,
)

default_image := {"label": "test-image:latest"}

future_date := "2099-01-01T00:00:00Z"
past_date   := "2020-01-01T00:00:00Z"


# ----- Tests ------------------------------------------------------------

test_expired_date_does_not_suppress if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": past_date}
    inp := fx.wrap_full([would_block], {}, [exc], default_image)
    blocked := gate.block with input as inp
    sup := gate.suppressed with input as inp
    count(blocked) == 1
    count(sup) == 0
}

test_future_date_suppresses if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": future_date}
    inp := fx.wrap_full([would_block], {}, [exc], default_image)
    blocked := gate.block with input as inp
    sup := gate.suppressed with input as inp
    count(blocked) == 0
    count(sup) == 1
    not gate.block_build with input as inp
}

test_fix_available_suppresses_while_no_fix if {
    f := json.patch(would_block, [{"op": "replace", "path": "/osv/fix_version", "value": null}])
    exc := {"cve_id": "CVE-2024-AAAA", "expires_when": "fix_available"}
    inp := fx.wrap_full([f], {}, [exc], default_image)
    blocked := gate.block with input as inp
    sup := gate.suppressed with input as inp
    count(blocked) == 0
    count(sup) == 1
}

test_fix_available_stops_suppressing_once_fixed if {
    f := json.patch(would_block, [{"op": "replace", "path": "/osv/fix_version", "value": "1.2.3"}])
    exc := {"cve_id": "CVE-2024-AAAA", "expires_when": "fix_available"}
    inp := fx.wrap_full([f], {}, [exc], default_image)
    blocked := gate.block with input as inp
    sup := gate.suppressed with input as inp
    count(blocked) == 1
    count(sup) == 0
}

test_image_scoped_exception_only_matches_that_image if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": future_date, "image": "other-image:1.0"}
    inp := fx.wrap_full([would_block], {}, [exc], default_image)
    blocked := gate.block with input as inp
    sup := gate.suppressed with input as inp
    count(blocked) == 1
    count(sup) == 0
}

test_package_mismatch_does_not_suppress if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": future_date, "package": "some-other-package"}
    inp := fx.wrap_full([would_block], {}, [exc], default_image)
    blocked := gate.block with input as inp
    sup := gate.suppressed with input as inp
    count(blocked) == 1
    count(sup) == 0
}

test_suppressed_set_records_would_have_been_block if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": future_date}
    inp := fx.wrap_full([would_block], {}, [exc], default_image)
    msgs := gate.suppressed with input as inp
    some m in msgs
    m.would_have_been == "block"
}

test_suppressed_set_records_would_have_been_review if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": future_date}
    inp := fx.wrap_full([would_review], {}, [exc], default_image)
    msgs := gate.suppressed with input as inp
    some m in msgs
    m.would_have_been == "review"
}

test_unscoped_exception_matches_any_image if {
    exc := {"cve_id": "CVE-2024-AAAA", "expires": future_date}
    inp1 := fx.wrap_full([would_block], {}, [exc], {"label": "image-a:1.0"})
    inp2 := fx.wrap_full([would_block], {}, [exc], {"label": "image-b:2.0"})
    sup1 := gate.suppressed with input as inp1
    sup2 := gate.suppressed with input as inp2
    count(sup1) == 1
    count(sup2) == 1
}

# Regression: input.exceptions entirely undefined (today's default, no
# --exceptions-dir passed) must not change existing block/review behaviour.
test_no_exceptions_key_does_not_break_existing_block if {
    msgs := gate.block with input as fx.wrap([would_block])
    count(msgs) == 1
}

test_no_exceptions_key_does_not_break_existing_review if {
    msgs := gate.review with input as fx.wrap([would_review])
    count(msgs) == 1
}
