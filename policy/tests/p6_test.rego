package vuln.p6_test

import data.vuln.p6
import data.vuln.fixtures as fx
import future.keywords.if

# EOL image: should insta-block, regardless of findings.
test_blocks_when_image_is_eol if {
    p6.block_build with input as {
        "image":    {"eol": true,  "label": "node:14"},
        "findings": [],
        "config":   {"eol_insta_block": true},
    }
}

test_deny_carries_eol_reason if {
    msgs := p6.deny with input as {
        "image":    {"eol": true,  "label": "node:14"},
        "findings": [],
        "config":   {"eol_insta_block": true},
    }
    some m in msgs
    m.eol == true
    m.policy == "p6"
}

# Non-EOL image: delegates to P5_layer.
test_passes_when_non_eol_with_no_findings if {
    not p6.block_build with input as {
        "image":    {"eol": false, "label": "node:20"},
        "findings": [],
    }
}

test_blocks_non_eol_via_delegated_p5 if {
    # critical_full is consensus + Analyzed + OSV advisory + fix + EPSS 0.42
    # P5 with default app config blocks (it's labelled "os" in fixtures,
    # but with EPSS 0.42 it still passes the 0.01 OS threshold).
    p6.block_build with input as {
        "image":    {"eol": false, "label": "production-app"},
        "findings": [fx.critical_full],
    }
}

# Config: eol_insta_block = false reduces P6 to P5 semantics.
test_eol_insta_block_false_falls_through if {
    not p6.block_build with input as {
        "image":    {"eol": true,  "label": "node:14"},
        "findings": [],
        "config":   {"eol_insta_block": false},
    }
}
