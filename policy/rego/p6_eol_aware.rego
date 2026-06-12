# P6: EOL-aware gating.
#
# Adds deployment-context awareness to the policy stack. When the image is
# end-of-life upstream AND eol_insta_block is enabled, the build is blocked
# immediately without consulting individual CVEs. EOL images do not receive
# security patches; the cost of further per-CVE triage is unjustified when
# the entire base will never be fixed.
#
# Otherwise (non-EOL image, or eol_insta_block disabled), the policy
# delegates to P5_layer.
#
# Config schema:
#     {
#       "eol_insta_block": true,     # false reduces P6 to a P5_layer pass-through
#       "app":             { ... },  # passed through to P5
#       "os":              { ... }   # passed through to P5
#     }
#
# Input must include `image.eol: bool` at the top level.

package vuln.p6

import data.vuln.lib
import data.vuln.p5
import future.keywords.if
import future.keywords.in

default block_build := false

eol_insta_block := lib.config_value("eol_insta_block", true)

# Rule 1: EOL short-circuit.
block_build if {
    eol_insta_block
    input.image.eol == true
}

# Rule 2: delegate to P5_layer in every other case (non-EOL image, or
# EOL image when the short-circuit is disabled).
block_build if {
    not eol_short_circuit_fires
    p5.block_build
}

eol_short_circuit_fires if {
    eol_insta_block
    input.image.eol == true
}

# Deny: EOL block carries a single explicit reason.
deny contains msg if {
    eol_short_circuit_fires
    msg := {
        "policy":   "p6",
        "image":    input.image.label,
        "reason":   "image is end-of-life upstream; insta-block",
        "eol":      true,
    }
}

# Deny: when P5 is the active gate, forward each of its messages.
deny contains msg if {
    not eol_short_circuit_fires
    some d in p5.deny
    msg := object.union(d, {"policy": "p6", "delegated_from": "p5"})
}
