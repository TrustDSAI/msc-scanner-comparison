# Shared predicates and helpers for the vulnerability gating policy bundle.
#
# Policies compose these predicates rather than duplicating their conditions.
# Adding a new policy is a matter of selecting the predicates that compose it
# and writing a thin wrapper in vuln.<name>.

package vuln.lib

import future.keywords.if
import future.keywords.in

# --- Severity predicates ------------------------------------------------

is_critical(finding) if finding.severity == "CRITICAL"

is_at_least(finding, tier) if {
    rank := {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    rank[finding.severity] >= rank[tier]
}

# --- Scanner predicates -------------------------------------------------

has_fix(finding) if {
    finding.fix_version != null
    finding.fix_version != ""
}

is_consensus(finding) if count(finding.detected_by) > 1

detected_by_all(finding, required_scanners) if {
    every s in required_scanners {
        s in finding.detected_by
    }
}

# --- Layer predicates ---------------------------------------------------

is_app(finding) if finding.layer == "app"

is_os(finding) if finding.layer == "os"

is_unknown_layer(finding) if {
    not finding.layer
}

is_unknown_layer(finding) if {
    finding.layer == "unknown"
}

# --- NVD predicates ----------------------------------------------------

nvd_validated(finding) if {
    finding.nvd.status == "Analyzed"
    finding.nvd.rejected == false
    finding.nvd.disputed == false
}

# Permissive NVD acceptance: status is in a configured allow-set.
nvd_status_in(finding, allowed_statuses) if {
    finding.nvd.status in allowed_statuses
    finding.nvd.rejected == false
    finding.nvd.disputed == false
}

nvd_rejected(finding) if finding.nvd.rejected == true

nvd_disputed(finding) if finding.nvd.disputed == true

# --- OSV predicates ----------------------------------------------------

osv_confirms_advisory(finding) if finding.osv.advisory_found == true

osv_has_fix(finding) if {
    finding.osv.fix_version != null
    finding.osv.fix_version != ""
}

# --- EPSS predicates ---------------------------------------------------

epss_score(finding) := finding.epss.score

epss_above(finding, threshold) if {
    finding.epss.score > threshold
}

# --- KEV predicates (P7) ----------------------------------------------

# True when CISA's Known Exploited Vulnerabilities catalog lists this CVE.
in_kev(finding) if finding.kev.in_kev == true

# --- Severity predicates (extended for P7) ----------------------------

is_severity(finding, tier) if finding.severity == tier

# --- Config helpers ----------------------------------------------------

# Resolve a config value at input.config.<key>, falling back to a fallback.
config_value(key, fallback) := v if {
    v := input.config[key]
} else := fallback

# --- Message construction ----------------------------------------------

# Build a structured deny message. Policies pass the policy name and any
# policy-specific extra fields; the base shape is consistent across policies
# so downstream consumers can rely on the schema.
make_msg(finding, policy_name, reason, extras) := msg if {
    base := {
        "policy":      policy_name,
        "cve_id":      finding.cve_id,
        "package":     finding.package,
        "version":     finding.version,
        "severity":    finding.severity,
        "detected_by": finding.detected_by,
        "fix_version": finding.fix_version,
        "layer":       finding.layer,
        "reason":      reason,

        # Image-lifecycle context attached to every deny entry.
        # EOL is reported, not gated: downstream CI logic decides whether
        # to treat an EOL image differently. This keeps lifecycle data
        # visible in the audit trail without conflating it with the CVE
        # gating decision.
        "image_label":      object.get(object.get(input, "image", {}), "label", ""),
        "image_eol":        object.get(object.get(input, "image", {}), "eol", false),
        "image_eol_source": object.get(object.get(input, "image", {}), "eol_source", ""),
    }
    msg := object.union(base, extras)
}
