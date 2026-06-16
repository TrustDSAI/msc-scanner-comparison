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

# --- Suppression / exception predicates ---------------------------------
#
# An exception is matched (and suppresses a finding) when its cve_id
# matches, its optional package/image scoping match (absent = unscoped,
# matches anything), and it has not expired. Exceptions are read from
# input.exceptions, a flat list loaded from version-controlled YAML
# (see exceptions_loader.py). When input.exceptions is undefined (the
# default, no --exceptions-dir passed), `some exc in input.exceptions`
# simply yields zero matches -- existing block/review behaviour is
# unaffected.

suppressed(finding, image) if {
    some exc in input.exceptions
    exc.cve_id == finding.cve_id
    matches_package(exc, finding)
    matches_image(exc, image)
    not expired(exc, finding)
}

# Unscoped (no package key) matches any package; otherwise exact match.
# Phase 1 ships exact-version-or-unconstrained matching only -- no semver
# range parser (OPA has no semver comparison builtin); range-style
# "<3.9.18" constraints are explicit future work.
matches_package(exc, finding) if {
    not exc.package
}
matches_package(exc, finding) if {
    exc.package == finding.package
}

# Unscoped (no image key) matches any image; otherwise exact label match.
matches_image(exc, image) if {
    not exc.image
}
matches_image(exc, image) if {
    exc.image == image.label
}

# An exception expires past its ISO date, or once a fix is recorded
# (when using expires_when: fix_available -- re-evaluated every run).
expired(exc, finding) if {
    exc.expires
    time.parse_rfc3339_ns(exc.expires) < time.now_ns()
}
expired(exc, finding) if {
    exc.expires_when == "fix_available"
    finding.osv.fix_version != null
    finding.osv.fix_version != ""
}

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
