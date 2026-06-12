# Shared test fixtures. Test files import from here rather than redefining
# the same finding structures per policy.

package vuln.fixtures

import future.keywords.if

# --- Canonical CRITICAL finding ----------------------------------------
# All P4 conditions met. Mutate one field to produce policy-specific
# negative variants.
critical_full := {
    "cve_id":      "CVE-2024-AAAA",
    "package":     "openssl",
    "version":     "1.1.1k",
    "ecosystem":   "debian",
    "severity":    "CRITICAL",
    "detected_by": ["trivy", "grype"],
    "fix_version": "1.1.1l",
    "cwes":        ["CWE-79"],
    "layer":       "os",
    "layer_source": "rule",
    "nvd": {
        "status":   "Analyzed",
        "rejected": false,
        "disputed": false,
    },
    "osv": {
        "advisory_found": true,
        "fix_version":    "1.1.1l",
    },
    "epss": {"score": 0.42, "percentile": 0.97, "as_of": "2026-03-29"},
}

# --- Variants ----------------------------------------------------------

critical_no_fix := json.patch(critical_full, [
    {"op": "replace", "path": "/fix_version",         "value": null},
    {"op": "replace", "path": "/osv/fix_version",     "value": null},
])

critical_single_scanner := json.patch(critical_full, [
    {"op": "replace", "path": "/detected_by", "value": ["trivy"]},
])

high_consensus := json.patch(critical_full, [
    {"op": "replace", "path": "/severity", "value": "HIGH"},
])

low_finding := json.patch(critical_full, [
    {"op": "replace", "path": "/severity",    "value": "LOW"},
    {"op": "replace", "path": "/detected_by", "value": ["trivy"]},
])

# --- Helpers -----------------------------------------------------------

# Mutate critical_full by patching one path. Used in negative test cases
# to isolate exactly one failing condition.
mutate(path, value) := result if {
    result := json.patch(critical_full, [{
        "op":    "replace",
        "path":  path,
        "value": value,
    }])
}

# Wrap one or more findings as the input document the policies expect.
wrap(findings) := {"findings": findings}

# As above, but with a config block for policies that read input.config.
wrap_with_config(findings, config) := {
    "findings": findings,
    "config":   config,
}
