"""Unified finding schema and severity helpers.

Kept deliberately small. If a future scanner produces information that does
not fit one of these fields, extend this module rather than the adapters.
"""

from __future__ import annotations

from typing import Any, TypedDict


_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


class EPSS(TypedDict, total=False):
    score: float
    percentile: float
    as_of: str


class Finding(TypedDict, total=False):
    cve_id: str
    package: str
    version: str
    ecosystem: str
    severity: str          # CRITICAL | HIGH | MEDIUM | LOW
    detected_by: list[str]
    fix_version: str | None
    cwes: list[str]
    epss: EPSS | None
    layer: str             # "app" | "os" | "unknown"
    layer_source: str      # which classifier produced the label


def normalise_severity(raw: str | None) -> str:
    """Map a scanner-reported severity string to one of the four canonical
    tiers. NEGLIGIBLE and UNKNOWN fold into LOW.
    """
    if not raw:
        return "LOW"
    sev = raw.strip().upper()
    if sev in _SEV_RANK:
        return sev
    return "LOW"  # NEGLIGIBLE, UNKNOWN, empty, anything unexpected


def higher_severity(a: str, b: str) -> str:
    """Return the more severe of two normalised severity tiers."""
    return a if _SEV_RANK.get(a, 0) >= _SEV_RANK.get(b, 0) else b


def severity_rank(severity: str) -> int:
    return _SEV_RANK.get(severity, 0)


def make_finding(
    *,
    cve_id: str,
    package: str,
    version: str,
    ecosystem: str,
    severity: str,
    scanner: str,
    fix_version: str | None = None,
    cwes: list[str] | None = None,
    epss: dict[str, Any] | None = None,
) -> Finding:
    """Construct a Finding with the given scanner as the sole detector."""
    return {
        "cve_id":      cve_id,
        "package":     package,
        "version":     version,
        "ecosystem":   ecosystem,
        "severity":    normalise_severity(severity),
        "detected_by": [scanner],
        "fix_version": fix_version or None,
        "cwes":        list(cwes or []),
        "epss":        epss,
    }
