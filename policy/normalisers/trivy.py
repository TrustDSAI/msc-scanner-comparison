"""Trivy JSON output adapter."""

from __future__ import annotations

import json
from pathlib import Path

from .schema import Finding, make_finding


def parse(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text())
    findings: list[Finding] = []
    for result in raw.get("Results", []) or []:
        ecosystem = result.get("Type", "")
        for vuln in result.get("Vulnerabilities", []) or []:
            cve_id = vuln.get("VulnerabilityID", "")
            if not cve_id:
                continue
            findings.append(make_finding(
                cve_id=cve_id,
                package=vuln.get("PkgName", ""),
                version=vuln.get("InstalledVersion", ""),
                ecosystem=ecosystem,
                severity=vuln.get("Severity") or "",
                scanner="trivy",
                fix_version=vuln.get("FixedVersion"),
                cwes=vuln.get("CweIDs") or [],
                epss=None,
            ))
    return findings


def os_metadata(path: Path) -> dict:
    """Extract OS-layer metadata from Trivy output.

    Returns a dict with `family`, `name`, and `eosl` (Trivy's
    end-of-service-life flag, sourced from vendor data). Note: EOSL
    here describes the OS distribution layer only. Language-runtime
    versions (e.g. Python 3.8 inside a Bookworm-based image) are not
    captured by this field; that requires a separate EOL data source
    (e.g. endoflife.date).
    """
    raw = json.loads(path.read_text())
    os_block = (raw.get("Metadata") or {}).get("OS") or {}
    return {
        "family": os_block.get("Family", ""),
        "name":   os_block.get("Name", ""),
        "eosl":   bool(os_block.get("EOSL")),
    }
