"""Grype JSON output adapter.

Grype reports many language-ecosystem vulnerabilities under GHSA identifiers.
We canonicalise to the first CVE alias from relatedVulnerabilities when one
exists so that cross-tool deduplication against Trivy's CVE-prefixed
identifiers works.
"""

from __future__ import annotations

import json
from pathlib import Path

from .schema import Finding, make_finding


def _canonical_cve_id(match: dict) -> str:
    primary = (match.get("vulnerability") or {}).get("id", "")
    if primary.startswith("CVE-"):
        return primary
    for related in match.get("relatedVulnerabilities") or []:
        rid = related.get("id", "")
        if rid.startswith("CVE-"):
            return rid
    return primary  # Keep GHSA identifier as a last resort.


def _extract_epss(vuln: dict) -> dict | None:
    entries = vuln.get("epss") or []
    if not entries:
        return None
    e = entries[0]
    return {
        "score":      e.get("epss"),
        "percentile": e.get("percentile"),
        "as_of":      e.get("date"),
    }


def parse(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text())
    findings: list[Finding] = []

    for match in raw.get("matches", []) or []:
        cve_id = _canonical_cve_id(match)
        if not cve_id:
            continue

        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        cwes = [c.get("cwe") for c in (vuln.get("cwes") or []) if c.get("cwe")]

        findings.append(make_finding(
            cve_id=cve_id,
            package=artifact.get("name", ""),
            version=artifact.get("version", ""),
            ecosystem=artifact.get("type", ""),
            severity=vuln.get("severity") or "",
            scanner="grype",
            fix_version=fix_versions[0] if fix_versions else None,
            cwes=cwes,
            epss=_extract_epss(vuln),
        ))
    return findings
