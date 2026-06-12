"""N-way cross-scanner finding merge.

Adding a new scanner requires no changes here: pass its findings to `merge`
alongside the existing ones.
"""

from __future__ import annotations

from collections.abc import Iterable

from .schema import Finding, higher_severity, severity_rank


def _key(f: Finding) -> tuple[str, str]:
    """Cross-tool deduplication key: (cve_id, package_name).

    Version is excluded; if scanners disagree on installed version the
    secondary version is preserved in `version_alternatives` rather than
    forking the finding, which would distort consensus counts.
    """
    return (f["cve_id"], f["package"])


def merge(*scanner_findings: Iterable[Finding],
          classifier=None) -> list[Finding]:
    """Merge findings from any number of scanners.

    Each argument is an iterable of Finding records produced by one
    scanner's adapter. Findings sharing a (cve_id, package) key are merged
    by taking:
        - the union of `detected_by`
        - the more severe of the two `severity` tiers
        - the first non-null `fix_version`
        - the first non-null `epss` block
        - the union of `cwes`
    Disagreements on `version` are recorded in `version_alternatives`.
    """
    by_key: dict[tuple[str, str], Finding] = {}

    for source in scanner_findings:
        for f in source:
            k = _key(f)
            if k not in by_key:
                # Copy so we can mutate without affecting the input list.
                by_key[k] = {**f, "cwes": list(f.get("cwes") or [])}
                continue

            existing = by_key[k]
            _merge_into(existing, f)

    results = sorted(
        by_key.values(),
        key=lambda f: (-severity_rank(f["severity"]), f["cve_id"], f["package"]),
    )

    if classifier is not None:
        # Policies only branch on CRITICAL findings (P5 layer-aware gating).
        # Skip non-CRITICAL to avoid quadratic LLM calls on large datasets;
        # they get a "skipped" sentinel so the schema stays uniform.
        for f in results:
            if f.get("severity") == "CRITICAL":
                label = classifier.classify(f)
                f["layer"]        = label.layer
                f["layer_source"] = label.source
            else:
                f["layer"]        = "skipped"
                f["layer_source"] = classifier.name

    return results


def _merge_into(target: Finding, src: Finding) -> None:
    for scanner in src.get("detected_by") or []:
        if scanner not in target["detected_by"]:
            target["detected_by"].append(scanner)

    target["severity"] = higher_severity(target["severity"], src["severity"])

    if not target.get("fix_version") and src.get("fix_version"):
        target["fix_version"] = src["fix_version"]

    for cwe in src.get("cwes") or []:
        if cwe not in target["cwes"]:
            target["cwes"].append(cwe)

    if not target.get("epss") and src.get("epss"):
        target["epss"] = src["epss"]

    if src.get("version") and src["version"] != target.get("version"):
        alts = target.setdefault("version_alternatives", [])
        if src["version"] not in alts:
            alts.append(src["version"])
