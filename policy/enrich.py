"""Enrich a normalised policy input with all registered enrichers.

Each enricher (NVD, OSV, EPSS, ...) attaches a sub-document to every finding
under its `field_name`. Enrichers are auto-discovered via the ENRICHERS
registry in `enrichers/__init__.py`; adding a new enricher is one new module.

On per-finding enrichment failure the orchestrator falls back to the
enricher's documented default (typically null fields) and records the
reason in `enrichment_log` on the finding, so the policy layer can branch
on enrichment availability without hiding the cause.

Usage:
    python enrich.py --in policy_input.json --out enriched_input.json

For large inputs, pass `--only-critical` to enrich only CRITICAL findings.
Other findings get the enrichers' default-empty payloads so the schema
remains uniform.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from enrichers import ENRICHERS, empty_payload
from enrichers.cache import configure as configure_cache


async def _enrich_one(finding: dict, *, restrict_to_critical: bool) -> dict:
    if restrict_to_critical and finding.get("severity") != "CRITICAL":
        # Attach default-empty payloads so downstream schema is uniform.
        for er in ENRICHERS:
            finding.setdefault(er.field_name, empty_payload(er.field_name))
        return finding

    log: list[dict] = []
    for er in ENRICHERS:
        result = await er.enrich(finding)
        finding[er.field_name] = result.data
        if not result.ok:
            log.append({"source": er.field_name, "reason": result.reason})
    if log:
        finding["enrichment_log"] = log
    return finding


async def enrich_async(payload: dict, *, restrict_to_critical: bool) -> dict:
    payload["findings"] = [
        await _enrich_one(f, restrict_to_critical=restrict_to_critical)
        for f in payload["findings"]
    ]
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in",  dest="in_path", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, default=Path(".cache/enrich"))
    parser.add_argument("--only-critical", action="store_true",
                        help="enrich only findings with severity=CRITICAL")
    args = parser.parse_args()

    configure_cache(args.cache)
    payload = json.loads(args.in_path.read_text())
    payload = asyncio.run(
        enrich_async(payload, restrict_to_critical=args.only_critical)
    )
    args.out.write_text(json.dumps(payload, indent=2))

    crit = sum(1 for f in payload["findings"] if f.get("severity") == "CRITICAL")
    failures = sum(1 for f in payload["findings"] if f.get("enrichment_log"))
    print(f"{args.out}: {len(payload['findings'])} findings ({crit} CRITICAL, "
          f"{failures} with at least one enrichment failure)")


if __name__ == "__main__":
    main()
