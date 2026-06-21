"""OSV enricher.

Queries OSV.dev by CVE identifier (GET /v1/vulns/{cve_id}). This is
simpler and more reliable than the package@version query path:
    - One request per unique CVE (cache keyed by CVE ID).
    - No fragile ecosystem-string mapping between scanner output and OSV's
      ecosystem taxonomy (Debian:11 vs debian, etc.).
    - Equivalent semantics for P4's validity check: "is this CVE recognised
      by OSV as a real, ecosystem-tracked vulnerability?"

The advisory's `affected[].package.ecosystem` list is returned so policies
can still gate on ecosystem coverage if needed; for the package-installed
validation, OSV's presence is sufficient.

Fallback policy on failure: ok=False, advisory_found=False. P4 already
treats missing OSV data as non-blocking, so this is fail-open at the
enrichment step.
"""

from __future__ import annotations

import asyncio
import json
import urllib.error
import urllib.request

from .base import Enricher, EnrichmentResult
from .cache import get_cache
from ._retry import retry_async


_OSV_VULNS_URL = "https://api.osv.dev/v1/vulns/{cve_id}"
_TIMEOUT = 15


class OSVEnricher(Enricher):
    field_name = "osv"

    async def enrich(self, finding: dict) -> EnrichmentResult:
        cve_id = finding.get("cve_id", "")
        if not cve_id.startswith("CVE-"):
            return EnrichmentResult(
                field_name=self.field_name,
                data=_empty(),
                ok=False,
                reason="non-CVE identifier",
            )

        cache = get_cache()
        cached = cache.get(self.field_name, cve_id)
        if cached is not None:
            return EnrichmentResult(
                field_name=self.field_name,
                data=cached["data"],
                ok=cached.get("ok", True),
                reason=cached.get("reason", ""),
            )

        try:
            payload = await retry_async(lambda: asyncio.to_thread(self._fetch_sync, cve_id))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                # OSV has no record. That's a meaningful negative result.
                result = EnrichmentResult(
                    field_name=self.field_name,
                    data=_empty(),
                    ok=True,
                )
            else:
                result = EnrichmentResult(
                    field_name=self.field_name,
                    data=_empty(),
                    ok=False,
                    reason=f"OSV HTTP {exc.code}",
                )
        except Exception as exc:  # noqa: BLE001
            result = EnrichmentResult(
                field_name=self.field_name,
                data=_empty(),
                ok=False,
                reason=f"OSV fetch failed: {exc}",
            )
        else:
            result = _parse_advisory(payload)

        cache.put(self.field_name, cve_id, {
            "data":   result.data,
            "ok":     result.ok,
            "reason": result.reason,
        })
        return result

    def _fetch_sync(self, cve_id: str) -> dict:
        url = _OSV_VULNS_URL.format(cve_id=cve_id)
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())


def _empty() -> dict:
    return {"advisory_found": False, "fix_version": None, "affected_ecosystems": []}


def _parse_advisory(advisory: dict) -> EnrichmentResult:
    fix_version = _extract_fix_version(advisory)
    ecosystems = _extract_ecosystems(advisory)
    return EnrichmentResult(
        field_name="osv",
        data={
            "advisory_found":      True,
            "fix_version":         fix_version,
            "affected_ecosystems": ecosystems,
        },
        ok=True,
    )


def _extract_fix_version(advisory: dict) -> str | None:
    """Return the first fixed-version recorded across any affected entry."""
    for affected in advisory.get("affected") or []:
        for r in affected.get("ranges") or []:
            for event in r.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _extract_ecosystems(advisory: dict) -> list[str]:
    ecosystems: list[str] = []
    for affected in advisory.get("affected") or []:
        eco = (affected.get("package") or {}).get("ecosystem", "")
        if eco and eco not in ecosystems:
            ecosystems.append(eco)
    return ecosystems
