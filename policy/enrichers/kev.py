"""CISA Known Exploited Vulnerabilities (KEV) catalog enricher.

The KEV catalog is CISA's authoritative list of CVEs being actively
exploited in the wild. Membership in this catalog is direct empirical
evidence of exploitation, not a probabilistic estimate (which is what
EPSS provides). KEV is therefore the strongest signal a policy can use:
if a CVE is in KEV, attackers are using it right now.

The catalog is published as a single JSON document and updated by CISA
when new actively-exploited CVEs are identified. It is free, has no
rate limit, and requires no authentication.

URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

This enricher downloads the full catalog once per run, caches it, and
performs O(1) membership lookups per CVE.

Output per finding:
    "kev": {
        "in_kev":         bool,
        "date_added":     "YYYY-MM-DD" | null,
        "due_date":       "YYYY-MM-DD" | null,   # CISA-recommended remediation deadline
        "ransomware_use": "Known" | "Unknown" | null
    }

Fallback policy on failure: ok=False, in_kev=False. P7 treats a missing
KEV signal as "not in KEV" (fail-open at the enrichment step). The cost
of missing a KEV hit is the same as never having had KEV: the build
falls back to the severity-based gates, which is the pre-P7 behaviour.
"""

from __future__ import annotations

import json
import urllib.request

from .base import Enricher, EnrichmentResult
from .cache import get_cache


_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_TIMEOUT = 30

# Cached lookup of the full KEV catalog (loaded once per process).
_KEV_INDEX: dict[str, dict] | None = None


def _load_kev_catalog() -> dict[str, dict]:
    """Fetch the full KEV catalog and build an index keyed by CVE ID.

    The catalog itself is cached on disk under the shared cache so
    repeated runs do not re-download it. Within a single process the
    catalog is held in `_KEV_INDEX` and used for O(1) lookups.
    """
    global _KEV_INDEX
    if _KEV_INDEX is not None:
        return _KEV_INDEX

    cache = get_cache()
    cached = cache.get("kev", "catalog")
    if cached is not None:
        catalog = cached
    else:
        try:
            with urllib.request.urlopen(_KEV_URL, timeout=_TIMEOUT) as resp:
                catalog = json.loads(resp.read().decode())
            cache.put("kev", "catalog", catalog)
        except Exception:  # noqa: BLE001
            catalog = {"vulnerabilities": []}

    _KEV_INDEX = {
        entry["cveID"]: entry
        for entry in catalog.get("vulnerabilities", [])
        if entry.get("cveID")
    }
    return _KEV_INDEX


class KEVEnricher(Enricher):
    field_name = "kev"

    async def enrich(self, finding: dict) -> EnrichmentResult:
        cve_id = finding.get("cve_id", "")
        if not cve_id.startswith("CVE-"):
            return EnrichmentResult(
                field_name=self.field_name,
                data=_empty(),
                ok=False,
                reason="non-CVE identifier",
            )

        try:
            index = _load_kev_catalog()
        except Exception as exc:  # noqa: BLE001
            return EnrichmentResult(
                field_name=self.field_name,
                data=_empty(),
                ok=False,
                reason=f"KEV catalog fetch failed: {exc}",
            )

        entry = index.get(cve_id)
        if not entry:
            return EnrichmentResult(
                field_name=self.field_name,
                data=_empty(),
                ok=True,
            )

        return EnrichmentResult(
            field_name=self.field_name,
            data={
                "in_kev":         True,
                "date_added":     entry.get("dateAdded"),
                "due_date":       entry.get("dueDate"),
                "ransomware_use": entry.get("knownRansomwareCampaignUse"),
            },
            ok=True,
        )


def _empty() -> dict:
    return {
        "in_kev":         False,
        "date_added":     None,
        "due_date":       None,
        "ransomware_use": None,
    }
