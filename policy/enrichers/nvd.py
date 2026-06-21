"""NVD enricher.

Fetches CVE status, rejected flag, and disputed flag from the NIST NVD REST
API. Requires the NVD_API_KEY environment variable for production rate
limits; without it the API allows 5 requests per 30 seconds, which is
sufficient for the 9-image dissertation experiment but not for production.

Fallback policy on failure: ok=False, status=None. The P4 policy treats a
missing or non-Analyzed NVD status as non-blocking, so this is conservative
(fail-open at the enrichment step, falling back to scanner-native logic).
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import urllib.request
import urllib.error
import json

from .base import Enricher, EnrichmentResult
from .cache import get_cache
from ._retry import is_transient, MAX_RETRIES as _MAX_RETRIES, RETRY_BACKOFF_BASE as _RETRY_BACKOFF_BASE


_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
_TIMEOUT = 15
_RATE_LIMIT_SLEEP_NO_KEY = 6.5  # 5 req / 30s -> 6.5s between calls when no key
_RATE_LIMIT_SLEEP_WITH_KEY = 0.6


class NVDEnricher(Enricher):
    field_name = "nvd"

    def __init__(self) -> None:
        self._api_key = os.environ.get("NVD_API_KEY")
        self._lock = asyncio.Lock()  # serialises requests for rate limiting

    async def enrich(self, finding: dict) -> EnrichmentResult:
        cve_id = finding.get("cve_id", "")
        if not cve_id.startswith("CVE-"):
            return EnrichmentResult(
                field_name=self.field_name,
                data={"status": None, "rejected": False, "disputed": False},
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

        # Each network attempt (and its rate-limit pacing sleep) is
        # serialized under the lock, like before. The inter-retry backoff
        # is deliberately NOT held under the lock: it's this finding's own
        # error-recovery wait, not part of the shared rate-limit budget, so
        # holding the lock through it would stall every other concurrent
        # enrichment for up to ~6s on a single flaky CVE for no reason.
        exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            async with self._lock:
                try:
                    payload = await asyncio.to_thread(self._fetch_sync, cve_id)
                    exc = None
                except Exception as e:  # noqa: BLE001 - we want to fail soft
                    exc = e
                await asyncio.sleep(
                    _RATE_LIMIT_SLEEP_WITH_KEY if self._api_key else _RATE_LIMIT_SLEEP_NO_KEY
                )
            if exc is None or not is_transient(exc) or attempt == _MAX_RETRIES - 1:
                break
            await asyncio.sleep(_RETRY_BACKOFF_BASE * (2 ** attempt))

        if exc is not None:
            result = EnrichmentResult(
                field_name=self.field_name,
                data={"status": None, "rejected": False, "disputed": False},
                ok=False,
                reason=f"NVD fetch failed: {exc}",
            )
        else:
            result = self._parse(cve_id, payload)

        cache.put(self.field_name, cve_id, {
            "data":   result.data,
            "ok":     result.ok,
            "reason": result.reason,
        })
        return result

    def _fetch_sync(self, cve_id: str) -> dict:
        url = _NVD_URL.format(cve_id=cve_id)
        req = urllib.request.Request(url)
        if self._api_key:
            req.add_header("apiKey", self._api_key)
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())

    def _parse(self, cve_id: str, payload: dict) -> EnrichmentResult:
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return EnrichmentResult(
                field_name=self.field_name,
                data={"status": "Not Found", "rejected": False, "disputed": False},
                ok=True,
            )
        cve = (vulns[0] or {}).get("cve") or {}
        status = cve.get("vulnStatus", "")
        rejected = status == "Rejected"
        descriptions = cve.get("descriptions") or []
        first_desc = (descriptions[0] or {}).get("value", "") if descriptions else ""
        disputed = "** DISPUTED **" in first_desc
        return EnrichmentResult(
            field_name=self.field_name,
            data={"status": status, "rejected": rejected, "disputed": disputed},
            ok=True,
        )
