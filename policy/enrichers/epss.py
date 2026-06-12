"""EPSS enricher.

Two-stage strategy:
    1. If the finding already carries EPSS data (Grype includes it in its
       output), use that. No API call needed.
    2. Otherwise query api.first.org/data/v1/epss.

Fallback policy: ok=False, score=None. P4 requires `epss.score > threshold`;
a missing score does not satisfy that, so P4 fails closed at the EPSS step.
"""

from __future__ import annotations

import asyncio
import json
import urllib.request

from .base import Enricher, EnrichmentResult
from .cache import get_cache


_EPSS_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
_TIMEOUT = 15


class EPSSEnricher(Enricher):
    field_name = "epss"

    async def enrich(self, finding: dict) -> EnrichmentResult:
        # Prefer scanner-provided EPSS to avoid the API call.
        embedded = finding.get("epss")
        if embedded and embedded.get("score") is not None:
            return EnrichmentResult(
                field_name=self.field_name,
                data={
                    "score":      embedded.get("score"),
                    "percentile": embedded.get("percentile"),
                    "as_of":      embedded.get("as_of"),
                },
                ok=True,
            )

        cve_id = finding.get("cve_id", "")
        if not cve_id.startswith("CVE-"):
            return EnrichmentResult(
                field_name=self.field_name,
                data={"score": None, "percentile": None, "as_of": None},
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
            payload = await asyncio.to_thread(self._fetch_sync, cve_id)
        except Exception as exc:  # noqa: BLE001
            result = EnrichmentResult(
                field_name=self.field_name,
                data={"score": None, "percentile": None, "as_of": None},
                ok=False,
                reason=f"EPSS fetch failed: {exc}",
            )
        else:
            result = self._parse(payload)

        cache.put(self.field_name, cve_id, {
            "data":   result.data,
            "ok":     result.ok,
            "reason": result.reason,
        })
        return result

    def _fetch_sync(self, cve_id: str) -> dict:
        url = _EPSS_URL.format(cve_id=cve_id)
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode())

    def _parse(self, payload: dict) -> EnrichmentResult:
        data = payload.get("data") or []
        if not data:
            return EnrichmentResult(
                field_name=self.field_name,
                data={"score": None, "percentile": None, "as_of": None},
                ok=True,
            )
        row = data[0]
        return EnrichmentResult(
            field_name=self.field_name,
            data={
                "score":      _safe_float(row.get("epss")),
                "percentile": _safe_float(row.get("percentile")),
                "as_of":      row.get("date"),
            },
            ok=True,
        )


def _safe_float(value) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
