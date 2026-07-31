"""External enrichment adapters for the policy layer.

Each enricher is responsible for one external data source (NVD, OSV, EPSS,
KEV, ...). All enrichers share the on-disk cache in `cache.py` and conform
to the `Enricher` protocol in `base.py`.

To add a new enrichment source:
    1. Implement an `Enricher` subclass in a new module.
    2. Register it in `ENRICHERS` below.
    3. Add a corresponding field name to `Finding` if you want the policy
       layer to consume it.
"""

from __future__ import annotations

from .base import Enricher, EnrichmentResult
from .nvd import NVDEnricher
from .osv import OSVEnricher
from .epss import EPSSEnricher
from .kev import KEVEnricher


ENRICHERS: list[Enricher] = [
    NVDEnricher(),
    OSVEnricher(),
    EPSSEnricher(),
    KEVEnricher(),
]

_EMPTY_PAYLOADS: dict[str, dict] = {
    "nvd":  {"status": None, "rejected": False, "disputed": False},
    "osv":  {"advisory_found": False, "fix_version": None, "affected_ecosystems": []},
    "epss": {"score": None, "percentile": None, "as_of": None},
    "kev":  {"in_kev": False, "date_added": None, "due_date": None, "ransomware_use": None},
}


def empty_payload(field_name: str) -> dict:
    """Default-empty payload for a skipped enrichment (schema stays uniform)."""
    return _EMPTY_PAYLOADS.get(field_name, {})


__all__ = [
    "Enricher",
    "EnrichmentResult",
    "ENRICHERS",
    "NVDEnricher",
    "OSVEnricher",
    "EPSSEnricher",
    "KEVEnricher",
    "empty_payload",
]
