"""Common protocol for enrichment adapters.

An Enricher takes one finding, looks up additional data from its source
(possibly cached), and returns a dict that gets merged into the finding
under a specific key (e.g. "nvd", "osv", "epss").

Failure handling is the enricher's responsibility. On unrecoverable failure
the enricher should return an EnrichmentResult with `ok=False` and a reason
string; the orchestrator records this on the finding so the policy layer
can branch on it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class EnrichmentResult:
    """Outcome of one enrichment call for one finding."""

    field_name: str             # "nvd", "osv", "epss", ...
    data: dict[str, Any]        # the enrichment payload to attach
    ok: bool = True
    reason: str = ""            # populated when ok=False


class Enricher(ABC):
    """Protocol every enricher implements."""

    #: Key under which the enricher's output is attached to the finding.
    field_name: str = ""

    @abstractmethod
    async def enrich(self, finding: dict) -> EnrichmentResult:
        """Look up enrichment data for one finding."""
        raise NotImplementedError
