"""Scanner-output normalisers.

Each module in this package implements one scanner adapter: a callable that
takes a path to that scanner's raw JSON output and returns a list of
findings in the unified schema documented in `schema.py`.

To add a new scanner:
    1. Implement a `parse(path: Path) -> list[Finding]` function in a new
       module under this package.
    2. Register it in `ADAPTERS` below, or pass it explicitly to the merge
       step from your own code.

The unified schema is intentionally minimal. Scanner-specific extras stay
out of the policy input; if downstream needs them, add them to the schema
in one place rather than each adapter.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from .schema import Finding
from .trivy import parse as parse_trivy
from .grype import parse as parse_grype


Adapter = Callable[[Path], list[Finding]]

# Built-in adapter registry. Custom callers may pass any callable matching
# the Adapter signature to the merge step; this is just a convenience for
# the CLI.
ADAPTERS: dict[str, Adapter] = {
    "trivy": parse_trivy,
    "grype": parse_grype,
}


__all__ = ["Adapter", "ADAPTERS", "Finding", "parse_trivy", "parse_grype"]
