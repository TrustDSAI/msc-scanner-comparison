"""On-disk JSON cache keyed by (source, identifier).

Shared by all enrichers. Cache hits skip the HTTP call entirely, which
matters because the same CVE typically appears across many images.

The cache is content-addressable by `(source, key)`; no TTL by default
(scanner outputs are pinned to a single date, so the cache for that
snapshot does not need to expire). Callers that want freshness control
can pass `ttl_seconds` to `get` or `delete` an entry manually.
"""

from __future__ import annotations

import json
import time
from hashlib import sha256
from pathlib import Path
from typing import Any


class Cache:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, source: str, key: str) -> Path:
        digest = sha256(key.encode()).hexdigest()[:24]
        return self.root / source / f"{digest}.json"

    def get(self, source: str, key: str, *, ttl_seconds: int | None = None) -> dict | None:
        path = self._path(source, key)
        if not path.exists():
            return None
        if ttl_seconds is not None and (time.time() - path.stat().st_mtime) > ttl_seconds:
            return None
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

    def put(self, source: str, key: str, value: dict[str, Any]) -> None:
        path = self._path(source, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2))


# Module-level singleton; enrichers grab it via get_cache().
_default_cache: Cache | None = None


def configure(root: Path) -> Cache:
    """Initialise the shared cache at the given root path."""
    global _default_cache
    _default_cache = Cache(root)
    return _default_cache


def get_cache() -> Cache:
    if _default_cache is None:
        configure(Path(".cache/enrich"))
    assert _default_cache is not None
    return _default_cache
