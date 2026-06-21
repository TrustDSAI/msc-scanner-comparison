"""Shared retry-with-backoff for transient HTTP failures.

Every enricher hits a different external API (NVD, OSV.dev, api.first.org,
CISA's KEV feed) but they all fail the same way under load: 503, 429, 502,
504, or a socket timeout. A single bad CVE lookup should not be treated the
same as a malformed request or a genuine 404 -- retrying those just burns
time and (for rate-limited APIs) quota for no benefit.
"""

from __future__ import annotations

import asyncio
import time
import urllib.error
from typing import Awaitable, Callable, TypeVar

MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 2.0  # seconds; doubles each retry (2s, 4s)

T = TypeVar("T")


def is_transient(exc: Exception) -> bool:
    """True for errors worth retrying: rate-limited, server-side, or timed out."""
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in (429, 500, 502, 503, 504)
    return isinstance(exc, TimeoutError) or "timed out" in str(exc).lower()


async def retry_async(fetch: Callable[[], Awaitable[T]]) -> T:
    """Call an async zero-arg callable, retrying transient failures with
    exponential backoff. Re-raises immediately on a non-transient error
    (e.g. a 404, which several enrichers treat as a meaningful negative
    result, not a failure) or after the last attempt."""
    exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return await fetch()
        except Exception as e:  # noqa: BLE001 - caller decides what's fatal
            exc = e
            if not is_transient(e) or attempt == MAX_RETRIES - 1:
                raise
            await asyncio.sleep(RETRY_BACKOFF_BASE * (2 ** attempt))
    raise exc  # unreachable; satisfies type checkers


def retry_sync(fetch: Callable[[], T]) -> T:
    """Synchronous counterpart for enrichers that fetch outside the event
    loop (e.g. KEV's once-per-process catalog download)."""
    exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            return fetch()
        except Exception as e:  # noqa: BLE001
            exc = e
            if not is_transient(e) or attempt == MAX_RETRIES - 1:
                raise
            time.sleep(RETRY_BACKOFF_BASE * (2 ** attempt))
    raise exc  # unreachable; satisfies type checkers
