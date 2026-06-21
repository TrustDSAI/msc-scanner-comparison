# Enrichment

Four enrichers, each attaching one field to a CRITICAL/HIGH Finding.
Defined in `enrichers/`, all implementing the `Enricher` protocol
(`enrichers/base.py`): take one finding, return an `EnrichmentResult`
(`field_name`, `data`, `ok`, `reason`).

| Enricher | Field | Source | Fallback on failure |
|---|---|---|---|
| `nvd.py` | `.nvd` | NIST NVD REST API | `status: null` (fails closed at the corroboration step) |
| `osv.py` | `.osv` | OSV.dev (`GET /v1/vulns/{cve}`) | `advisory_found: false` |
| `epss.py` | `.epss` | api.first.org, **or** Grype's embedded EPSS if present | `score: null` |
| `kev.py` | `.kev` | CISA's KEV catalog (one bulk JSON download, cached) | `in_kev: false` |

All four are fail-soft: a failed enrichment never aborts the run, it just
means that one finding lacks that signal and the policy treats it
conservatively (the table above shows what "missing" means per field).

## EPSS: embedded vs. live, and why it matters

`epss.py` **prefers Grype's embedded EPSS score** over a live API call,
if Grype's scan output already carries one (`normalisers/grype.py`'s
`_extract_epss`). This means a finding's EPSS score can be **frozen at
whatever Grype's vulnerability-DB snapshot had on the day the scan ran**,
not the live, current score — `api.first.org` is never even queried for
that finding.

This was the root cause of a real debugging trail this session:
`CVE-2023-32314` (vm2 sandbox escape) showed EPSS 0.70 (`as_of:
2026-03-29`) every single re-run, regardless of cache clears, because that
value was embedded in `data/raw/grype/bkimminich_juice-shop_grype.json`
from the original scan — re-running `evaluate_all.py` re-reads that same
raw scanner JSON every time, it does not re-scan the image. The *actual*
live score (fetched manually via `curl` on 2026-06-20) was 0.056 — a 92%
drop in three months. If you need a finding's EPSS to reflect today's
score rather than the scan snapshot's, that path doesn't exist yet; it
would require either re-scanning with Grype or stripping the embedded
score before enrichment so `epss.py` falls through to the live API call.

## Retry behavior

All four enrichers retry transient failures (503/429/502/504/timeout) via
the shared `enrichers/_retry.py` helper, added after a live NVD outage
during a dataset re-run silently degraded gate verdicts with no signal it
had happened (`nvd.status: null` for ~100 of 135 unique CRITICAL CVEs in
one run). A non-transient error (e.g. OSV's 404, a meaningful "no record"
result, not a failure) is never retried — `is_transient()` is the single
predicate shared by every enricher, so this can't drift between them.

- `retry_async()` — used by `nvd.py`, `osv.py`, `epss.py`. NVD's call site
  also holds its own `asyncio.Lock` for rate-limit pacing (5 req/30s
  without `NVD_API_KEY`, ~50/30s with it); the lock wraps only the actual
  network attempt + pacing sleep, not the inter-retry backoff, so one
  flaky CVE doesn't stall every other concurrent enrichment.
- `retry_sync()` — used by `kev.py`'s one-time bulk catalog download
  (synchronous, not per-finding, no lock needed).

## Caching

`enrichers/cache.py`'s `Cache` is a flat on-disk JSON cache keyed by
`(source, identifier)` — no TTL by default, since the scanner data it's
keyed against (a CVE ID) doesn't change identity over time even though
the *enrichment result* (EPSS, NVD status) can. Configured once via
`configure_cache()` at process start (`POLICY_GATE_CACHE` env var, or
`--cache` CLI flag). Clearing it (`rm -rf .cache/enrich`) forces every
enrichment to hit the live APIs again on the next run — useful for
getting a dataset re-run onto one consistent point-in-time snapshot
rather than a mix of old-cached and newly-fetched values.
