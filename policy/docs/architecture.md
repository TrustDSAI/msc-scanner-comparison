# Architecture

One image goes through a fixed pipeline; every stage's output feeds the next.

```
container image
      │
      ▼
  scan (Trivy + Grype)              raw scanner JSON
      │
      ▼
  normalise (normalisers/)          one Finding schema, deduped, detected_by[] per CVE
      │
      ▼
  classify layer (classifiers/)     attaches Finding.layer: "app" | "os" | "unknown"
      │
      ▼
  enrich CRITICAL+HIGH (enrichers/) attaches .nvd, .osv, .epss, .kev per Finding
      │
      ▼
  opa eval (rego/p_gate.rego)       block / review / suppressed sets
      │
      ▼
  verdict + report formatter        json | markdown | pr-comment | sarif | junit
```

Only CRITICAL and HIGH findings are enriched (`enrich_critical_and_high` in
`policy_gate.py`) — LOW/MEDIUM never reach a gate decision, so enriching them
would just burn API calls.

## Run modes

Three callers share the same `run_gate()` function in `policy_gate.py`:

| Caller | Entry point | Used by |
|---|---|---|
| CLI | `policy_gate.py --image <ref>` | local runs, the Docker image's default entrypoint |
| API server | `api.py` (`POST /gate`) | the API mode (`POLICY_GATE_MODE=api`) |
| GitHub composite action | `.github/actions/policy-gate/action.yml` | any consuming repo's CI |

All three produce the identical verdict shape — see `Finding`/`Tier`/`Decision`
in [`CONTEXT.md`](../../CONTEXT.md) for the vocabulary.

## Where logic lives, and why

- **Policy logic is Rego, not Python.** `policy_gate.py` treats `block`,
  `review`, `suppressed`, `tier`, and `reason` as opaque values returned by
  `opa eval` — it never re-derives "is this corroborated" or similar in
  Python. Swapping `--rego-dir`/`--policy-package` replaces the entire
  decision logic without touching the orchestration code.
- **Enrichment failure is always fail-soft.** Every enricher
  (`enrichers/nvd.py`, `epss.py`, `osv.py`, `kev.py`) returns
  `EnrichmentResult(ok=False, ...)` on failure rather than raising — a
  flaky external API degrades one finding's data, never aborts the run.
  All four retry transient failures (503/429/timeout) via the shared
  `enrichers/_retry.py` helper before giving up.
- **Classification's effect is deliberately narrow.** `Finding.layer` only
  changes the EPSS floor for non-corroborated CRITICALs in `review`
  (`review_critical_min_epss` in `p_gate.rego`). It never affects `block`,
  never affects a fully corroborated finding, and isn't passed to the LLM
  advisor. A misclassification's worst case is one finding flipping
  between `review` and `pass` — it can never cause a wrong `block`.

See [`policy-reference.md`](./policy-reference.md) for the full tier logic
and config schema, and [`enrichment.md`](./enrichment.md) for what each
enricher does and its failure behavior.
