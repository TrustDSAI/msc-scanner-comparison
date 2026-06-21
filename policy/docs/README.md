# Policy gate documentation

- [`architecture.md`](./architecture.md) — pipeline stages, where logic lives and why
- [`policy-reference.md`](./policy-reference.md) — full p_gate tier logic and config schema
- [`enrichment.md`](./enrichment.md) — the four enrichers, retry behavior, the embedded-vs-live EPSS caveat
- [`deployment.md`](./deployment.md) — CLI / API server / GitHub Action, image publishing

See [`../../CONTEXT.md`](../../CONTEXT.md) for the project's domain
vocabulary (Finding, Tier, Decision, Corroborated, Suppression, Exception)
and the decisions made about the gate's design, kept in sync as the code
changes rather than written once and left to drift.

For the thesis's research narrative (experiment design, empirical results,
scope boundaries like the reachability-analysis gap) see `docs/` at the
repo root, not here — that's the research record; this is the code
reference.
