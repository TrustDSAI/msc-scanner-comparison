# Dataset Expansion: 9 → 30 Images

**Date:** 2026-06-21
**Status:** In progress
**Motivation:** the original 9-image dataset (Chapter 5/6) covers three
language ecosystems (Python, Node, and the implicit Alpine/nginx OS
layer) plus two PHP/Node-based intentionally-vulnerable apps. That's
enough to demonstrate the empirical claim but thin on ecosystem
diversity — a reviewer could reasonably ask whether the gate's behavior
generalizes beyond Python/Node, or whether the layer-aware classifier's
effect is specific to those ecosystems' particular CVE landscape.

## What's being added

21 new images, bringing the total to 30, keeping the existing group
convention (A = intentionally vulnerable, B = outdated/EOL, C = modern)
and adding ecosystem coverage the original 9 didn't have: Go, Ruby,
Java/JVM, .NET, PHP, Rust.

| Group | New images |
|---|---|
| A (vulnerable) | `v01-log4shell`, `v03-text4shell`, `v04-spring4shell` (Java; already-built Dockerfiles under `validation/images/`, previously used only for one-off CI demos, not the main dataset) · `webgoat/webgoat-8.0` (Java, OWASP) · `citizenstig/nowasp` (PHP, Mutillidae II) |
| B (outdated/EOL) | `golang:1.16-alpine` · `ruby:2.5-slim` · `eclipse-temurin:8-jre` (swapped in for `openjdk:8-jre`, which Docker Hub no longer serves — the official `openjdk` repo was retired in favor of `eclipse-temurin`) · `mcr.microsoft.com/dotnet/runtime:3.1` · `php:7.4-apache` · `rust:1.56-slim` · `node:12` · `python:2.7` |
| C (modern) | `golang:1.23-alpine` · `ruby:3.3-slim` · `eclipse-temurin:21-jre` · `mcr.microsoft.com/dotnet/runtime:8.0` · `php:8.3-apache` · `rust:1.82-slim` · `node:22` · `python:3.13-slim` |

`node:12`/`python:2.7` and `node:22`/`python:3.13-slim` deepen the two
ecosystems the original 9 already had (an EOL/modern pair each) rather
than adding a seventh ecosystem; every other new image is a genuinely
new ecosystem.

## Methodology (unchanged from the original 9)

1. **Scan**: `scripts/scan.sh <image> <safe_name> <group>` — pulls the
   image, runs Syft (SBOM), Trivy, Grype, OSV-Scanner, writes raw JSON to
   `data/raw/{trivy,grype,osv}/`. The three `validation/images/` Dockerfiles
   are built locally first (`docker build`), then scanned by image ID
   rather than pulled from a registry.
2. **Evaluate**: `evaluate_all.py`'s `IMAGES` list gets the 21 new
   `(safe_name, label, group)` tuples. Everything downstream (normalise,
   classify, enrich, `opa eval` against every policy including `p_gate`)
   is identical to the existing 9 — no new code path, same pipeline.
3. **LLM usage**: both classifiers run on every image as before (rule
   always; agent if `ANTHROPIC_API_KEY` is set). Additionally, this run
   captures the LLM advisor's `advise_batch()` triage summary for each
   image's `p_gate` review/block sets (not part of the original 9's
   `evaluate_all.py` output) — written to `output/<safe>_advisor_summary.json`.

## Known cost

18 of the 21 images require a fresh `docker pull` (no cached raw scanner
data exists, unlike re-running against the original 9 which reads
pre-committed `data/raw/` JSON). Each scan is 4 tools against an
uncached image — realistically minutes per image, hours total, plus
enrichment and LLM calls afterward. Run in the background with periodic
checks, not a single blocking command.

## What this does NOT change

The original 9-image numbers (`output/summary.csv`, `verdict_matrix.csv`,
etc.) are not invalidated or recomputed differently by this expansion —
`evaluate_all.py`'s logic is unchanged, only its `IMAGES` list grows. Any
thesis claim already validated against the 9 stays valid; this expansion
is additive evidence for ecosystem generalization, not a correction.
