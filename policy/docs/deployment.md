# Deployment

Three ways to run the gate, all sharing `run_gate()` in `policy_gate.py`.

## CLI

```bash
python3 policy_gate.py --image <ref> [options]
```

Key flags:

| Flag | Default | Purpose |
|---|---|---|
| `--policy` | `configs/p_gate.json` | config JSON, see [`policy-reference.md`](./policy-reference.md) |
| `--classifier` | `rule` | `rule` \| `agent` (LLM) — optional, see below |
| `--fail-on` | `review` | `block` \| `review` \| `none`; which tiers exit non-zero |
| `--report-format` | `json` | `json` \| `markdown` \| `pr-comment` \| `sarif` \| `junit` |
| `--pr-comment-path` | none | also render the pr-comment markdown here, independent of `--report-format` |
| `--comment-max-findings` | 20 | row cap per table in pr-comment format, sorted by EPSS descending |
| `--override-active` | false | render the gate-override banner (caller checks the PR label and passes this) |
| `--log-url` | none | "full log" link appended to the pr-comment |
| `--exceptions-dir` | none | enables suppression; no value = suppression off |
| `--rego-dir` / `--policy-package` | built-in | swap the entire policy without touching this file |

Exit codes: `0` = pass, `1` = block, `2` = review (only when `--fail-on review`).

## API server

```bash
POLICY_GATE_MODE=api python3 api.py    # listens on :8080
```

| Endpoint | Purpose |
|---|---|
| `POST /gate` | scan an image, return a `GateResponse` (same shape as CLI's `--report-format json`) |
| `POST /gate/verdict` | same, but accepts pre-computed Trivy + Grype JSON (skips scanning) |
| `GET /health` | liveness probe |
| `GET /config` | active gate configuration |

Auth: `X-API-Key` header, checked against `POLICY_GATE_API_KEY` env var.
Unset = no auth (local/dev only — there is no default-deny).

Exceptions are **server-controlled, not client-suppliable**:
`POLICY_GATE_EXCEPTIONS_DIR` env var, read once at startup. There is no
per-request exceptions field on `GateRequest` — this preserves the
PR-review governance model (exceptions are checked-in, reviewed YAML, not
something a caller can inject at request time).

## GitHub composite action

`.github/actions/policy-gate/action.yml`. A consuming repo's "5 lines":

```yaml
- uses: TrustDSAI/msc-scanner-comparison/.github/actions/policy-gate@main
  with:
    image: my-app:${{ github.sha }}
    fail-on: review
    nvd-api-key: ${{ secrets.NVD_API_KEY }}
```

Runs the published `ghcr.io/<owner>/policy-gate:latest` image via
`docker run`, mounting the Docker socket (so the action's container can
inspect the target image) and an enrichment-cache volume
(`actions/cache@v4`, persists across runs to avoid NVD rate limits).

The override banner and "full log" link in the PR comment are computed
**inside the action**, not by the calling workflow — composite-action
steps share the same `github` context as any workflow step, so
`contains(github.event.pull_request.labels.*.name, 'gate-override')` and
the run URL are available without the caller needing any inline script.
The calling workflow's job is reduced to: read the comment file the tool
wrote, call `createComment`.

## Publishing the image

`.github/workflows/publish-image.yml` builds and pushes
`ghcr.io/<owner>/policy-gate:latest` automatically on any push to `main`
touching `policy/**`. **This is load-bearing**: the composite action
above pulls whatever was last pushed, and a stale image silently rejects
new CLI flags with no signal pointing at "rebuild the image" — it looks
identical to a real gate bug from the consuming repo's side. This was a
real failure mode hit directly this session before the workflow existed.

First-run gotcha: the package's GHCR settings need
`TrustDSAI/msc-scanner-comparison` added under "Actions repository
access" (Package settings → Manage Actions access) before
`GITHUB_TOKEN` can push — a manually-`docker push`-created package
doesn't grant this by default.
