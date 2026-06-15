#!/usr/bin/env bash
# run_validation.sh — build, scan, and gate-check all 10 validation images.
#
# Usage:
#   cd /root/msc-scanner-comparison
#   bash validation/run_validation.sh
#
# Options:
#   --fail-fast   stop on first unexpected outcome
#   --no-build    skip docker build (use cached images)
#   --id v01      run only a specific image id
#
# Prerequisites: docker, trivy, grype, opa, python3 (policy/policy_gate.py)
# Optional: NVD_API_KEY env var (reduces enrichment time significantly)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATION_DIR="$REPO_ROOT/validation"
RESULTS_DIR="$VALIDATION_DIR/results"
POLICY_GATE="$REPO_ROOT/policy/policy_gate.py"
CACHE_DIR="$REPO_ROOT/policy/.cache/enrich"

FAIL_FAST=0
NO_BUILD=0
ONLY_ID=""

for arg in "$@"; do
  case $arg in
    --fail-fast) FAIL_FAST=1 ;;
    --no-build)  NO_BUILD=1  ;;
    --id)        shift; ONLY_ID="$1" ;;
    --id=*)      ONLY_ID="${arg#--id=}" ;;
  esac
done

mkdir -p "$RESULTS_DIR"

# ---------------------------------------------------------------------------
# Image definitions  (id, tag, dockerfile_dir|null, expected_tier)
# ---------------------------------------------------------------------------
declare -A DOCKERFILE
declare -A IMAGE_TAG
declare -A EXPECTED

IMAGE_TAG[v01-log4shell]="policy-gate-val/v01-log4shell:latest"
DOCKERFILE[v01-log4shell]="images/v01-log4shell"
EXPECTED[v01-log4shell]="block"

IMAGE_TAG[v02-jenkins-2441]="jenkins/jenkins:2.441"
DOCKERFILE[v02-jenkins-2441]=""            # pre-built; no local build
EXPECTED[v02-jenkins-2441]="block"

IMAGE_TAG[v03-text4shell]="policy-gate-val/v03-text4shell:latest"
DOCKERFILE[v03-text4shell]="images/v03-text4shell"
EXPECTED[v03-text4shell]="review"

IMAGE_TAG[v04-spring4shell]="policy-gate-val/v04-spring4shell:latest"
DOCKERFILE[v04-spring4shell]="images/v04-spring4shell"
EXPECTED[v04-spring4shell]="block"

IMAGE_TAG[v05-regresshion]="policy-gate-val/v05-regresshion:latest"
DOCKERFILE[v05-regresshion]="images/v05-regresshion"
EXPECTED[v05-regresshion]="review"

IMAGE_TAG[v06-crit-low-epss]="policy-gate-val/v06-crit-low-epss:latest"
DOCKERFILE[v06-crit-low-epss]="images/v06-crit-low-epss"
EXPECTED[v06-crit-low-epss]="review"

IMAGE_TAG[v07-high-only]="policy-gate-val/v07-high-only:latest"
DOCKERFILE[v07-high-only]="images/v07-high-only"
EXPECTED[v07-high-only]="review"

IMAGE_TAG[v08-eol-stretch]="policy-gate-val/v08-eol-stretch:latest"
DOCKERFILE[v08-eol-stretch]="images/v08-eol-stretch"
EXPECTED[v08-eol-stretch]="review"

IMAGE_TAG[v09-distroless]="gcr.io/distroless/static-debian12:latest"
DOCKERFILE[v09-distroless]=""
EXPECTED[v09-distroless]="pass"

IMAGE_TAG[v10-alpine-current]="alpine:3.21"
DOCKERFILE[v10-alpine-current]=""
EXPECTED[v10-alpine-current]="pass"

ORDERED_IDS=(
  v01-log4shell v02-jenkins-2441 v03-text4shell v04-spring4shell v05-regresshion
  v06-crit-low-epss v07-high-only v08-eol-stretch v09-distroless v10-alpine-current
)

# ---------------------------------------------------------------------------

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0
FAILURES=()

log()  { echo "[$(date +%H:%M:%S)] $*"; }
ok()   { echo "  ✓ $*"; }
fail() { echo "  ✗ $*"; }

for ID in "${ORDERED_IDS[@]}"; do
  [[ -n "$ONLY_ID" && "$ID" != "$ONLY_ID" ]] && { SKIP_COUNT=$((SKIP_COUNT+1)); continue; }

  TAG="${IMAGE_TAG[$ID]}"
  DFDIR="${DOCKERFILE[$ID]}"
  WANT="${EXPECTED[$ID]}"
  RESULT_FILE="$RESULTS_DIR/${ID}.json"

  log "--- $ID  (expect: $WANT) ---"

  # Build if Dockerfile provided and not skipped
  if [[ -n "$DFDIR" && "$NO_BUILD" -eq 0 ]]; then
    log "Building $TAG from $DFDIR ..."
    if ! docker build -t "$TAG" "$VALIDATION_DIR/$DFDIR" 2>&1 | tail -3; then
      fail "docker build failed — skipping"
      FAIL_COUNT=$((FAIL_COUNT+1))
      FAILURES+=("$ID: docker build failed")
      [[ "$FAIL_FAST" -eq 1 ]] && exit 1
      continue
    fi
  elif [[ -z "$DFDIR" && "$NO_BUILD" -eq 0 ]]; then
    log "Pulling $TAG ..."
    docker pull "$TAG" 2>&1 | tail -1 || true
  fi

  # Run the gate (--fail-on none so exit code never aborts this script)
  log "Running policy gate against $TAG ..."
  python3 "$POLICY_GATE" \
    --image "$TAG" \
    --fail-on none \
    --report-format json \
    --report "$RESULT_FILE" \
    --cache "$CACHE_DIR" \
    2>&1 | grep -E "(block|review|pass|BLOCK|REVIEW|PASS|error|Error|WARNING)" | head -10 || true

  if [[ ! -f "$RESULT_FILE" ]]; then
    fail "no report produced"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILURES+=("$ID: gate produced no report")
    [[ "$FAIL_FAST" -eq 1 ]] && exit 1
    continue
  fi

  # Extract the verdict (policy_gate.py JSON: {decision, block: [...], review: [...]})
  GOT=$(jq -r '.decision // "unknown"' "$RESULT_FILE" 2>/dev/null || echo "unknown")
  BLOCK_COUNT=$(jq -r '(.block // []) | length' "$RESULT_FILE" 2>/dev/null || echo "0")
  REVIEW_COUNT=$(jq -r '(.review // []) | length' "$RESULT_FILE" 2>/dev/null || echo "0")

  log "Decision: $GOT  (block=$BLOCK_COUNT, review=$REVIEW_COUNT)"

  if [[ "$GOT" == "$WANT" ]]; then
    ok "$ID — got '$GOT' as expected"
    PASS_COUNT=$((PASS_COUNT+1))
  else
    fail "$ID — expected '$WANT', got '$GOT'"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAILURES+=("$ID: expected $WANT got $GOT")
    [[ "$FAIL_FAST" -eq 1 ]] && exit 1
  fi

  echo
done

# ---------------------------------------------------------------------------
echo "========================================"
echo "Validation summary"
echo "========================================"
echo "  Pass:    $PASS_COUNT / ${#ORDERED_IDS[@]}"
echo "  Fail:    $FAIL_COUNT"
echo "  Skipped: $SKIP_COUNT"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
  echo
  echo "Failures:"
  for f in "${FAILURES[@]}"; do
    echo "  - $f"
  done
fi

echo
echo "Results written to: $RESULTS_DIR/"
echo "========================================"

[[ "$FAIL_COUNT" -eq 0 ]]
