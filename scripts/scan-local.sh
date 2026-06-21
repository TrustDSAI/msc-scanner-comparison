#!/bin/bash
# scan-local.sh — Same as scan.sh but for images that only exist locally
# (no registry pull). Used for validation/images/* Dockerfiles built via
# `docker build`, since scan.sh's `docker pull` would fail on them.
set -euo pipefail

IMAGE="${1}"
SAFE_NAME="${2}"
GROUP="${3:-unknown}"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_TRIVY="${REPO_DIR}/data/raw/trivy"
RESULTS_GRYPE="${REPO_DIR}/data/raw/grype"
RESULTS_OSV="${REPO_DIR}/data/raw/osv"
RESULTS_SBOM="${REPO_DIR}/data/sbom"
LOGS="${REPO_DIR}/logs"
DIGEST_LOG="${LOGS}/digests.log"

mkdir -p "${RESULTS_TRIVY}" "${RESULTS_GRYPE}" "${RESULTS_OSV}" "${RESULTS_SBOM}" "${LOGS}"

echo "=== Scanning (local): ${IMAGE} (${SAFE_NAME}, group ${GROUP}) ==="
DIGEST=$(docker inspect --format='{{.Id}}' "${IMAGE}")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  ${SAFE_NAME}  ${IMAGE}  ${DIGEST}" >> "${DIGEST_LOG}"

syft "${IMAGE}" -o syft-json > "${RESULTS_SBOM}/${SAFE_NAME}_syft.json"
trivy image --format json --scanners vuln --output "${RESULTS_TRIVY}/${SAFE_NAME}_trivy.json" "${IMAGE}"
grype "${IMAGE}" -o json > "${RESULTS_GRYPE}/${SAFE_NAME}_grype.json"
osv-scanner scan image --format json --output-file "${RESULTS_OSV}/${SAFE_NAME}_osv.json" "${IMAGE}" || true

echo "=== Done: ${IMAGE} ==="
