#!/bin/bash
# scan.sh — Run all vulnerability scanners against a single container image.
#
# Usage: ./scan.sh <image> <safe_name> <group>
#   image     — full image reference (e.g. alpine:3.19)
#   safe_name — filesystem-safe name used for output files (e.g. alpine_3.19)
#   group     — dataset group: A (intentionally vulnerable), B (outdated), C (modern)
#
# Outputs (relative to this script's directory):
#   sbom/<safe_name>_syft.json
#   results/trivy/<safe_name>_trivy.json
#   results/grype/<safe_name>_grype.json
#   results/osv/<safe_name>_osv.json
#   logs/digests.log
#   logs/timing.log
#
# Note on OSV-Scanner: images without an explicit tag (e.g. owner/name without
# :latest) are rejected. Pass the full tagged reference as <image>.

set -euo pipefail

IMAGE="${1}"
SAFE_NAME="${2}"
GROUP="${3:-unknown}"

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_TRIVY="${REPO_DIR}/results/trivy"
RESULTS_GRYPE="${REPO_DIR}/results/grype"
RESULTS_OSV="${REPO_DIR}/results/osv"
RESULTS_SBOM="${REPO_DIR}/sbom"
LOGS="${REPO_DIR}/logs"
TIMING_LOG="${LOGS}/timing.log"
DIGEST_LOG="${LOGS}/digests.log"

mkdir -p "${RESULTS_TRIVY}" "${RESULTS_GRYPE}" "${RESULTS_OSV}" "${RESULTS_SBOM}" "${LOGS}"

echo "============================================================"
echo "Scanning: ${IMAGE} (safe name: ${SAFE_NAME}, group: ${GROUP})"
echo "Started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

# [1] Pull image and record digest
echo "[1/5] Pulling image and recording digest..."
docker pull "${IMAGE}"
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' "${IMAGE}" 2>/dev/null \
         || docker inspect --format='{{.Id}}' "${IMAGE}")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  ${SAFE_NAME}  ${IMAGE}  ${DIGEST}" >> "${DIGEST_LOG}"
echo "Digest: ${DIGEST}"

# [2] SBOM — Syft
echo "[2/5] Generating SBOM with Syft..."
SBOM_OUT="${RESULTS_SBOM}/${SAFE_NAME}_syft.json"
T_START=$(date +%s%N)
syft "${IMAGE}" -o syft-json > "${SBOM_OUT}"
T_END=$(date +%s%N)
T_SYFT=$(( (T_END - T_START) / 1000000 ))
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  ${SAFE_NAME}  syft  ${T_SYFT}ms" >> "${TIMING_LOG}"
echo "Syft done: ${T_SYFT}ms -> ${SBOM_OUT}"

# [3] Trivy — vuln only
echo "[3/5] Scanning with Trivy..."
TRIVY_OUT="${RESULTS_TRIVY}/${SAFE_NAME}_trivy.json"
T_START=$(date +%s%N)
trivy image --format json --scanners vuln --output "${TRIVY_OUT}" "${IMAGE}"
T_END=$(date +%s%N)
T_TRIVY=$(( (T_END - T_START) / 1000000 ))
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  ${SAFE_NAME}  trivy  ${T_TRIVY}ms" >> "${TIMING_LOG}"
echo "Trivy done: ${T_TRIVY}ms -> ${TRIVY_OUT}"

# [4] Grype
echo "[4/5] Scanning with Grype..."
GRYPE_OUT="${RESULTS_GRYPE}/${SAFE_NAME}_grype.json"
T_START=$(date +%s%N)
grype "${IMAGE}" -o json > "${GRYPE_OUT}"
T_END=$(date +%s%N)
T_GRYPE=$(( (T_END - T_START) / 1000000 ))
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  ${SAFE_NAME}  grype  ${T_GRYPE}ms" >> "${TIMING_LOG}"
echo "Grype done: ${T_GRYPE}ms -> ${GRYPE_OUT}"

# [5] OSV-Scanner
echo "[5/5] Scanning with OSV-Scanner..."
OSV_OUT="${RESULTS_OSV}/${SAFE_NAME}_osv.json"
T_START=$(date +%s%N)
osv-scanner scan image --format json --output-file "${OSV_OUT}" "${IMAGE}" || true
T_END=$(date +%s%N)
T_OSV=$(( (T_END - T_START) / 1000000 ))
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)  ${SAFE_NAME}  osv  ${T_OSV}ms" >> "${TIMING_LOG}"
echo "OSV-Scanner done: ${T_OSV}ms -> ${OSV_OUT}"

echo ""
echo "Completed: ${IMAGE} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Timings: syft=${T_SYFT}ms trivy=${T_TRIVY}ms grype=${T_GRYPE}ms osv=${T_OSV}ms"
echo "============================================================"
