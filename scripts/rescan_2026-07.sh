#!/bin/bash
# rescan_2026-07.sh — Re-run the 9 design-set images against today's live
# scanner databases, writing to an isolated directory so the original
# 2026-03-31 baseline in data/raw/ is never overwritten.
#
# Usage: ./scripts/rescan_2026-07.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${REPO_DIR}/data/raw_rescan_2026-07-29"
LOG="${REPO_DIR}/logs/rescan_2026-07-29.log"

mkdir -p "${OUT}/trivy" "${OUT}/grype" "${OUT}/osv"

declare -A DIGESTS=(
    ["alpine_3.19"]="alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
    ["nginx_1.29.7"]="nginx@sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18"
    ["node_20"]="node@sha256:a4545fc6f4f1483384ad5f4c71d34d71781c3779da407173ec6058079a718520"
    ["python_3.12"]="python@sha256:c4c9e439bf98d5c20453156194f937aefb4a633555d93a1960d612052c4b3436"
    ["nginx_1.19"]="nginx@sha256:df13abe416e37eb3db4722840dd479b00ba193ac6606e7902331dcea50f4f1f2"
    ["node_14"]="node@sha256:a158d3b9b4e3fa813fa6c8c590b8f0a860e015ad4e59bbce5744d2f6fd8461aa"
    ["python_3.8"]="python@sha256:d411270700143fa2683cc8264d9fa5d3279fd3b6afff62ae81ea2f9d070e390c"
    ["vulnerables_web-dvwa"]="vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7"
    ["bkimminich_juice-shop"]="bkimminich/juice-shop@sha256:5539448a1d3fa88d932d3f80a8d3f69a16cde6253c1d4256b28a38ef910e4114"
)

declare -A OSV_TAGS=(
    ["alpine_3.19"]="alpine:3.19"
    ["nginx_1.29.7"]="nginx:1.29.7"
    ["node_20"]="node:20"
    ["python_3.12"]="python:3.12"
    ["nginx_1.19"]="nginx:1.19"
    ["node_14"]="node:14"
    ["python_3.8"]="python:3.8"
    ["vulnerables_web-dvwa"]="vulnerables/web-dvwa:latest"
    ["bkimminich_juice-shop"]="bkimminich/juice-shop:latest"
)

for safe in "${!DIGESTS[@]}"; do
    IMAGE="${DIGESTS[$safe]}"
    OSV_TAG="${OSV_TAGS[$safe]}"

    echo "=== ${safe} (${IMAGE}) ===" | tee -a "${LOG}"
    docker pull "${IMAGE}" | tee -a "${LOG}"
    docker tag "${IMAGE}" "${OSV_TAG}"

    trivy image --format json --scanners vuln \
        --output "${OUT}/trivy/${safe}_trivy.json" "${IMAGE}" 2>&1 | tee -a "${LOG}"

    grype "${IMAGE}" -o json > "${OUT}/grype/${safe}_grype.json" 2>>"${LOG}"

    osv-scanner scan image --format json \
        --output-file "${OUT}/osv/${safe}_osv.json" "${OSV_TAG}" 2>>"${LOG}" || true

    echo "done: ${safe}" | tee -a "${LOG}"
done

echo "Re-scan complete. Output: ${OUT}"
