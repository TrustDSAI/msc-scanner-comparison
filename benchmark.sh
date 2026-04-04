#!/bin/bash
# benchmark.sh — Re-run each scanner N times per image and record execution times.
# Images must already be present locally (no pull step).
# Output appended to logs/benchmark.log

set -euo pipefail
REPO_DIR="$(cd "$(dirname "$0")/scanner-comparison" && pwd)"
LOGS="${REPO_DIR}/logs"
OUT="${LOGS}/benchmark.log"
RUNS="${1:-3}"

declare -A IMAGES=(
    ["alpine_3.19"]="alpine@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1"
    ["nginx_latest"]="nginx@sha256:7150b3a39203cb5bee612ff4a9d18774f8c7caf6399d6e8985e97e28eb751c18"
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
    ["nginx_latest"]="nginx:latest"
    ["node_20"]="node:20"
    ["python_3.12"]="python:3.12"
    ["nginx_1.19"]="nginx:1.19"
    ["node_14"]="node:14"
    ["python_3.8"]="python:3.8"
    ["vulnerables_web-dvwa"]="vulnerables/web-dvwa:latest"
    ["bkimminich_juice-shop"]="bkimminich/juice-shop:latest"
)

SCAN_ORDER=(alpine_3.19 nginx_1.19 nginx_latest node_14 node_20 python_3.8 python_3.12 vulnerables_web-dvwa bkimminich_juice-shop)

echo "benchmark_start $(date -u +%Y-%m-%dT%H:%M:%SZ) runs=${RUNS}" >> "${OUT}"

for SAFE in "${SCAN_ORDER[@]}"; do
    IMAGE="${IMAGES[$SAFE]}"
    OSV_TAG="${OSV_TAGS[$SAFE]}"
    SIZE_BYTES=$(docker inspect --format '{{.Size}}' "${IMAGE}" 2>/dev/null || echo 0)
    SIZE_MB=$(echo "scale=1; ${SIZE_BYTES}/1048576" | bc)
    echo "  image=${SAFE} size=${SIZE_MB}MB"

    for RUN in $(seq 1 "${RUNS}"); do
        # Trivy
        T_START=$(date +%s%N)
        trivy image --format json --scanners vuln --output /dev/null "${IMAGE}" 2>/dev/null
        T_END=$(date +%s%N)
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${SAFE} trivy run${RUN} $(( (T_END-T_START)/1000000 ))ms ${SIZE_MB}MB" >> "${OUT}"
        echo "    trivy run${RUN}: $(( (T_END-T_START)/1000000 ))ms"

        # Grype
        T_START=$(date +%s%N)
        grype "${IMAGE}" -o json > /dev/null 2>&1
        T_END=$(date +%s%N)
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${SAFE} grype run${RUN} $(( (T_END-T_START)/1000000 ))ms ${SIZE_MB}MB" >> "${OUT}"
        echo "    grype run${RUN}: $(( (T_END-T_START)/1000000 ))ms"

        # OSV-Scanner
        T_START=$(date +%s%N)
        osv-scanner scan image --format json --output-file /dev/null "${OSV_TAG}" 2>/dev/null || true
        T_END=$(date +%s%N)
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${SAFE} osv run${RUN} $(( (T_END-T_START)/1000000 ))ms ${SIZE_MB}MB" >> "${OUT}"
        echo "    osv run${RUN}: $(( (T_END-T_START)/1000000 ))ms"
    done
done

echo "benchmark_end $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "${OUT}"
echo "Done. Results in ${OUT}"
