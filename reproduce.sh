#!/bin/bash
# reproduce.sh — Re-run all scans using pinned image digests.
#
# Guarantees identical image inputs regardless of when the script is run.
# See REPRODUCIBILITY CONSTRAINTS below before executing.
#
# Usage:
#   ./reproduce.sh all              # reproduce all images
#   ./reproduce.sh <safe_name>      # reproduce one image
#   ./reproduce.sh --list           # list available safe names
#
# ============================================================
# REPRODUCIBILITY CONSTRAINTS
# ============================================================
#
# IMAGE INPUTS — fully reproducible.
#   All images are pulled by digest, not by mutable tag.
#
# GRYPE DB — reproducible with archived snapshot.
#   Set GRYPE_DB_AUTO_UPDATE=false and point GRYPE_DB_CACHE_DIR at
#   the archived DB to reproduce exact Grype results:
#
#     export GRYPE_DB_AUTO_UPDATE=false
#     export GRYPE_DB_CACHE_DIR=/path/to/db_snapshots
#
#   The archived DB (grype_v6.1.4_2026-03-30.db) is not included in
#   this repository due to its size (1.4 GB). It can be downloaded from
#   the source URL recorded in logs/environment.txt.
#
# TRIVY DB — partially reproducible.
#   The DB version and build date are recorded in logs/environment.txt.
#   To pin it, archive ~/.cache/trivy/ before running and restore it here.
#
# OSV-SCANNER — NOT reproducible.
#   OSV-Scanner v2.3.5 fetches live from api.osv.dev. There is no supported
#   mechanism to pin the database in standard scan-image mode. Use the stored
#   raw JSON in results/osv/ as the authoritative record of OSV results.
# ============================================================

set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

declare -A DIGESTS=(
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

# OSV-Scanner requires an explicit tag — these are used only for docker tag + OSV invocation
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

scan_image() {
    local SAFE="${1}"
    local IMAGE="${DIGESTS[$SAFE]}"
    local OSV_TAG="${OSV_TAGS[$SAFE]}"

    echo "============================================================"
    echo "Reproducing: ${SAFE}"
    echo "  Pinned image: ${IMAGE}"
    echo "  OSV tag:      ${OSV_TAG}"
    echo "  Started:      $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "============================================================"

    # Pull by digest — guarantees identical layer content
    docker pull "${IMAGE}"

    # Tag locally so OSV-Scanner can resolve by name:tag
    docker tag "${IMAGE}" "${OSV_TAG}"

    # Run all four tools via the main scan script, passing the digest reference
    bash "${REPO_DIR}/scan.sh" "${IMAGE}" "${SAFE}" "reproduce"

    # OSV-Scanner needs the tagged name — overwrite the OSV output
    osv-scanner scan image --format json \
        --output-file "${REPO_DIR}/results/osv/${SAFE}_osv.json" \
        "${OSV_TAG}" || true

    echo "Done: ${SAFE} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

TARGET="${1:-}"

case "${TARGET}" in
    --list)
        echo "Available safe names:"
        for k in "${!DIGESTS[@]}"; do
            printf "  %-30s %s\n" "${k}" "${DIGESTS[$k]}"
        done
        ;;
    all)
        for safe in "${!DIGESTS[@]}"; do
            scan_image "${safe}"
        done
        ;;
    "")
        echo "Usage: $0 <safe_name|all|--list>"
        exit 1
        ;;
    *)
        if [[ -z "${DIGESTS[$TARGET]+x}" ]]; then
            echo "Unknown image: ${TARGET}"
            echo "Run '$0 --list' to see available names."
            exit 1
        fi
        scan_image "${TARGET}"
        ;;
esac
