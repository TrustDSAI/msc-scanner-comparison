#!/bin/bash
# scan-expansion.sh — Scan all 21 new dataset-expansion images in one run.
# Local (already-built) images use scan-local.sh; everything else pulls
# from a registry via scan.sh. Logs progress to stdout per image so a
# partial failure on one image doesn't lose visibility into the rest.
set -uo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO_DIR}"

# safe_name : image_ref : group : local(1)/pull(0)
IMAGES=(
  "v01_log4shell:policy-gate-val/v01-log4shell:latest:A:1"
  "v03_text4shell:policy-gate-val/v03-text4shell:latest:A:1"
  "v04_spring4shell:policy-gate-val/v04-spring4shell:latest:A:1"
  "webgoat_webgoat:webgoat/webgoat-8.0:A:0"
  "citizenstig_nowasp:citizenstig/nowasp:latest:A:0"
  "golang_1.16-alpine:golang:1.16-alpine:B:0"
  "ruby_2.5-slim:ruby:2.5-slim:B:0"
  "openjdk_8-jre:openjdk:8-jre:B:0"
  "dotnet_runtime_3.1:mcr.microsoft.com/dotnet/runtime:3.1:B:0"
  "php_7.4-apache:php:7.4-apache:B:0"
  "rust_1.56-slim:rust:1.56-slim:B:0"
  "node_12:node:12:B:0"
  "python_2.7:python:2.7:B:0"
  "golang_1.23-alpine:golang:1.23-alpine:C:0"
  "ruby_3.3-slim:ruby:3.3-slim:C:0"
  "eclipse-temurin_21-jre:eclipse-temurin:21-jre:C:0"
  "dotnet_runtime_8.0:mcr.microsoft.com/dotnet/runtime:8.0:C:0"
  "php_8.3-apache:php:8.3-apache:C:0"
  "rust_1.82-slim:rust:1.82-slim:C:0"
  "node_22:node:22:C:0"
  "python_3.13-slim:python:3.13-slim:C:0"
)

TOTAL=${#IMAGES[@]}
N=0
FAILED=()

for entry in "${IMAGES[@]}"; do
  N=$((N+1))
  # safe_name is field 1; group is second-to-last; local-flag is last;
  # image ref is everything in between (handles refs containing ':').
  IFS=':' read -ra parts <<< "$entry"
  safe_name="${parts[0]}"
  is_local="${parts[-1]}"
  group="${parts[-2]}"
  image_ref=$(IFS=:; echo "${parts[*]:1:${#parts[@]}-3}")

  echo ""
  echo "########## [$N/$TOTAL] ${safe_name} (${image_ref}, group ${group}, local=${is_local}) ##########"
  if [ "$is_local" = "1" ]; then
    bash scripts/scan-local.sh "$image_ref" "$safe_name" "$group" || FAILED+=("$safe_name")
  else
    bash scripts/scan.sh "$image_ref" "$safe_name" "$group" || FAILED+=("$safe_name")
  fi
done

echo ""
echo "========== Expansion scan complete: $((TOTAL - ${#FAILED[@]}))/${TOTAL} succeeded =========="
if [ ${#FAILED[@]} -gt 0 ]; then
  echo "Failed: ${FAILED[*]}"
fi
