#!/bin/sh
# Entrypoint: CLI mode by default, API server when POLICY_GATE_MODE=api.
set -e

if [ "${POLICY_GATE_MODE:-cli}" = "api" ]; then
    exec uvicorn api:app \
        --host "${POLICY_GATE_HOST:-0.0.0.0}" \
        --port "${POLICY_GATE_PORT:-8080}" \
        --workers "${POLICY_GATE_WORKERS:-1}"
else
    exec python3 /app/policy_gate.py "$@"
fi
