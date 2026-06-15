# policy-gate: self-contained CI/CD vulnerability gate.
#
# Bundles the scanners (Trivy, Grype), the OPA binary, the Python pipeline,
# and the policy bundle into one image. A CI runner needs only to
#   docker run --rm ghcr.io/<org>/policy-gate --image <target>
# with no local tool installation.
#
# Pinned versions match the dissertation study for reproducibility.

FROM python:3.12-slim

# Pinned tool versions (match the empirical study).
ARG TRIVY_VERSION=0.69.3
ARG GRYPE_VERSION=0.110.0
ARG OPA_VERSION=1.17.0

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl tar \
    && rm -rf /var/lib/apt/lists/*

# --- OPA ---
RUN curl -sSL -o /usr/local/bin/opa \
        "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_amd64_static" \
    && chmod +x /usr/local/bin/opa

# --- Trivy ---
RUN curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        | tar -xz -C /usr/local/bin trivy

# --- Grype ---
RUN curl -sSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" \
        | tar -xz -C /usr/local/bin grype

# --- Python deps ---
# Anthropic and OpenAI SDKs are optional (advisor + agent classifier).
# fastapi + uvicorn are needed only for the API server mode.
RUN pip install \
        "anthropic>=0.40,<1.0" \
        "openai>=1.0,<2.0" \
        "fastapi>=0.115,<1.0" \
        "uvicorn[standard]>=0.30,<1.0" \
        "python-multipart>=0.0.9"

# --- Application ---
WORKDIR /app
COPY normalisers/   ./normalisers/
COPY enrichers/     ./enrichers/
COPY classifiers/   ./classifiers/
COPY rego/          ./rego/
COPY configs/       ./configs/
COPY policy_gate.py ./policy_gate.py
COPY api.py         ./api.py

# Cache directory for enrichment data; mount a volume here in CI to persist
# across runs and avoid NVD rate limits.
ENV POLICY_GATE_CACHE=/cache
RUN mkdir -p /cache

# Custom policy mount point. To use your own Rego without rebuilding:
#   docker run --rm -v ./my-policy:/policy ghcr.io/<org>/policy-gate \
#     --image my-app:latest --rego-dir /policy --policy-package myorg.gate
VOLUME /policy

# Two run modes:
#
#   CLI (default) — one image, exit code 0/1/2:
#     docker run --rm ghcr.io/<org>/policy-gate --image my-app:latest
#
#   API server — listens on :8080, POST /gate:
#     docker run --rm -p 8080:8080 \
#       -e POLICY_GATE_MODE=api \
#       ghcr.io/<org>/policy-gate
#
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["--help"]
