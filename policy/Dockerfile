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
# Only the standard library plus the Anthropic SDK (optional, for the agent
# classifier). The pipeline otherwise uses urllib, so keep this minimal.
RUN pip install "anthropic>=0.40,<1.0"

# --- Application ---
WORKDIR /app
COPY normalisers/   ./normalisers/
COPY enrichers/     ./enrichers/
COPY classifiers/   ./classifiers/
COPY rego/          ./rego/
COPY configs/       ./configs/
COPY policy_gate.py ./policy_gate.py

# Cache directory for enrichment data; mount a volume here in CI to persist
# across runs and avoid NVD rate limits.
ENV POLICY_GATE_CACHE=/cache
RUN mkdir -p /cache

ENTRYPOINT ["python3", "/app/policy_gate.py"]
CMD ["--help"]
