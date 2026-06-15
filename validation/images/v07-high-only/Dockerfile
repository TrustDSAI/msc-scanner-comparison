# v07-high-only
# Target: HIGH-severity findings with cross-scanner consensus, no CRITICAL CVEs
# Purpose: exercises the P7 REVIEW-HIGH gate path; confirms HIGH findings go
#          to review without auto-blocking (EPSS bar for HIGH auto-block is 0.5).
# Expected gate outcome: REVIEW (exit code 2; P7 review via HIGH+fix+consensus)
#
# curl has a consistent track record of HIGH-severity CVEs with low exploitation
# rates. Including a slightly older curl from ubuntu 22.04's main channel
# (before security backports) provides HIGH findings that both Trivy and Grype
# detect. No CRITICAL CVEs are expected on a plain ubuntu:22.04 base.

FROM ubuntu:22.04

# Strip security and updates to get older curl without security backports.
# This keeps curl at the jammy/main release version which has HIGH-severity
# CVEs without CRITICAL or KEV membership.
RUN sed -i '/security.ubuntu.com/d' /etc/apt/sources.list && \
    sed -i '/jammy-updates/d' /etc/apt/sources.list && \
    sed -i '/jammy-backports/d' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends curl libcurl4 && \
    rm -rf /var/lib/apt/lists/*

CMD ["curl", "--version"]
