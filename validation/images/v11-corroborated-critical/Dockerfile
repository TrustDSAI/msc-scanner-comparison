# v11-corroborated-critical
#
# Exercises p_gate's corroborated-CRITICAL block path. Every other
# blocking image in the validation suite reaches the block tier through
# the KEV path instead, leaving the six-condition conjunction untested by
# construction.
#
# Base: debian:11-slim. Its own CRITICAL findings all lack a fix, so none
# of them can satisfy either block condition (both require has_fix).
#
# Injected, two dpkg-registered OS packages so that both Trivy and Grype
# enumerate them and cross-scanner consensus holds:
#
#   libcurl4 7.74.0-1.3+deb11u10  CVE-2023-38545 (SOCKS5 heap overflow),
#                                 fixed in +deb11u11, not in CISA KEV.
#   zlib1g   1:1.2.11.dfsg-2+deb11u1  CVE-2022-37434 (inflate over-read),
#                                 fixed in +deb11u2, not in CISA KEV.
#
# Both are CRITICAL with a recorded fix, validated by NVD and confirmed
# with a fix version by OSV. Neither is in KEV, so neither can reach the
# block tier through the KEV path. Two targets are included because the
# EPSS score of any single CVE drifts over time and may fall below the
# 0.5 block threshold; see the reproducibility discussion in the results.
#
# Expected: BLOCK via corroborated_critical, never via kev_block.
FROM debian:11-slim
COPY libcurl4_7.74.0-1.3+deb11u10_amd64.deb /tmp/
COPY zlib1g_1.2.11.dfsg-2+deb11u1_amd64.deb /tmp/
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcurl4 \
 && dpkg -i --force-downgrade /tmp/libcurl4_7.74.0-1.3+deb11u10_amd64.deb \
 && dpkg -i --force-downgrade /tmp/zlib1g_1.2.11.dfsg-2+deb11u1_amd64.deb \
 && rm -rf /tmp/*.deb /var/lib/apt/lists/*
