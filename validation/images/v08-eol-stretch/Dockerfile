# v08-eol-stretch
# Target: EOL base image (Debian 9 "Stretch", EOL 2022-06-30)
# Purpose: validates EOL context annotation — Trivy reports EOSL=true for
#          Debian Stretch; the gate must attach eol=true to every deny
#          message but NOT use EOL status to determine the tier itself.
#          This confirms the P6 design decision (EOL is context, not a gate).
# Expected gate outcome: REVIEW (CRITICAL findings below block threshold;
#                        EOL=true on every deny message)
#
# Debian 9 carries many unfixed CVEs (no upstream patches since EOL).
# The majority have EPSS below 0.5 and no KEV entry, so they reach the
# REVIEW tier, not BLOCK. The EOL flag should be visible in every finding
# in the JSON report under finding.image.eol = true.

FROM debian:9

# Use the snapshot archive for Stretch since the main mirrors no longer serve it.
RUN echo "deb http://archive.debian.org/debian stretch main" > /etc/apt/sources.list && \
    echo "deb http://archive.debian.org/debian-security stretch/updates main" >> /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y --no-install-recommends \
        openssl libssl1.1 libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

CMD ["openssl", "version"]
