# v05-regresshion
# Target: CVE-2024-6387 (regreSSHion)
# Incident: Jul 2024 — unauthenticated RCE in OpenSSH 8.5p1–9.7p1 via a race
#            condition in signal handling; regression of CVE-2006-5051.
#            USN-6859-1 patched Ubuntu 22.04 on 2024-07-01.
# Expected gate outcome: BLOCK (KEV catalog entry, fix available as ubuntu0.X backport)
#
# Strategy: install openssh-server 1:8.9p1-3 from jammy/main, which is the
# original unpatched release. The patched versions (1:8.9p1-3ubuntu0.X) are
# only in jammy-security and jammy-updates, which are excluded here.
# OpenSSH 8.9p1 sits within the vulnerable range (8.5p1 ≤ v < 9.8p1).

FROM ubuntu:22.04

# Strip security and updates channels to force the original unpatched package.
RUN sed -i '/security.ubuntu.com/d' /etc/apt/sources.list && \
    sed -i '/jammy-updates/d' /etc/apt/sources.list && \
    sed -i '/jammy-backports/d' /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends openssh-server=1:8.9p1-3 && \
    rm -rf /var/lib/apt/lists/*

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
