# v06-crit-low-epss
# Target: CRITICAL CVEs with EPSS well below 0.5, no KEV membership
# Purpose: validates that the gate does NOT block everything CRITICAL;
#          EPSS filter and KEV check are working as designed.
# Expected gate outcome: REVIEW (CRITICAL tier, exit code 2, not 1)
#
# Package versions chosen for their CRITICAL NVD ratings and historically
# stable low-to-moderate EPSS scores (< 0.1 at time of study):
#
#   cryptography==38.0.4  CVE-2023-0286 (X.400 type confusion in OpenSSL,
#                         CRITICAL, NVD Analyzed, no KEV entry, EPSS ~0.05)
#   Pillow==9.3.0         CVE-2023-44271 (uncontrolled resource consumption,
#                         CRITICAL per NVD, no KEV, low EPSS)
#   lxml==4.9.2           CVE-2022-2309 (NULL dereference, CRITICAL per NVD,
#                         no KEV, EPSS < 0.01)
#
# If EPSS values have risen above 0.5 at scan time, the image may produce
# a BLOCK result instead — this is a correct gate behaviour and should be
# documented as an EPSS drift event rather than a gate failure.

FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    "cryptography==38.0.4" \
    "Pillow==9.3.0" \
    "lxml==4.9.2"

CMD ["python3", "-c", "import cryptography, PIL, lxml; print('ok')"]
