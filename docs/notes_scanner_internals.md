# Scanner Internals — How Trivy, Grype, and OSV-Scanner Work

**Purpose:** Technical explanation of how each scanner operates internally, why their results differ, and why execution times vary so dramatically. Reference for dissertation Chapter 3 and Chapter 4 gap analysis.

---

## 1. The Core Architectural Difference

All three scanners solve the same problem — find vulnerable packages in a container image — but they take fundamentally different approaches:

| Scanner | Approach | DB location | Image access |
|---------|----------|-------------|--------------|
| Trivy | Index-first lookup | Local cache | Layer extraction |
| Grype | SBOM-first matching | Local cache | Embeds Syft |
| OSV-Scanner | Package-first query | Remote API | Full image export to disk |

---

## 2. Trivy

### How it works

Trivy uses a **pre-built inverted index** — its vulnerability database is structured so that given a package name and version, it can immediately return matching CVEs without scanning the full DB. The process is:

1. **Image unpacking:** Trivy extracts image layers and identifies the OS (via `/etc/os-release`, `/etc/debian_version`, etc.)
2. **Package enumeration:** Parses OS package manifests (`dpkg`, `apk`, `rpm`) and application manifests (`package-lock.json`, `requirements.txt`, etc.) directly from the layer filesystem
3. **DB lookup:** For each package, queries its local DB index by `(ecosystem, package_name, version)` → returns matching CVEs in O(1) or O(log n) time
4. **Fix status resolution:** DB includes Debian/Alpine/RHEL security tracker data, so `Status` and `FixedVersion` come directly from the DB record

**Why it's fast:** Steps 2 and 3 are both O(packages) with very low constants. The DB lookup is a simple key-value read against a BoltDB (embedded key-value store). There is no image layer traversal for the matching step — it's just package list parsing + index lookup.

### Where its data comes from

- **OS packages:** Debian Security Tracker, Alpine SecDB, RHEL/CentOS advisories, Ubuntu USN
- **Application packages:** NVD (National Vulnerability Database), GitHub Advisory Database
- **Fix status:** Pulled directly from OS vendor security trackers — each tracker states whether a fix is available in that distro's repos

### Why Trivy inflates LOW counts

Trivy includes CVEs from NVD that OS vendor trackers may classify as "negligible" or not assign a fix to. The NVD assigns CVSS scores independently; Debian may accept a CVE as low-risk and not backport a fix, but Trivy still includes it with the NVD CVSS score. Grype's DB, which weights vendor scores, tends to exclude or downgrade these.

---

## 3. Grype

### How it works

Grype takes a **SBOM-first approach** — it doesn't scan an image directly. Instead:

1. **SBOM generation:** Grype embeds Syft internally. When you run `grype <image>`, it first runs a full Syft SBOM extraction — unpacking all image layers, traversing every file, identifying package manifests, and building a complete Software Bill of Materials
2. **Package matching:** Takes the SBOM output (list of packages with PURLs — Package URLs) and matches each against its local vulnerability DB
3. **DB matching:** Grype DB is structured by PURL ecosystem. For each package, it queries `(type, name, version)` and returns all matching advisories
4. **Fix state resolution:** Each advisory record in Grype's DB includes a `fix.state` field sourced from the advisory's original publication

**Why it's slow:** Step 1 — the embedded Syft scan — is a full filesystem traversal of every layer in the image. For a 1GB image, this involves decompressing layers, walking directory trees, parsing hundreds of manifest files, and computing file hashes. This IO-bound work scales linearly with image size and file count. You can verify this by comparing Grype scan times to Syft standalone times — they are nearly identical, because Grype is essentially running Syft then doing a fast DB lookup.

**Why Grype finds more on npm images:** Grype ingests the GitHub Advisory Database more aggressively for npm and other application ecosystems. GitHub Advisory includes advisories for packages that NVD sometimes does not have CVE assignments for, leading to more Grype findings on npm-heavy images.

**Why Grype uses GHSA IDs for npm:** GitHub Advisory Database (GHSA) is the primary source for npm advisories. Not all GHSA advisories have a corresponding CVE ID. Grype may report a finding as `GHSA-xxxx-yyyy-zzzz` with a `relatedVulnerabilities` field listing the CVE alias — which is why the CVE overlap analysis must expand aliases before computing Jaccard similarity.

---

## 4. OSV-Scanner

### How it works

OSV-Scanner takes the most different approach of the three:

1. **Full image export:** OSV-Scanner exports the entire container image to a temporary directory on disk as a tar archive, then unpacks it. This is the most expensive I/O step — writing several hundred MB to GB to disk.
2. **Package enumeration via scalibr:** Uses Google's `scalibr` library to enumerate packages from the unpacked filesystem. Scalibr is a universal extractor supporting OS packages, language packages, and more.
3. **Advisory-level queries:** Rather than querying by CVE ID, OSV-Scanner queries the OSV database (`api.osv.dev`) at the **advisory level** — it asks "is this package at this version affected by any OSV advisories?"
4. **Live network queries:** Unlike Trivy and Grype which use local cached DBs, OSV-Scanner makes HTTP requests to the OSV API. This adds network latency per batch of packages.

**Why it's slow:** Two compounding factors:
- Full image export to disk (dominant for large images)
- Live API queries (adds latency per batch)

**Why OSV totals look different for Debian images:** OSV advisories are grouped differently from CVEs. A Debian Security Advisory (DSA) may bundle 10–15 related CVEs under a single advisory ID. OSV-Scanner reports at the advisory level, so its totals are not directly comparable to Trivy/Grype which report at the CVE level. For npm/Python images, OSV is more comparable because those advisories map more closely 1:1 to CVEs.

**Why it requires explicit image tags:** OSV-Scanner rejects image references without an explicit tag (e.g., `image/name` without `:latest`). This is a known limitation of the `scan image` subcommand — it uses the tag to construct the image reference for its internal registry pull logic.

---

## 5. Execution Time Explained

Summary of why times differ:

| Step | Trivy | Grype | OSV-Scanner |
|------|-------|-------|-------------|
| Image access | Layer extraction (fast) | Syft full traversal (slow) | Full export to disk (slowest) |
| Package identification | OS manifest parsing | Syft extraction + PURL | scalibr extraction |
| Vulnerability lookup | Local BoltDB index (O(1)) | Local DB by PURL (fast) | Live HTTP to api.osv.dev |
| Scales with | Package count (weakly) | Image size + file count | Image size (strongly) |

**Trivy on alpine:3.19: 56ms** — 15 packages, tiny image, OS manifest is a single file, BoltDB lookup is near-instant.

**Grype on alpine:3.19: 1451ms** — Same 15 packages, but Syft still has to decompress and walk the entire Alpine layer before it finds the apk manifest.

**OSV on node:20: 25.5s** — 1044 MB image written to disk, unpacked, scalibr walks ~600 packages, multiple API batches to osv.dev.

**Trivy on node:20: 346ms** — 1044 MB image, but Trivy only parses the package manifest files (dpkg status, package-lock.json) — it does not traverse every file in the layer.

---

## 6. Why Severity Scores Differ

Each tool has a different hierarchy for selecting which CVSS score to display:

| Scanner | Primary source | Fallback |
|---------|---------------|---------|
| Trivy | NVD CVSS v3 base score | Vendor score |
| Grype | Vendor advisory score (e.g. GitHub Advisory) | NVD |
| OSV-Scanner | OSV advisory severity | — |

NVD CVSS scores are assigned by a central authority based on the worst-case theoretical impact. Vendor scores (GitHub Advisory, Debian severity levels) are assigned by people closer to the affected ecosystem and tend to be more conservative.

This is why Trivy almost always assigns higher severity than Grype for the same CVE — it prefers the NVD base score, while Grype prefers the vendor score which may be lower.

---

## 7. Fix Status Source

Fix status is **not computed by the scanners** — it is read from the advisory databases:

- **Trivy:** Reads `Status` from Debian Security Tracker / Alpine SecDB records embedded in its DB. The tracker explicitly states whether a fix has been released into the distro repository.
- **Grype:** Reads `fix.state` from the advisory record in its DB, which mirrors the upstream advisory's stated fix status.
- **OSV-Scanner:** Does not report per-finding fix status in its standard output format.

When Debian marks a CVE as `will_not_fix` (internally tracked as "ignored"), both Trivy and Grype reflect this in their output — Trivy as `will_not_fix`, Grype as `wont-fix`.

---

*See also: `experiment_log.md §10` (notable findings), `analysis_narrative.md §2` (methodology notes), `logs/analysis_results.txt` (quantitative tables).*
