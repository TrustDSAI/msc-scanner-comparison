"""Rule-based layer classifier.

Maps each finding to "app" or "os" using ecosystem-string heuristics derived
from scanner output. The taxonomy follows OSV / Trivy / Grype conventions:

    OS ecosystems     apk, deb, debian, rpm, alpine, ubuntu, centos,
                      amazon, rhel, oracle, suse, photon, mariner, wolfi,
                      gentoo, archlinux, opensuse, chainguard

    APP ecosystems    npm, python-pkg, pip, pypi, gem, rubygems,
                      maven, java-archive, jar, go-module, gomod,
                      cargo, crates.io, nuget, composer, conan,
                      hex, swift, pub, cocoapods, packagist

Anything not in either bucket falls through to "unknown". The classifier is
deterministic and acts as the baseline against which agent-based classifiers
are compared.

Known weakness: ecosystem-string heuristics misclassify OS-packaged
application code. For example, `libapache2-mod-php7.0` is delivered as a
Debian package (deb -> os) but contains application-layer PHP code that an
attacker reaches via HTTP requests. The rule classifier labels this OS;
a semantic classifier (agent) is expected to disagree on cases like this.
"""

from __future__ import annotations

from .base import Classifier, Label


_OS_ECOSYSTEMS = {
    "apk", "deb", "debian", "rpm", "alpine", "ubuntu", "centos",
    "amazon", "rhel", "oracle", "suse", "photon", "mariner", "wolfi",
    "gentoo", "archlinux", "opensuse", "chainguard",
}

_APP_ECOSYSTEMS = {
    "npm", "node-pkg",
    "python-pkg", "pip", "pypi",
    "gem", "rubygems",
    "maven", "java-archive", "jar",
    "go-module", "gomod", "gobinary",
    "cargo", "crates.io",
    "nuget", "composer", "conan",
    "hex", "swift", "pub", "cocoapods", "packagist",
}


class RuleClassifier(Classifier):
    name = "rule"

    def classify(self, finding: dict) -> Label:
        eco = (finding.get("ecosystem") or "").lower()
        if eco in _OS_ECOSYSTEMS:
            return Label(layer="os", source="rule",
                         reasoning=f"ecosystem '{eco}' in OS taxonomy")
        if eco in _APP_ECOSYSTEMS:
            return Label(layer="app", source="rule",
                         reasoning=f"ecosystem '{eco}' in app taxonomy")
        return Label(layer="unknown", source="rule",
                     confidence=0.0,
                     reasoning=f"ecosystem '{eco}' not in taxonomy")
