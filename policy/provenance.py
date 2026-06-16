"""Provenance metadata: what produced a given gate verdict.

A saved verdict JSON is otherwise unattributable months later — there is
no record of which Trivy/Grype/OPA versions, which policy bundle, or which
config thresholds produced it. This module assembles that record so every
verdict (CLI and API) and /health carry it.

Tool version probes are cached at module level: a long-lived API process
should not shell out to `trivy --version` etc. on every request. The Rego
bundle fingerprint is NOT cached against a fixed path, since --rego-dir can
point anywhere per call; hashing a handful of small .rego files is cheap.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_TIMEOUT = 5

_tool_versions_cache: Optional[dict] = None


def _probe_trivy() -> Optional[str]:
    try:
        out = subprocess.run(["trivy", "--version"], capture_output=True,
                              text=True, timeout=_TIMEOUT, check=True).stdout
        m = re.search(r"Version:\s*(\S+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def _probe_grype() -> Optional[str]:
    try:
        out = subprocess.run(["grype", "version"], capture_output=True,
                              text=True, timeout=_TIMEOUT, check=True).stdout
        m = re.search(r"Version:\s*(\S+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def _probe_opa() -> Optional[str]:
    try:
        out = subprocess.run(["opa", "version"], capture_output=True,
                              text=True, timeout=_TIMEOUT, check=True).stdout
        m = re.search(r"Version:\s*(\S+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def get_tool_versions() -> dict:
    """Returns {"trivy": "0.69.3"|None, "grype": ..., "opa": ...}.

    Each tool is probed independently so one tool's version-string format
    shifting in a future release never blanks out the others or raises.
    Cached after first call for the lifetime of the process.
    """
    global _tool_versions_cache
    if _tool_versions_cache is None:
        _tool_versions_cache = {
            "trivy": _probe_trivy(),
            "grype": _probe_grype(),
            "opa":   _probe_opa(),
        }
    return _tool_versions_cache


def fingerprint_rego_dir(rego_dir: Path) -> str:
    """sha256 over sorted (relative_path, content) pairs of every .rego
    file under rego_dir. Stable across runs, changes whenever any policy
    file's content changes. Returns "sha256:<hex>".
    """
    rego_dir = Path(rego_dir)
    h = hashlib.sha256()
    for path in sorted(rego_dir.rglob("*.rego")):
        rel = path.relative_to(rego_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(path.read_bytes())
    return f"sha256:{h.hexdigest()}"


def build_provenance(*, rego_dir: Path, policy_package: str,
                      config: dict, classifier: str,
                      scan_timestamp: Optional[str] = None) -> dict:
    """Assemble the full provenance block for one verdict."""
    return {
        "tool_versions":             get_tool_versions(),
        "policy_bundle_fingerprint": fingerprint_rego_dir(rego_dir),
        "policy_package":            policy_package,
        "rego_dir":                  str(Path(rego_dir).resolve()),
        "classifier":                classifier,
        "config":                    config,
        "build_sha":                 os.environ.get("POLICY_GATE_BUILD_SHA") or None,
        "scan_timestamp":            scan_timestamp or now_iso(),
    }


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
