"""Suppression/exception YAML loader.

Exceptions live as version-controlled YAML under a directory (typically
policy/exceptions/), one file per exception, reviewed via the same PR
process as code. See docs/notes_suppression_workflow_design.md for the
governance rationale.

Each file wraps its content under a top-level `exception:` key (matching
the design doc's schema). This loader unwraps that into a flat list of
exception dicts, ready to merge into the OPA input payload as
input.exceptions.

A malformed file (bad YAML, missing required fields) is skipped with a
stderr warning rather than aborting the whole gate run -- a single bad
exception file should not take down an otherwise-working CI gate. Real
governance enforcement happens at PR review time, not at gate-eval time.
"""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path
from typing import List

import yaml

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")


def _stringify_dates(obj):
    """PyYAML parses unquoted ISO dates (e.g. 2027-01-01) into
    datetime.date objects, which are not JSON-serializable and would
    crash json.dumps() downstream in run_gate(). Recursively convert
    any date/datetime value to its ISO string form."""
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _stringify_dates(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_stringify_dates(v) for v in obj]
    return obj


def validate_exception(exc: dict, *, source: Path) -> List[str]:
    """Return a list of validation error strings; empty list = valid."""
    errors = []

    cve_id = exc.get("cve_id")
    if not cve_id:
        errors.append("missing cve_id")
    elif not _CVE_RE.match(cve_id):
        errors.append(f"cve_id '{cve_id}' does not match ^CVE-\\d{{4}}-\\d+$")

    if not exc.get("expires") and not exc.get("expires_when"):
        errors.append("must set at least one of: expires, expires_when")

    approval = exc.get("approval") or {}
    if not approval.get("approver"):
        errors.append("missing approval.approver")
    if not approval.get("reasoning"):
        errors.append("missing approval.reasoning")

    return errors


def load_exceptions(exceptions_dir: Path) -> List[dict]:
    """Read every *.yaml/*.yml under exceptions_dir, validate, and return
    a flat list of exception dicts (the `exception:` wrapper unwrapped).

    Raises FileNotFoundError if exceptions_dir itself does not exist
    (an explicitly-passed missing directory is almost certainly a config
    typo, not "no exceptions exist", so it should not fail silently).
    """
    exceptions_dir = Path(exceptions_dir)
    if not exceptions_dir.exists():
        raise FileNotFoundError(f"exceptions directory not found: {exceptions_dir}")

    result: List[dict] = []
    for path in sorted(exceptions_dir.glob("*.yaml")) + sorted(exceptions_dir.glob("*.yml")):
        try:
            doc = _stringify_dates(yaml.safe_load(path.read_text()))
        except yaml.YAMLError as exc:
            print(f"[policy-gate] skipping invalid exception {path}: YAML parse error: {exc}",
                  file=sys.stderr)
            continue

        if not isinstance(doc, dict) or "exception" not in doc:
            print(f"[policy-gate] skipping invalid exception {path}: "
                  f"missing top-level 'exception:' key", file=sys.stderr)
            continue

        exc_obj = doc["exception"]
        errors = validate_exception(exc_obj, source=path)
        if errors:
            print(f"[policy-gate] skipping invalid exception {path}: " + "; ".join(errors),
                  file=sys.stderr)
            continue

        result.append(exc_obj)

    return result
