"""Normalise one or more scanner JSON outputs into a unified policy input.

Each `--<scanner>` flag accepts a path to one scanner's raw JSON. Any
combination of registered scanners can be passed; adapters live in the
`normalisers/` package and are auto-discovered via the `ADAPTERS` registry.

Examples:
    # Two scanners
    python normalise.py --trivy trivy.json --grype grype.json --out input.json

    # Single scanner
    python normalise.py --trivy trivy.json --out input.json

Adding a new scanner does not require editing this file: drop a new module
into `normalisers/`, register it in `ADAPTERS`, and the corresponding
`--<scanner>` flag is created automatically.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from normalisers import ADAPTERS
from normalisers.merge import merge


def normalise(scanner_files: dict[str, Path],
              image: str = "",
              snapshot_date: str = "") -> dict:
    findings_per_scanner = [
        ADAPTERS[name](path) for name, path in scanner_files.items()
    ]
    return {
        "image":         image,
        "snapshot_date": snapshot_date,
        "findings":      merge(*findings_per_scanner),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    for scanner_name in ADAPTERS:
        parser.add_argument(
            f"--{scanner_name}",
            type=Path,
            default=None,
            help=f"path to {scanner_name} JSON output",
        )
    parser.add_argument("--out",   type=Path, required=True)
    parser.add_argument("--image", type=str, default="")
    parser.add_argument("--snapshot-date", type=str, default="")
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    scanner_files: dict[str, Path] = {}
    for scanner_name in ADAPTERS:
        path = getattr(args, scanner_name)
        if path is not None:
            scanner_files[scanner_name] = path

    if not scanner_files:
        raise SystemExit(
            "no scanner inputs provided; pass at least one of: "
            + ", ".join(f"--{s}" for s in ADAPTERS)
        )

    payload = normalise(scanner_files, args.image, args.snapshot_date)
    args.out.write_text(json.dumps(payload, indent=2))

    findings = payload["findings"]
    n = len(findings)
    crit = sum(1 for f in findings if f["severity"] == "CRITICAL")
    consensus = sum(1 for f in findings if len(f["detected_by"]) > 1)
    print(f"{args.out}: {n} findings ({crit} CRITICAL, {consensus} cross-confirmed)")


if __name__ == "__main__":
    main()
