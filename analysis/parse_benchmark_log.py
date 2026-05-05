#!/usr/bin/env python3
"""
parse_benchmark_log.py — Parse logs/benchmark.log → logs/benchmark_summary.json.

Handles any number of runs per image/tool. Safe to re-run; rewrites the JSON.
Uses only the last complete session in benchmark.log to avoid mixing runs across
different benchmark invocations. If logs/benchmark_trivy.log exists, its Trivy
data replaces the Trivy data from benchmark.log (used when Trivy is re-run
separately to fix DB warmup issues).

Usage:
    python3 parse_benchmark_log.py
    python3 parse_benchmark_log.py --log logs/benchmark.log
    python3 parse_benchmark_log.py --trivy-log logs/benchmark_trivy.log
"""

import argparse
import json
import os
import re
import statistics

ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS    = os.path.join(ROOT, "logs")
DERIVED = os.path.join(ROOT, "data", "derived")

IMAGES = [
    ("alpine_3.19",           "alpine:3.19",                "C",  7.1),
    ("nginx_latest",          "nginx:latest",               "C",  153.5),
    ("node_20",               "node:20",                    "C",  1044.7),
    ("python_3.12",           "python:3.12",                "C",  1055.6),
    ("nginx_1.19",            "nginx:1.19",                 "B",  127.0),
    ("node_14",               "node:14",                    "B",  869.5),
    ("python_3.8",            "python:3.8",                 "B",  949.3),
    ("vulnerables_web-dvwa",  "vulnerables/web-dvwa:latest","A",  678.8),
    ("bkimminich_juice-shop", "bkimminich/juice-shop:latest","A", 467.3),
]

# Pattern: <timestamp> <safe> <tool> run<N> <ms>ms <size>MB
LINE_RE = re.compile(
    r"^\S+\s+(\S+)\s+(trivy|grype|osv)\s+run(\d+)\s+(\d+)ms"
)


def parse(log_path: str) -> dict:
    """Return {safe: {tool: [ms, ...]}} from the last complete session in benchmark.log.

    A complete session is delimited by a benchmark_start / benchmark_end pair.
    Using only the last complete session avoids mixing runs from different machines
    or database snapshots when the log spans multiple benchmark invocations.
    Falls back to all lines if no complete session is found.
    """
    with open(log_path) as f:
        lines = f.readlines()

    # Find the last benchmark_start that is followed by a benchmark_end
    last_start = None
    for i, line in enumerate(lines):
        if line.startswith("benchmark_start"):
            last_start = i
    has_end = any(l.startswith("benchmark_end") for l in lines[last_start + 1:]) if last_start is not None else False

    session_lines = lines[last_start + 1:] if (last_start is not None and has_end) else lines

    runs: dict = {}
    for line in session_lines:
        if line.startswith("benchmark_end"):
            break
        m = LINE_RE.match(line.strip())
        if not m:
            continue
        safe, tool, _run, ms = m.group(1), m.group(2), m.group(3), int(m.group(4))
        runs.setdefault(safe, {}).setdefault(tool, []).append(ms)
    return runs


def summarise(runs: dict) -> list:
    summary = []
    for safe, image, group, size_mb in IMAGES:
        entry = {"safe": safe, "image": image, "group": group, "size_mb": size_mb}
        for tool in ("trivy", "grype", "osv"):
            ms_list = runs.get(safe, {}).get(tool, [])
            mean = statistics.mean(ms_list) if ms_list else 0
            sd   = statistics.stdev(ms_list) if len(ms_list) > 1 else 0
            entry[tool] = {
                "runs_ms": ms_list,
                "n":       len(ms_list),
                "mean_ms": round(mean),
                "sd_ms":   round(sd),
            }
        summary.append(entry)
    return summary


def parse_trivy_log(log_path: str) -> dict:
    """Return {safe: [ms, ...]} from a benchmark_trivy.log (last complete session)."""
    with open(log_path) as f:
        lines = f.readlines()

    last_start = None
    for i, line in enumerate(lines):
        if line.startswith("benchmark_trivy_start"):
            last_start = i
    has_end = any(l.startswith("benchmark_trivy_end") for l in lines[last_start + 1:]) if last_start is not None else False
    session_lines = lines[last_start + 1:] if (last_start is not None and has_end) else lines

    trivy: dict = {}
    for line in session_lines:
        if line.startswith("benchmark_trivy_end"):
            break
        m = LINE_RE.match(line.strip())
        if m and m.group(2) == "trivy":
            safe, ms = m.group(1), int(m.group(4))
            trivy.setdefault(safe, []).append(ms)
    return trivy


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=os.path.join(LOGS, "benchmark.log"))
    parser.add_argument("--trivy-log", default=None,
                        help="Optional separate Trivy log to override Trivy data from --log")
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[ERROR] Log not found: {args.log}")
        print("  Run ./benchmark.sh [N] first (default N=30).")
        raise SystemExit(1)

    runs = parse(args.log)

    # Auto-detect benchmark_trivy.log alongside the main log if --trivy-log not given
    default_trivy_log = os.path.join(LOGS, "benchmark_trivy.log")
    trivy_log_path = args.trivy_log or (default_trivy_log if os.path.exists(default_trivy_log) else None)

    if trivy_log_path:
        print(f"Overriding Trivy data from: {trivy_log_path}")
        trivy_override = parse_trivy_log(trivy_log_path)
        for safe, ms_list in trivy_override.items():
            runs.setdefault(safe, {})["trivy"] = ms_list

    summary = summarise(runs)

    out_path = os.path.join(DERIVED, "benchmark_summary.json")
    with open(out_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Parsed {args.log}")
    for entry in summary:
        s = entry["safe"]
        for tool in ("trivy", "grype", "osv"):
            n = entry[tool]["n"]
            mean = entry[tool]["mean_ms"]
            sd   = entry[tool]["sd_ms"]
            print(f"  {s:<32} {tool:<6} n={n:>3}  mean={mean:>7}ms  sd={sd:>6}ms")
    print(f"\nWrote: {out_path}")


if __name__ == "__main__":
    main()
