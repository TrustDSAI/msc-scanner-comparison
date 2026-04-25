#!/usr/bin/env python3
"""
parse_benchmark_log.py — Parse logs/benchmark.log → logs/benchmark_summary.json.

Handles any number of runs per image/tool. Safe to re-run; rewrites the JSON.

Usage:
    python3 parse_benchmark_log.py
    python3 parse_benchmark_log.py --log logs/benchmark.log
"""

import argparse
import json
import os
import re
import statistics

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS = os.path.join(SCRIPT_DIR, "logs")

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
    """Return {safe: {tool: [ms, ...]}} from benchmark.log."""
    runs: dict = {}
    with open(log_path) as f:
        for line in f:
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default=os.path.join(LOGS, "benchmark.log"))
    args = parser.parse_args()

    if not os.path.exists(args.log):
        print(f"[ERROR] Log not found: {args.log}")
        print("  Run ./benchmark.sh [N] first (default N=30).")
        raise SystemExit(1)

    runs = parse(args.log)
    summary = summarise(runs)

    out_path = os.path.join(LOGS, "benchmark_summary.json")
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
