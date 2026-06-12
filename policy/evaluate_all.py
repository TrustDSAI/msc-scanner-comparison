"""Run the full policy pipeline across all 9 study images.

For each image:
    1. Load raw scanner outputs.
    2. Classify each finding's layer (rule classifier; optionally agent).
    3. Merge into a normalised policy input.
    4. Enrich CRITICAL findings (NVD, OSV, EPSS).
    5. Evaluate every (policy, config) combination via `opa eval`.

Outputs:
    output/<safe>_input_<classifier>.json     normalised input per image+classifier
    output/<safe>_enriched_<classifier>.json  enriched version
    output/verdict_matrix.csv                 row per (image, classifier, policy_config)
    output/summary.md                         human-readable summary

If ANTHROPIC_API_KEY or OPENAI_API_KEY is set, an agent-based classifier
also runs and produces a parallel matrix for comparison.
"""

from __future__ import annotations

import asyncio
import csv
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader. Reads KEY=VALUE lines, skips comments/blank,
    and only sets variables that aren't already in the environment."""
    import os as _os
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if k and v and k not in _os.environ:
            _os.environ[k] = v


_load_dotenv(HERE / ".env")


from normalisers import ADAPTERS
from normalisers.merge import merge
from normalisers.trivy import os_metadata as trivy_os_metadata
from enrichers import ENRICHERS
from enrichers.cache import configure as configure_cache
from enrichers.eol import EOLEnricher
from classifiers import CLASSIFIERS

# --- Configuration ----------------------------------------------------

DATA_RAW    = HERE.parent / "data" / "raw"
OUTPUT_DIR  = HERE / "output"
REGO_DIR    = HERE / "rego"
CONFIGS_DIR = HERE / "configs"
CACHE_DIR   = HERE / ".cache" / "enrich"

# (safe_name, label, group)
# EOL status is NOT hardcoded; it is read from Trivy's Metadata.OS.EOSL
# during normalisation. Trivy's EOSL describes the OS distribution layer.
# Language-runtime EOL (e.g. python 3.8 lifecycle) is not captured by this
# field and would require an endoflife.date enricher (future work).
IMAGES = [
    ("alpine_3.19",                 "alpine:3.19",                "C"),
    ("nginx_1.29.7",                "nginx:1.29.7",               "C"),
    ("node_20",                     "node:20",                    "C"),
    ("python_3.12",                 "python:3.12",                "C"),
    ("nginx_1.19",                  "nginx:1.19",                 "B"),
    ("node_14",                     "node:14",                    "B"),
    ("python_3.8",                  "python:3.8",                 "B"),
    ("vulnerables_web-dvwa",        "vulnerables/web-dvwa",       "A"),
    ("bkimminich_juice-shop",       "bkimminich/juice-shop",      "A"),
]

# (display_name, policy_package, config_path_or_None)
POLICY_RUNS: list[tuple[str, str, Path | None]] = [
    ("P1",          "vuln.p1", None),
    ("P2",          "vuln.p2", None),
    ("P3",          "vuln.p3", None),
    ("P4_strict",   "vuln.p4", CONFIGS_DIR / "p4_strict.json"),
    ("P4_relaxed",  "vuln.p4", CONFIGS_DIR / "p4_relaxed.json"),
    ("P5_layer",    "vuln.p5", CONFIGS_DIR / "p5_layer_aware.json"),
    ("P6_eol_strict",      "vuln.p6", CONFIGS_DIR / "p6_eol_strict.json"),
    ("P6_eol_permissive",  "vuln.p6", CONFIGS_DIR / "p6_eol_permissive.json"),
]


# --- Steps ------------------------------------------------------------

_eol_enricher = EOLEnricher()


def normalise_image(safe: str, label: str, group: str,
                    classifier_name: str) -> dict:
    scanner_files: dict = {}
    for scanner in ADAPTERS:
        p = DATA_RAW / scanner / f"{safe}_{scanner}.json"
        if p.exists():
            scanner_files[scanner] = p
    if not scanner_files:
        raise FileNotFoundError(f"no scanner output for {safe}")

    classifier = CLASSIFIERS[classifier_name]
    findings_lists = [ADAPTERS[name](path) for name, path in scanner_files.items()]

    # Look up EOL status dynamically.
    # Priority chain: endoflife.date label lookup ->
    #                 Trivy OS-layer EOSL ->
    #                 LLM semantic fallback
    trivy_os = trivy_os_metadata(scanner_files["trivy"]) if "trivy" in scanner_files else {}
    eol_info = _eol_enricher.enrich_image({"label": label, "trivy_os": trivy_os})

    return {
        "image": {
            "safe":      safe,
            "label":     label,
            "group":     group,
            "eol":       eol_info["eol"],
            "eol_date":  eol_info.get("eol_date"),
            "eol_source": eol_info["source"],
        },
        "snapshot_date":    "2026-03-31",
        "scanners":         sorted(scanner_files),
        "classifier":       classifier_name,
        "findings":         merge(*findings_lists, classifier=classifier),
    }


async def _enrich_one(finding: dict) -> dict:
    log = []
    for er in ENRICHERS:
        result = await er.enrich(finding)
        finding[er.field_name] = result.data
        if not result.ok:
            log.append({"source": er.field_name, "reason": result.reason})
    if log:
        finding["enrichment_log"] = log
    return finding


async def enrich_critical_only(payload: dict, network_ok: bool) -> dict:
    for f in payload["findings"]:
        if f.get("severity") == "CRITICAL" and network_ok:
            await _enrich_one(f)
        else:
            for er in ENRICHERS:
                f.setdefault(er.field_name, _empty(er.field_name))
    return payload


def _empty(field_name: str) -> dict:
    if field_name == "nvd":
        return {"status": None, "rejected": False, "disputed": False}
    if field_name == "osv":
        return {"advisory_found": False, "fix_version": None, "affected_ecosystems": []}
    if field_name == "epss":
        return {"score": None, "percentile": None, "as_of": None}
    return {}


def opa_eval(input_path: Path, query: str) -> object:
    proc = subprocess.run(
        ["opa", "eval", "--input", str(input_path),
         "--data", str(REGO_DIR), "--format", "json", query],
        capture_output=True, text=True, check=True,
    )
    out = json.loads(proc.stdout)
    expressions = out.get("result", [{}])[0].get("expressions", [{}])
    return expressions[0].get("value")


def _inject_config(input_path: Path, out_path: Path, config_path: Path | None) -> None:
    """Write a copy of input_path with an optional `config` block grafted in."""
    payload = json.loads(input_path.read_text())
    if config_path is not None:
        cfg = json.loads(config_path.read_text())
        cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}
        payload["config"] = cfg
    out_path.write_text(json.dumps(payload, indent=2))


def probe_network() -> bool:
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(
            "https://api.first.org/data/v1/epss?cve=CVE-2024-38428",
            timeout=5):
            return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


# --- Orchestrator -----------------------------------------------------

@dataclass
class Row:
    image: str
    group: str
    classifier: str
    policy: str
    block: bool
    deny_count: int
    critical_total: int


def _layer_counts(findings: list[dict]) -> dict[str, int]:
    out = {"app": 0, "os": 0, "unknown": 0}
    for f in findings:
        if f.get("severity") != "CRITICAL":
            continue
        layer = f.get("layer", "unknown")
        out[layer] = out.get(layer, 0) + 1
    return out


def run() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    configure_cache(CACHE_DIR)

    network_ok = probe_network()
    print(f"network probe: {'OK' if network_ok else 'unreachable'}")

    classifiers_to_run = [name for name in CLASSIFIERS]
    print(f"classifiers available: {classifiers_to_run}")

    rows: list[Row] = []
    classifier_compare: list[dict] = []  # for cross-classifier diff if multiple

    per_image_layer: dict[tuple[str, str], dict[str, int]] = {}

    for safe, label, group in IMAGES:
        print(f"--- {label} [Group {group}] ---")
        for clf in classifiers_to_run:
            normalised = normalise_image(safe, label, group, clf)
            input_path = OUTPUT_DIR / f"{safe}_input_{clf}.json"
            input_path.write_text(json.dumps(normalised, indent=2))

            enriched = asyncio.run(enrich_critical_only(
                json.loads(input_path.read_text()),
                network_ok=network_ok,
            ))
            enriched_path = OUTPUT_DIR / f"{safe}_enriched_{clf}.json"
            enriched_path.write_text(json.dumps(enriched, indent=2))

            crit_total = sum(1 for f in enriched["findings"]
                             if f["severity"] == "CRITICAL")
            per_image_layer[(label, clf)] = _layer_counts(enriched["findings"])

            for policy_name, policy_pkg, config_path in POLICY_RUNS:
                # Inject config into input file for this run.
                run_input = OUTPUT_DIR / f"{safe}_{clf}_{policy_name}_input.json"
                _inject_config(enriched_path, run_input, config_path)

                block = bool(opa_eval(run_input, f"data.{policy_pkg}.block_build"))
                deny  = opa_eval(run_input, f"data.{policy_pkg}.deny") or []
                rows.append(Row(label, group, clf, policy_name,
                                block, len(deny), crit_total))

            verdict_summary = {
                row.policy: {"block": row.block, "deny": row.deny_count}
                for row in rows
                if row.image == label and row.classifier == clf
            }
            print(f"  [{clf}]  layers: {per_image_layer[(label, clf)]}  "
                  + " ".join(
                      f"{p}={'B' if verdict_summary[p]['block'] else 'p'}({verdict_summary[p]['deny']})"
                      for p in [r[0] for r in POLICY_RUNS]
                  ))

            # Cross-classifier diff scaffolding (collected after all classifiers run)
            if clf == "rule":
                continue
            rule_layer = per_image_layer.get((label, "rule"), {})
            agent_layer = per_image_layer.get((label, clf), {})
            classifier_compare.append({
                "image":  label,
                "agent":  clf,
                "rule_app": rule_layer.get("app", 0),
                "rule_os":  rule_layer.get("os", 0),
                "rule_unk": rule_layer.get("unknown", 0),
                "agent_app": agent_layer.get("app", 0),
                "agent_os":  agent_layer.get("os", 0),
                "agent_unk": agent_layer.get("unknown", 0),
            })

    # CSV matrix
    matrix_path = OUTPUT_DIR / "verdict_matrix.csv"
    with matrix_path.open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["group", "image", "classifier", "policy",
                    "block", "deny_count", "critical_total"])
        for r in rows:
            w.writerow([r.group, r.image, r.classifier, r.policy,
                        r.block, r.deny_count, r.critical_total])

    # Markdown summary
    md_lines = ["# Policy comparison matrix", "",
                f"Network probe: {'OK' if network_ok else 'unreachable'}",
                f"Classifiers: {', '.join(classifiers_to_run)}",
                ""]
    for clf in classifiers_to_run:
        md_lines += [f"## Classifier: {clf}", "",
                     "| Group | Image | CRIT | app/os/? | "
                     + " | ".join(p[0] for p in POLICY_RUNS) + " |",
                     "|-------|-------|------|----------|"
                     + "|".join(["---"] * len(POLICY_RUNS)) + "|"]
        by_image: dict[str, dict[str, Row]] = {}
        for r in rows:
            if r.classifier != clf:
                continue
            by_image.setdefault(r.image, {})[r.policy] = r
        for safe, label, group in IMAGES:
            if label not in by_image:
                continue
            verdicts = by_image[label]
            crit = next(iter(verdicts.values())).critical_total
            layers = per_image_layer.get((label, clf), {})
            md_lines.append(
                f"| {group} | {label} | {crit} | "
                f"{layers.get('app',0)}/{layers.get('os',0)}/{layers.get('unknown',0)} | "
                + " | ".join(
                    f"{'**B**' if verdicts[p[0]].block else 'pass'} ({verdicts[p[0]].deny_count})"
                    for p in POLICY_RUNS
                ) + " |"
            )
        md_lines.append("")

    if classifier_compare:
        md_lines += ["## Classifier comparison (CRITICAL findings only)", "",
                     "| Image | Agent | rule app/os/? | agent app/os/? |",
                     "|-------|-------|---------------|----------------|"]
        for c in classifier_compare:
            md_lines.append(
                f"| {c['image']} | {c['agent']} | "
                f"{c['rule_app']}/{c['rule_os']}/{c['rule_unk']} | "
                f"{c['agent_app']}/{c['agent_os']}/{c['agent_unk']} |"
            )

    (OUTPUT_DIR / "summary.md").write_text("\n".join(md_lines) + "\n")

    print(f"\nWrote {matrix_path}")
    print(f"Wrote {OUTPUT_DIR / 'summary.md'}")


if __name__ == "__main__":
    run()
