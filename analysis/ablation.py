#!/usr/bin/env python3
"""
ablation.py — Leave-one-out ablation on p_gate's signals across all 30
images: consensus, OSV confirmation, KEV, the block-tier EPSS threshold,
and layer-aware routing.

Reuses the already-enriched, already-verified per-image input files
(policy/output/<safe>_enriched_rule.json, produced by evaluate_all.py's
2026-06-21 run) rather than re-fetching NVD/OSV/EPSS/KEV live — this
holds the dataset and enrichment fixed and varies only the policy
config/signal, the same methodology p_gate's own P1-P7 development used
(Section 4.2.1 of the thesis). No network calls, fully reproducible.

For each ablation, one signal is neutralised across every finding in
every image (e.g. "disable consensus" = treat every finding as detected
by both scanners), the tri-state gate is re-evaluated via `opa eval`
against the unmodified p_gate.rego, and the resulting block/review/pass
counts are compared to the baseline (unmodified enrichment + unmodified
config).

Usage: python3 analysis/ablation.py
"""
import copy
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_DIR = HERE.parent / "policy"
OUTPUT_DIR = POLICY_DIR / "output"
REGO_DIR = POLICY_DIR / "rego"
CONFIG_PATH = POLICY_DIR / "configs" / "p_gate.json"
TMP_DIR = HERE.parent / "data" / "derived" / "ablation_tmp"

SAFE_NAMES = [
    "alpine_3.19", "nginx_1.29.7", "node_20", "python_3.12",
    "nginx_1.19", "node_14", "python_3.8",
    "vulnerables_web-dvwa", "bkimminich_juice-shop",
    "v01_log4shell", "v03_text4shell", "v04_spring4shell",
    "webgoat_webgoat", "citizenstig_nowasp",
    "golang_1.16-alpine", "ruby_2.5-slim", "eclipse-temurin_8-jre",
    "dotnet_runtime_3.1", "php_7.4-apache", "rust_1.56-slim",
    "node_12", "python_2.7",
    "golang_1.23-alpine", "ruby_3.3-slim", "eclipse-temurin_21-jre",
    "dotnet_runtime_8.0", "php_8.3-apache", "rust_1.82-slim",
    "node_22", "python_3.13-slim",
]

# Published Table 5.6 CRITICAL counts (rule classifier, 2026-06-21 run),
# used to self-check that opa eval reproduces the thesis exactly before
# trusting any ablation delta.
PUBLISHED_VERDICT = {
    "vulnerables_web-dvwa": ("BLOCK", 328), "bkimminich_juice-shop": ("REVIEW", 9),
    "v01_log4shell": ("BLOCK", 4), "v03_text4shell": ("REVIEW", 2),
    "v04_spring4shell": ("BLOCK", 6), "webgoat_webgoat": ("BLOCK", 107),
    "citizenstig_nowasp": ("REVIEW", 0),
    "nginx_1.19": ("BLOCK", 42), "node_14": ("BLOCK", 23), "python_3.8": ("REVIEW", 191),
    "golang_1.16-alpine": ("REVIEW", 9), "ruby_2.5-slim": ("BLOCK", 30),
    "eclipse-temurin_8-jre": ("REVIEW", 1), "dotnet_runtime_3.1": ("REVIEW", 5),
    "php_7.4-apache": ("BLOCK", 96), "rust_1.56-slim": ("REVIEW", 41),
    "node_12": ("BLOCK", 72), "python_2.7": ("BLOCK", 184),
    "alpine_3.19": ("PASS", 0), "nginx_1.29.7": ("PASS", 0), "node_20": ("REVIEW", 33),
    "python_3.12": ("REVIEW", 0), "golang_1.23-alpine": ("REVIEW", 8),
    "ruby_3.3-slim": ("REVIEW", 7), "eclipse-temurin_21-jre": ("REVIEW", 1),
    "dotnet_runtime_8.0": ("REVIEW", 6), "php_8.3-apache": ("REVIEW", 30),
    "rust_1.82-slim": ("REVIEW", 18), "node_22": ("REVIEW", 41),
    "python_3.13-slim": ("REVIEW", 6),
}


def opa_eval(input_path: Path, query: str):
    proc = subprocess.run(
        ["opa", "eval", "--input", str(input_path),
         "--data", str(REGO_DIR), "--format", "json", query],
        capture_output=True, text=True, check=True,
    )
    out = json.loads(proc.stdout)
    expressions = out.get("result", [{}])[0].get("expressions", [{}])
    return expressions[0].get("value")


def verdict_for(safe: str, config: dict, mutate_finding=None,
                classifier: str = "rule") -> str:
    enriched = json.loads(
        (OUTPUT_DIR / f"{safe}_enriched_{classifier}.json").read_text())
    if mutate_finding is not None:
        enriched = copy.deepcopy(enriched)
        for f in enriched["findings"]:
            mutate_finding(f)
    payload = dict(enriched)
    payload["config"] = {k: v for k, v in config.items() if not k.startswith("_")}

    TMP_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = TMP_DIR / f"{safe}_ablation_input.json"
    tmp_path.write_text(json.dumps(payload))

    block = opa_eval(tmp_path, "data.vuln.gate.block") or []
    review = opa_eval(tmp_path, "data.vuln.gate.review") or []
    if block:
        return "BLOCK"
    if review:
        return "REVIEW"
    return "PASS"


# --- Ablations ---------------------------------------------------------
#
# Direction rule. The gate's block condition is a disjunction of two paths:
# the KEV path, and the corroborated-CRITICAL path, which is itself a
# conjunction of six conditions (is_critical, is_consensus, has_fix,
# nvd_status_in, osv_confirms_advisory, osv_has_fix) plus an EPSS bar.
#
#   * A CONJUNCT of the corroborated path is neutralised PERMISSIVELY:
#     set it always-true, asking "what was this condition filtering out?"
#   * The DISJUNCTIVE KEV path is neutralised RESTRICTIVELY: delete the
#     path, asking "what was this path letting through?" Making KEV
#     always-true would block everything and measure nothing.
#
# Each ablation below records its direction so the reported table can
# state per signal which operation was applied.

def no_op(f):
    pass


def disable_consensus(f):
    f["detected_by"] = ["trivy", "grype"]  # every finding treated as consensus


def disable_fix_requirement(f):
    f["fix_version"] = "ablated-fix-signal"


def disable_nvd_status(f):
    f["nvd"] = {"status": "Analyzed", "rejected": False, "disputed": False}


def disable_osv(f):
    f["osv"] = {"advisory_found": True, "fix_version": "ablated-osv-signal",
                "affected_ecosystems": []}


def disable_kev(f):
    f["kev"] = {"in_kev": False, "date_added": None, "due_date": None,
                "ransomware_use": None}


def disable_layer_routing(f):
    # Use the OS floor uniformly instead of the app/os asymmetry — removes
    # layer as a discriminating signal without removing the floor itself.
    f["layer"] = "os"


BASE_CONFIG = json.loads(CONFIG_PATH.read_text())

EPSS_OFF_CONFIG = {**BASE_CONFIG, "block_epss_threshold": 0.0,
                   "review_critical_app_min_epss": 0.0,
                   "review_critical_os_min_epss": 0.0,
                   "review_critical_unknown_min_epss": 0.0}

# (label, config_override, finding_mutator, direction, classifier)
ABLATIONS = [
    ("baseline (unmodified)", BASE_CONFIG, no_op, "--", "rule"),
    ("consensus requirement", BASE_CONFIG, disable_consensus, "permissive", "rule"),
    ("fix availability", BASE_CONFIG, disable_fix_requirement, "permissive", "rule"),
    ("NVD status", BASE_CONFIG, disable_nvd_status, "permissive", "rule"),
    ("OSV confirmation", BASE_CONFIG, disable_osv, "permissive", "rule"),
    ("EPSS threshold", EPSS_OFF_CONFIG, no_op, "permissive", "rule"),
    ("KEV block path", BASE_CONFIG, disable_kev, "restrictive", "rule"),
    ("layer routing (rule classifier)", BASE_CONFIG, disable_layer_routing,
     "permissive", "rule"),
    # The rule classifier labels every CRITICAL finding os-layer on the one
    # image where routing has any effect (Section 5.5.4), so the rule-classifier
    # row above cannot distinguish "routing is inert" from "classifier produced
    # uniform labels". Re-run under the LLM classifier to separate the two.
    ("layer routing (LLM classifier)", BASE_CONFIG, disable_layer_routing,
     "permissive", "agent"),
]


def main():
    # --- Self-check: baseline must reproduce the published Table 5.6
    # verdicts exactly before any ablation delta is trusted.
    mismatches = []
    for safe in SAFE_NAMES:
        got = verdict_for(safe, BASE_CONFIG, no_op)
        expected = PUBLISHED_VERDICT[safe][0]
        if got != expected:
            mismatches.append((safe, expected, got))
    if mismatches:
        print("SELF-CHECK FAILED — baseline does not reproduce Table 5.6:")
        for safe, exp, got in mismatches:
            print(f"  {safe}: expected {exp}, got {got}")
        return
    print(f"Self-check passed: opa eval reproduces all {len(SAFE_NAMES)} "
          f"published Table 5.6 verdicts exactly.\n")

    # Per-classifier baselines: the LLM-classifier row must be compared to
    # the LLM-classifier baseline, not the rule-classifier one.
    baselines = {}
    for clf in ("rule", "agent"):
        baselines[clf] = {safe: verdict_for(safe, BASE_CONFIG, no_op, clf)
                          for safe in SAFE_NAMES}

    results = {}
    print(f"{'Signal':<34}{'Direction':<13}{'BLOCK':>6}{'REVIEW':>7}{'PASS':>6}{'Moved':>7}")
    for label, config, mutator, direction, clf in ABLATIONS:
        counts = {"BLOCK": 0, "REVIEW": 0, "PASS": 0}
        per_image = {}
        for safe in SAFE_NAMES:
            v = verdict_for(safe, config, mutator, clf)
            counts[v] += 1
            per_image[safe] = v
        base = baselines[clf]
        moved = [(s, base[s], per_image[s]) for s in SAFE_NAMES
                 if per_image[s] != base[s]]
        results[label] = (counts, per_image, direction, clf, moved)
        n_moved = "--" if label.startswith("baseline") else str(len(moved))
        print(f"{label:<34}{direction:<13}{counts['BLOCK']:>6}"
              f"{counts['REVIEW']:>7}{counts['PASS']:>6}{n_moved:>7}")

    print("\nPer-image tier movement vs the matching per-classifier baseline:")
    for label, (counts, per_image, direction, clf, moved) in results.items():
        if label.startswith("baseline"):
            continue
        print(f"\n  {label} [{direction}, {clf} classifier]: {len(moved)} image(s) moved")
        for safe, before, after in moved:
            print(f"    {safe:<28} {before} -> {after}")

    # Layer routing changes finding counts even where it changes no verdict.
    # Report the deny-set size on web-dvwa under both classifiers so the
    # "no verdict moved" result cannot be misread as "routing is inert".
    print("\nLayer-routing deny-set size on vulnerables_web-dvwa "
          "(verdict stays BLOCK in every case):")
    for clf in ("rule", "agent"):
        for lbl, mut in (("routing on ", no_op), ("routing off", disable_layer_routing)):
            enriched = json.loads(
                (OUTPUT_DIR / f"vulnerables_web-dvwa_enriched_{clf}.json").read_text())
            enriched = copy.deepcopy(enriched)
            for f in enriched["findings"]:
                mut(f)
            payload = dict(enriched)
            payload["config"] = {k: v for k, v in BASE_CONFIG.items()
                                 if not k.startswith("_")}
            TMP_DIR.mkdir(parents=True, exist_ok=True)
            p = TMP_DIR / "layer_probe_input.json"
            p.write_text(json.dumps(payload))
            block = opa_eval(p, "data.vuln.gate.block") or []
            review = opa_eval(p, "data.vuln.gate.review") or []
            print(f"    {clf:<6} {lbl}: block={len(block):>3}  review={len(review):>4}")


if __name__ == "__main__":
    main()
