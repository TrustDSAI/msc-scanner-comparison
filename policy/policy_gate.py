#!/usr/bin/env python3
"""policy-gate: single-image CI/CD vulnerability gate.

Runs the full pipeline for ONE container image and emits a tri-state
verdict suitable for a CI/CD pipeline step:

    normalise (Trivy + Grype)  ->  enrich (NVD/OSV/EPSS/KEV)
        ->  classify layer  ->  opa eval (tri-state gate)

Exit codes
----------
    0   clean      no block-tier and no review-tier findings
    1   blocked    at least one block-tier finding (beyond reasonable doubt)
    2   review     no block-tier findings, but review-tier findings exist

`--fail-on` controls which tiers fail the build:
    block       exit non-zero only on block findings        (review passes)
    review      exit non-zero on block OR review findings   (default; fail-closed)
    none        always exit 0 (report-only mode)

Report formats: json (default), markdown, sarif, junit.

Scanner inputs
--------------
By default the gate invokes Trivy and Grype itself (they must be on PATH;
in the bundled container image they are). Alternatively, pre-computed
scanner JSON can be supplied with --trivy / --grype to skip invocation.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def _load_dotenv(path: Path) -> None:
    import os
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v and k not in os.environ:
            os.environ[k] = v


_load_dotenv(HERE / ".env")

from normalisers import ADAPTERS
from normalisers.merge import merge
from normalisers.trivy import os_metadata as trivy_os_metadata
from enrichers import ENRICHERS
from enrichers.cache import configure as configure_cache
from enrichers.eol import EOLEnricher
from classifiers import get as get_classifier

REGO_DIR = HERE / "rego"
DEFAULT_CONFIG = HERE / "configs" / "p_gate.json"
CACHE_DIR = HERE / ".cache" / "enrich"
GATE_PKG = "vuln.gate"


# --- Scanner invocation ----------------------------------------------

def run_trivy(image: str, out: Path) -> None:
    subprocess.run(
        ["trivy", "image", "--quiet", "--format", "json", "--output", str(out), image],
        check=True,
    )


def run_grype(image: str, out: Path) -> None:
    with out.open("w") as fh:
        subprocess.run(["grype", image, "-o", "json"], check=True, stdout=fh)


# --- Pipeline --------------------------------------------------------

def normalise(trivy_json: Path, grype_json: Path, image: str,
              classifier_name: str) -> dict:
    findings_lists = [
        ADAPTERS["trivy"](trivy_json),
        ADAPTERS["grype"](grype_json),
    ]
    classifier = get_classifier(classifier_name)
    eol = EOLEnricher().enrich_image({
        "label":    image,
        "trivy_os": trivy_os_metadata(trivy_json),
    })
    return {
        "image": {
            "label":      image,
            "eol":        eol["eol"],
            "eol_source": eol["source"],
        },
        "findings": merge(*findings_lists, classifier=classifier),
    }


async def _enrich_one(finding: dict) -> dict:
    for er in ENRICHERS:
        result = await er.enrich(finding)
        finding[er.field_name] = result.data
    return finding


async def enrich_critical_and_high(payload: dict) -> dict:
    # Enrich CRITICAL and HIGH; lower tiers never reach a gate decision.
    for f in payload["findings"]:
        if f.get("severity") in ("CRITICAL", "HIGH"):
            await _enrich_one(f)
        else:
            for er in ENRICHERS:
                f.setdefault(er.field_name, _empty(er.field_name))
    return payload


def _empty(field: str) -> dict:
    return {
        "nvd":  {"status": None, "rejected": False, "disputed": False},
        "osv":  {"advisory_found": False, "fix_version": None, "affected_ecosystems": []},
        "epss": {"score": None, "percentile": None, "as_of": None},
        "kev":  {"in_kev": False, "date_added": None, "due_date": None, "ransomware_use": None},
    }.get(field, {})


def opa_eval(input_path: Path, query: str) -> object:
    proc = subprocess.run(
        ["opa", "eval", "--input", str(input_path),
         "--data", str(REGO_DIR), "--format", "json", query],
        capture_output=True, text=True, check=True,
    )
    out = json.loads(proc.stdout)
    exprs = out.get("result", [{}])[0].get("expressions", [{}])
    return exprs[0].get("value")


# --- Report formatters -----------------------------------------------

def report_json(verdict: dict) -> str:
    return json.dumps(verdict, indent=2)


def report_markdown(verdict: dict) -> str:
    lines = [f"# Vulnerability gate report: {verdict['image']}", ""]
    lines.append(f"**Decision:** {verdict['decision'].upper()}  "
                 f"(block: {len(verdict['block'])}, review: {len(verdict['review'])})")
    if verdict["image_eol"]:
        lines.append(f"**Image is end-of-life** (source: {verdict['image_eol_source']})")
    lines.append("")
    for tier in ("block", "review"):
        entries = verdict[tier]
        if not entries:
            continue
        lines.append(f"## {tier.title()} ({len(entries)})")
        lines.append("")
        lines.append("| CVE | Package | Version | EPSS | KEV | Reason |")
        lines.append("|-----|---------|---------|------|-----|--------|")
        for e in entries:
            epss = e.get("epss_score")
            epss_s = f"{epss:.3f}" if isinstance(epss, (int, float)) else "-"
            kev_s = "yes" if e.get("in_kev") else "-"
            lines.append(f"| {e['cve_id']} | {e['package']} | {e['version']} | "
                         f"{epss_s} | {kev_s} | {e['reason']} |")
        lines.append("")
    return "\n".join(lines)


def report_sarif(verdict: dict) -> str:
    """Minimal SARIF 2.1.0 so the report renders in GitHub code scanning."""
    results = []
    for tier, level in (("block", "error"), ("review", "warning")):
        for e in verdict[tier]:
            results.append({
                "ruleId": e["cve_id"],
                "level":  level,
                "message": {"text": f"{e['reason']} ({e['package']} {e['version']})"},
                "properties": {
                    "tier": tier,
                    "epss_score": e.get("epss_score"),
                    "in_kev": e.get("in_kev", False),
                },
            })
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "policy-gate", "rules": []}},
            "results": results,
        }],
    }, indent=2)


def report_junit(verdict: dict) -> str:
    """JUnit XML: one testcase per finding; block = failure, review = skipped."""
    from xml.sax.saxutils import escape
    cases = []
    for e in verdict["block"]:
        cases.append(
            f'  <testcase classname="{escape(verdict["image"])}" '
            f'name="{escape(e["cve_id"])} ({escape(e["package"])})">\n'
            f'    <failure message="{escape(e["reason"])}"/>\n'
            f'  </testcase>'
        )
    for e in verdict["review"]:
        cases.append(
            f'  <testcase classname="{escape(verdict["image"])}" '
            f'name="{escape(e["cve_id"])} ({escape(e["package"])})">\n'
            f'    <skipped message="{escape(e["reason"])}"/>\n'
            f'  </testcase>'
        )
    n = len(cases)
    failures = len(verdict["block"])
    skipped = len(verdict["review"])
    body = "\n".join(cases)
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="policy-gate" tests="{n}" '
        f'failures="{failures}" skipped="{skipped}">\n{body}\n</testsuite>'
    )


FORMATTERS = {
    "json": report_json,
    "markdown": report_markdown,
    "sarif": report_sarif,
    "junit": report_junit,
}


# --- Main ------------------------------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    p.add_argument("--image", required=True, help="container image reference")
    p.add_argument("--policy", type=Path, default=DEFAULT_CONFIG,
                   help="gate config JSON (default: configs/p_gate.json)")
    p.add_argument("--trivy", type=Path, default=None,
                   help="pre-computed Trivy JSON (skips scanner invocation)")
    p.add_argument("--grype", type=Path, default=None,
                   help="pre-computed Grype JSON (skips scanner invocation)")
    p.add_argument("--classifier", default="rule",
                   help="layer classifier: rule | agent (default: rule)")
    p.add_argument("--report", type=Path, default=None,
                   help="write report to this path (default: stdout)")
    p.add_argument("--report-format", choices=list(FORMATTERS), default="json")
    p.add_argument("--fail-on", choices=["block", "review", "none"], default="review",
                   help="which tiers fail the build (default: review = fail-closed)")
    p.add_argument("--cache", type=Path, default=CACHE_DIR)
    args = p.parse_args()

    configure_cache(args.cache)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        trivy_json = args.trivy or (tdp / "trivy.json")
        grype_json = args.grype or (tdp / "grype.json")
        if args.trivy is None:
            run_trivy(args.image, trivy_json)
        if args.grype is None:
            run_grype(args.image, grype_json)

        payload = normalise(trivy_json, grype_json, args.image, args.classifier)
        payload = asyncio.run(enrich_critical_and_high(payload))

        # Inject config and evaluate.
        cfg = json.loads(args.policy.read_text())
        cfg = {k: v for k, v in cfg.items() if not k.startswith("_")}
        payload["config"] = cfg
        eval_input = tdp / "gate_input.json"
        eval_input.write_text(json.dumps(payload))

        block  = opa_eval(eval_input, f"data.{GATE_PKG}.block")  or []
        review = opa_eval(eval_input, f"data.{GATE_PKG}.review") or []

    decision = "block" if block else ("review" if review else "pass")
    verdict = {
        "image":            args.image,
        "decision":         decision,
        "image_eol":        payload["image"]["eol"],
        "image_eol_source": payload["image"]["eol_source"],
        "block":            block,
        "review":           review,
    }

    rendered = FORMATTERS[args.report_format](verdict)
    if args.report:
        args.report.write_text(rendered)
    else:
        print(rendered)

    # Console summary to stderr so it does not pollute a stdout report.
    print(f"[policy-gate] {args.image}: {decision.upper()} "
          f"(block={len(block)}, review={len(review)}, "
          f"eol={payload['image']['eol']})", file=sys.stderr)

    # Exit-code mapping.
    if args.fail_on == "none":
        return 0
    if block:
        return 1
    if review and args.fail_on == "review":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
