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
from enrichers import ENRICHERS, empty_payload
from enrichers.cache import configure as configure_cache
from enrichers.eol import EOLEnricher
from classifiers import get as get_classifier
from classifiers.advisor import ReviewAdvisor, is_available as advisor_available
import provenance as provenance_mod
from exceptions_loader import load_exceptions

REGO_DIR = HERE / "rego"
DEFAULT_CONFIG = HERE / "configs" / "p_gate.json"
CACHE_DIR = HERE / ".cache" / "enrich"
DEFAULT_GATE_PKG = "vuln.gate"


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
                f.setdefault(er.field_name, empty_payload(er.field_name))
    return payload


def opa_eval(input_path: Path, query: str, rego_dir: Path) -> object:
    proc = subprocess.run(
        ["opa", "eval", "--input", str(input_path),
         "--data", str(rego_dir), "--format", "json", query],
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
                 f"(block: {len(verdict['block'])}, review: {len(verdict['review'])}, "
                 f"suppressed: {len(verdict.get('suppressed', []))})")
    if verdict["image_eol"]:
        lines.append(f"**Image is end-of-life** (source: {verdict['image_eol_source']})")

    prov = verdict.get("provenance") or {}
    if prov and "error" not in prov:
        tv = prov.get("tool_versions", {})
        lines.append(
            f"**Provenance:** trivy {tv.get('trivy')}, grype {tv.get('grype')}, "
            f"opa {tv.get('opa')}, bundle {prov.get('policy_bundle_fingerprint')}, "
            f"classifier={prov.get('classifier')}, scanned {prov.get('scan_timestamp')}"
        )
    lines.append("")

    for tier in ("block", "review", "suppressed"):
        entries = verdict.get(tier, [])
        if not entries:
            continue
        lines.append(f"## {tier.title()} ({len(entries)})")
        lines.append("")
        if tier == "suppressed":
            lines.append("| CVE | Package | Version | Would have been | Reason |")
            lines.append("|-----|---------|---------|------------------|--------|")
            for e in entries:
                lines.append(f"| {e['cve_id']} | {e['package']} | {e['version']} | "
                             f"{e.get('would_have_been', '-')} | {e['reason']} |")
        else:
            lines.append("| CVE | Package | Version | EPSS | KEV | Reason |")
            lines.append("|-----|---------|---------|------|-----|--------|")
            for e in entries:
                epss = e.get("epss_score")
                epss_s = f"{epss:.3f}" if isinstance(epss, (int, float)) else "-"
                kev_s = "yes" if e.get("in_kev") else "-"
                lines.append(f"| {e['cve_id']} | {e['package']} | {e['version']} | "
                             f"{epss_s} | {kev_s} | {e['reason']} |")
        lines.append("")

        # Reviewer advice section: only for review tier, only when advice exists.
        if tier == "review":
            advised = [(e, e.get("advice")) for e in entries if e.get("advice")]
            if advised:
                lines.append("### Reviewer guidance")
                lines.append("")
                for e, advice in advised:
                    lines.append(f"**{e['cve_id']} ({e['package']}):** {advice}")
                    lines.append("")

    return "\n".join(lines)


def report_pr_comment(
    verdict: dict,
    max_findings: int = 20,
    *,
    override_active: bool = False,
    log_url: str | None = None,
) -> str:
    """GitHub PR comment body, fully rendered here so the calling workflow
    never reimplements formatting in inline JS. override_active and log_url
    are the only two facts the tool cannot know on its own (PR labels, run
    URL live in the GitHub Actions context) -- the caller passes them in
    as plain values, and the workflow's job shrinks to "read this file and
    call createComment", nothing else.
    """
    decision = verdict["decision"]
    emoji = {"block": "🔴", "review": "🟡", "pass": "🟢"}.get(decision, "⚪")

    def by_epss_desc(entries):
        return sorted(entries, key=lambda f: f.get("epss_score") or 0, reverse=True)

    def epss_str(f):
        return f"{(f.get('epss_score') or 0):.3f}"

    block      = by_epss_desc(verdict.get("block", []))
    review     = by_epss_desc(verdict.get("review", []))
    suppressed = by_epss_desc(verdict.get("suppressed", []))

    def table(entries, header, row_fn):
        shown = entries[:max_findings]
        rows = "\n".join(row_fn(e) for e in shown)
        out = f"{header}\n{rows}"
        hidden = len(entries) - len(shown)
        if hidden > 0:
            out += f"\n\n_+{hidden} more not shown (capped at {max_findings})_"
        return out

    sections = [
        f"## {emoji} Policy Gate: **{decision.upper()}**",
        f"**{len(block)}** blocked · **{len(review)}** review · **{len(suppressed)}** suppressed",
    ]

    if block:
        body = table(
            block,
            "| CVE | Package | Severity | EPSS | |\n|---|---|---|---|---|",
            lambda f: f"| `{f['cve_id']}` | {f['package']} {f['version']} | "
                      f"{f.get('severity', '-')} | {epss_str(f)} | "
                      f"{'✅ KEV' if f.get('in_kev') else '—'} |",
        )
        if verdict.get("block_summary"):
            body += f"\n\n> 🤖 **Triage advice:** {verdict['block_summary']}"
        sections.append(f"### Blocked findings\n{body}")

    if review:
        body = table(
            review,
            "| CVE | Package | Severity | EPSS |\n|---|---|---|---|",
            lambda f: f"| `{f['cve_id']}` | {f['package']} {f['version']} | "
                      f"{f.get('severity', '-')} | {epss_str(f)} |",
        )
        if verdict.get("review_summary"):
            body += f"\n\n> 🤖 **Triage advice:** {verdict['review_summary']}"
        sections.append(f"### Review findings\n{body}")

    if suppressed:
        body = table(
            suppressed,
            "| CVE | Package | Severity | Would have been |\n|---|---|---|---|",
            lambda f: f"| `{f['cve_id']}` | {f['package']} {f['version']} | "
                      f"{f.get('severity', '-')} | {f.get('would_have_been', '—')} |",
        )
        sections.append(f"### Suppressed findings\n{body}")

    if override_active:
        sections.append(
            "> ⚠️ **Override active** (`gate-override` label) — build will not be blocked."
        )

    prov = verdict.get("provenance") or {}
    if prov and "error" not in prov:
        tv = prov.get("tool_versions", {})
        fp = (prov.get("policy_bundle_fingerprint") or "")[:19]
        sections.append(
            f"<sub>trivy `{tv.get('trivy', '?')}` · grype `{tv.get('grype', '?')}` · "
            f"opa `{tv.get('opa', '?')}` · bundle `{fp}`</sub>"
        )

    if log_url:
        sections.append(f"<sub>[full log]({log_url})</sub>")

    return "\n\n".join(sections)


def report_sarif(verdict: dict) -> str:
    """Minimal SARIF 2.1.0 so the report renders in GitHub code scanning."""
    results = []
    for tier, level in (("block", "error"), ("review", "warning")):
        for e in verdict.get(tier, []):
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

    prov = verdict.get("provenance") or {}
    tv = prov.get("tool_versions", {})
    driver = {
        "name": "policy-gate",
        "version": prov.get("build_sha") or prov.get("policy_bundle_fingerprint", ""),
        "rules": [],
        "properties": {
            "provenance": prov,
            "trivy_version": tv.get("trivy"),
            "grype_version": tv.get("grype"),
            "opa_version": tv.get("opa"),
        },
    }
    return json.dumps({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": driver},
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

    prov = verdict.get("provenance") or {}
    tv = prov.get("tool_versions", {})
    props = {
        "trivy_version": tv.get("trivy"),
        "grype_version": tv.get("grype"),
        "opa_version": tv.get("opa"),
        "policy_bundle_fingerprint": prov.get("policy_bundle_fingerprint"),
        "policy_package": prov.get("policy_package"),
        "classifier": prov.get("classifier"),
        "build_sha": prov.get("build_sha"),
        "scan_timestamp": prov.get("scan_timestamp"),
        "suppressed_count": len(verdict.get("suppressed", [])),
    }
    props_xml = "\n".join(
        f'    <property name="{escape(k)}" value="{escape(str(v))}"/>'
        for k, v in props.items() if v is not None
    )
    properties_block = f"  <properties>\n{props_xml}\n  </properties>\n" if props_xml else ""

    return (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="policy-gate" tests="{n}" '
        f'failures="{failures}" skipped="{skipped}">\n{properties_block}{body}\n</testsuite>'
    )


FORMATTERS = {
    "json": report_json,
    "markdown": report_markdown,
    "pr-comment": report_pr_comment,
    "sarif": report_sarif,
    "junit": report_junit,
}


# --- Core pipeline (used by both CLI and API) -------------------------

def run_gate(
    image: str,
    *,
    policy_path: Path = DEFAULT_CONFIG,
    trivy_json: Path | None = None,
    grype_json: Path | None = None,
    classifier: str = "rule",
    rego_dir: Path = REGO_DIR,
    policy_package: str = DEFAULT_GATE_PKG,
    config_override: dict | None = None,
    exceptions_dir: Path | None = None,
) -> dict:
    """Run the full enrichment + OPA pipeline for one image.

    Returns the verdict dict:
        {image, decision, image_eol, image_eol_source,
         block: [...], review: [...], suppressed: [...],
         summary: {...}, provenance: {...}}

    Caller is responsible for calling configure_cache() before invoking this.
    exceptions_dir=None (default) means no suppression is applied.
    """
    scan_timestamp = provenance_mod.now_iso()

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        t_json = trivy_json or (tdp / "trivy.json")
        g_json = grype_json or (tdp / "grype.json")
        if trivy_json is None:
            run_trivy(image, t_json)
        if grype_json is None:
            run_grype(image, g_json)

        payload = normalise(t_json, g_json, image, classifier)
        payload = asyncio.run(enrich_critical_and_high(payload))

        cfg = config_override if config_override is not None else (
            {k: v for k, v in json.loads(policy_path.read_text()).items()
             if not k.startswith("_")}
        )
        payload["config"] = cfg
        if exceptions_dir is not None:
            payload["exceptions"] = load_exceptions(exceptions_dir)
        eval_input = tdp / "gate_input.json"
        eval_input.write_text(json.dumps(payload))

        block      = opa_eval(eval_input, f"data.{policy_package}.block",      rego_dir) or []
        review     = opa_eval(eval_input, f"data.{policy_package}.review",     rego_dir) or []
        suppressed = opa_eval(eval_input, f"data.{policy_package}.suppressed", rego_dir) or []

    block_summary = None
    review_summary = None
    if advisor_available() and (block or review):
        try:
            advisor = ReviewAdvisor()
            if block:
                block_summary = advisor.advise_batch(block)
            if review:
                review_summary = advisor.advise_batch(review)
        except Exception as exc:  # noqa: BLE001
            print(f"[policy-gate] advisor unavailable: {exc}", file=sys.stderr)

    decision = "block" if block else ("review" if review else "pass")
    findings = payload["findings"]
    severity_counts: dict = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    try:
        prov = provenance_mod.build_provenance(
            rego_dir=rego_dir, policy_package=policy_package,
            config=cfg, classifier=classifier, scan_timestamp=scan_timestamp,
        )
    except Exception as exc:  # noqa: BLE001
        prov = {"error": f"provenance unavailable: {exc}"}

    return {
        "image":            image,
        "decision":         decision,
        "image_eol":        payload["image"]["eol"],
        "image_eol_source": payload["image"]["eol_source"],
        "block":            block,
        "block_summary":    block_summary,
        "review":           review,
        "review_summary":   review_summary,
        "suppressed":       suppressed,
        "summary": {
            "total_findings":    len(findings),
            "severity_counts":   severity_counts,
            "evaluated_findings": sum(
                1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH")
            ),
            "suppressed_count": len(suppressed),
            "reason": _summary_reason(decision, findings),
        },
        "provenance": prov,
    }


def _summary_reason(decision: str, findings: list) -> str:
    total = len(findings)
    if decision != "pass":
        return f"{decision} tier reached; see block/review for details"
    if total == 0:
        return "no findings reported by either scanner"
    evaluated = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    if evaluated == 0:
        return (f"{total} findings reported, none CRITICAL or HIGH "
                f"(only CRITICAL/HIGH are evaluated against the gate)")
    return (f"{evaluated} CRITICAL/HIGH findings evaluated, none met "
            f"block or review conditions")


# --- Main (CLI) -------------------------------------------------------

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
    p.add_argument("--comment-max-findings", type=int, default=20,
                   help="max rows per table in pr-comment format (default: 20)")
    p.add_argument("--pr-comment-path", type=Path, default=None,
                   help="also render the pr-comment markdown to this path, "
                        "regardless of --report-format")
    p.add_argument("--override-active", action="store_true",
                   help="render the gate-override banner in the pr-comment (caller "
                        "checks the PR label, e.g. gate-override, and passes this)")
    p.add_argument("--log-url", default=None,
                   help="CI run URL to append as a 'full log' link in the pr-comment")
    p.add_argument("--fail-on", choices=["block", "review", "none"], default="review",
                   help="which tiers fail the build (default: review = fail-closed)")
    p.add_argument("--rego-dir", type=Path, default=REGO_DIR,
                   help="directory of .rego files to load (default: built-in rego/)")
    p.add_argument("--policy-package", default=DEFAULT_GATE_PKG,
                   help="OPA package to evaluate (default: vuln.gate)")
    p.add_argument("--exceptions-dir", type=Path, default=None,
                   help="directory of exception YAML files (default: none, no suppression)")
    p.add_argument("--cache", type=Path, default=CACHE_DIR)
    args = p.parse_args()

    configure_cache(args.cache)

    verdict = run_gate(
        args.image,
        policy_path=args.policy,
        trivy_json=args.trivy,
        grype_json=args.grype,
        classifier=args.classifier,
        rego_dir=args.rego_dir,
        policy_package=args.policy_package,
        exceptions_dir=args.exceptions_dir,
    )

    pr_comment = None
    if args.report_format == "pr-comment" or args.pr_comment_path is not None:
        pr_comment = report_pr_comment(
            verdict, max_findings=args.comment_max_findings,
            override_active=args.override_active, log_url=args.log_url,
        )

    rendered = pr_comment if args.report_format == "pr-comment" else FORMATTERS[args.report_format](verdict)
    if args.report:
        args.report.write_text(rendered)
    else:
        print(rendered)

    if args.pr_comment_path is not None:
        args.pr_comment_path.write_text(pr_comment)

    print(f"[policy-gate] {args.image}: {verdict['decision'].upper()} "
          f"(block={len(verdict['block'])}, review={len(verdict['review'])}, "
          f"eol={verdict['image_eol']})", file=sys.stderr)

    if args.fail_on == "none":
        return 0
    if verdict["decision"] == "block":
        return 1
    if verdict["decision"] == "review" and args.fail_on == "review":
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
