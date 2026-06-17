"""LLM-based reviewer advisor.

For each finding that reaches the REVIEW tier, generates 1-2 sentences of
actionable guidance for the human reviewer: what the evidence says, what
action is most appropriate, and any notable context (EOL image, missing fix,
low EPSS despite CRITICAL label, etc.).

Same provider detection and HTTP call pattern as agent.py. Results are
cached by a key derived from the CVE, enrichment snapshot, and model so
swapping models does not serve stale advice and re-running after EPSS
updates produces fresh advice.

If no LLM key is set, advise() returns None and the caller omits the
field from the report. The gate functions normally without it.
"""

from __future__ import annotations

import json
import os
import urllib.request

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_URL    = "https://api.openai.com/v1/chat/completions"
_DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5"
_DEFAULT_OPENAI_MODEL    = "gpt-4o-mini"
_TIMEOUT = 30

_SYSTEM = (
    "You are a security triage assistant embedded in a CI/CD vulnerability gate. "
    "A finding has been routed to human review because the automated evidence is "
    "insufficient to auto-block or auto-pass. Your job is to help the reviewer "
    "make a fast, informed decision. "
    "Write exactly 1-2 concise sentences. Be direct and specific. "
    "Do not repeat facts the reviewer can already see in the table. "
    "Focus on what action to take and why, not on describing the vulnerability. "
    "Do not hedge or qualify everything — give a recommendation."
)

_BATCH_SYSTEM = (
    "You are a security triage assistant embedded in a CI/CD vulnerability gate. "
    "Multiple findings have been routed to human review. "
    "Write a concise consolidated triage summary (3-5 sentences). "
    "Group findings by theme or package where it helps. "
    "End with a clear recommended action for the reviewer. "
    "Be direct — do not hedge or repeat the raw data back."
)

_BATCH_TEMPLATE = """\
The following {n} findings were routed to the REVIEW tier (not severe enough to auto-block, \
not clean enough to auto-pass). Provide a consolidated triage summary.

{rows}

Summarise in 3-5 sentences what the reviewer should focus on and what action to take."""

_USER_TEMPLATE = """\
Finding routed to REVIEW tier. Provide triage advice.

CVE: {cve_id}
Package: {package} {version} (ecosystem: {ecosystem}, layer: {layer})
Severity: {severity}
Fix available: {fix_available} ({fix_version})
EPSS score: {epss} (probability of exploitation in next 30 days)
In CISA KEV (confirmed exploited in wild): {in_kev}
NVD status: {nvd_status} | rejected: {nvd_rejected} | disputed: {nvd_disputed}
OSV advisory found: {osv_advisory} | OSV fix recorded: {osv_fix}
Image EOL: {eol} (source: {eol_source})
Gate reason: {reason}

Respond in 1-2 sentences with a specific recommendation for the reviewer."""


def _provider() -> tuple[str, str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ("anthropic",
                os.environ.get("ADVISOR_MODEL")
                or os.environ.get("CLASSIFIER_MODEL")
                or _DEFAULT_ANTHROPIC_MODEL)
    if os.environ.get("OPENAI_API_KEY"):
        return ("openai",
                os.environ.get("ADVISOR_MODEL")
                or os.environ.get("CLASSIFIER_MODEL")
                or _DEFAULT_OPENAI_MODEL)
    return ("", "")


def is_available() -> bool:
    return bool(_provider()[0])


def _cache_key(provider: str, model: str, finding: dict) -> str:
    epss = (finding.get("epss") or {}).get("score", "")
    kev  = (finding.get("kev")  or {}).get("in_kev", "")
    return (f"{provider}::{model}::{finding.get('cve_id','')}"
            f"::{finding.get('package','')}"
            f"::{epss}::{kev}")


def _build_prompt(finding: dict) -> str:
    epss_data = finding.get("epss") or {}
    nvd_data  = finding.get("nvd")  or {}
    osv_data  = finding.get("osv")  or {}
    kev_data  = finding.get("kev")  or {}

    epss_score = epss_data.get("score")
    epss_str   = f"{epss_score:.4f}" if isinstance(epss_score, float) else "not available"

    return _USER_TEMPLATE.format(
        cve_id      = finding.get("cve_id", "unknown"),
        package     = finding.get("package", "unknown"),
        version     = finding.get("version", "unknown"),
        ecosystem   = finding.get("ecosystem", "unknown"),
        layer       = finding.get("layer", "unknown"),
        severity    = finding.get("severity", "unknown"),
        fix_available = "yes" if finding.get("fix_version") else "no",
        fix_version = finding.get("fix_version") or "none recorded",
        epss        = epss_str,
        in_kev      = "yes" if kev_data.get("in_kev") else "no",
        nvd_status  = nvd_data.get("status", "not available"),
        nvd_rejected  = nvd_data.get("rejected", "unknown"),
        nvd_disputed  = nvd_data.get("disputed", "unknown"),
        osv_advisory  = "yes" if osv_data.get("advisory_found") else "no",
        osv_fix       = osv_data.get("fix_version") or "none recorded",
        eol           = finding.get("image_eol", False),
        eol_source    = finding.get("image_eol_source", ""),
        reason        = finding.get("reason", ""),
    )


class ReviewAdvisor:
    """Generate actionable reviewer guidance for REVIEW-tier findings."""

    def __init__(self) -> None:
        self.provider, self.model = _provider()
        if not self.provider:
            raise RuntimeError(
                "no LLM API key set (ANTHROPIC_API_KEY or OPENAI_API_KEY)"
            )

    _BATCH_CAP = 20  # max findings sent to LLM; keeps prompt within context limits

    def advise_batch(self, findings: list) -> str | None:
        """Return a single consolidated triage summary for all review findings."""
        if not findings:
            return None
        findings = sorted(
            findings,
            key=lambda f: (f.get("epss") or {}).get("score", 0),
            reverse=True,
        )[:self._BATCH_CAP]
        from enrichers.cache import get_cache
        cache = get_cache()
        import hashlib, json as _json
        key_src = self.provider + self.model + _json.dumps(
            [_cache_key(self.provider, self.model, f) for f in findings], sort_keys=True
        )
        key = hashlib.sha256(key_src.encode()).hexdigest()
        cached = cache.get("advice_batch", key)
        if cached is not None:
            return cached.get("summary")

        rows = "\n".join(
            f"- {f.get('cve_id','?')} | {f.get('package','?')} {f.get('version','?')} "
            f"| {f.get('severity','?')} | EPSS {(f.get('epss') or {}).get('score', 0):.3f} "
            f"| fix={'yes' if f.get('fix_version') else 'no'} "
            f"| kev={'yes' if (f.get('kev') or {}).get('in_kev') else 'no'}"
            for f in findings
        )
        prompt = _BATCH_TEMPLATE.format(n=len(findings), rows=rows)
        try:
            if self.provider == "anthropic":
                text = self._call_anthropic(prompt, system=_BATCH_SYSTEM, max_tokens=600)
            else:
                text = self._call_openai(prompt, system=_BATCH_SYSTEM, max_tokens=600)
            text = text.strip()
        except Exception as exc:  # noqa: BLE001
            text = f"[advisor unavailable: {exc}]"

        cache.put("advice_batch", key, {"summary": text})
        return text

    def advise(self, finding: dict) -> str | None:
        """Return a 1-2 sentence advice string, or None on failure."""
        from enrichers.cache import get_cache
        cache = get_cache()
        key = _cache_key(self.provider, self.model, finding)
        cached = cache.get("advice", key)
        if cached is not None:
            return cached.get("advice")

        prompt = _build_prompt(finding)
        try:
            if self.provider == "anthropic":
                text = self._call_anthropic(prompt)
            else:
                text = self._call_openai(prompt)
            text = text.strip()
        except Exception as exc:  # noqa: BLE001
            text = f"[advisor unavailable: {exc}]"

        cache.put("advice", key, {"advice": text})
        return text

    def _call_anthropic(self, user_prompt: str, system: str = _SYSTEM, max_tokens: int = 150) -> str:
        from anthropic import Anthropic
        client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        resp = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=0,
            system=system,
            messages=[{"role": "user", "content": user_prompt}],
        )
        for block in resp.content:
            if block.type == "text":
                return block.text
        return ""

    def _call_openai(self, user_prompt: str, system: str = _SYSTEM, max_tokens: int = 150) -> str:
        body = json.dumps({
            "model":       self.model,
            "temperature": 0,
            "max_tokens":  max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user_prompt},
            ],
        }).encode()
        req = urllib.request.Request(_OPENAI_URL, data=body, headers={
            "authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "content-type":  "application/json",
        })
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        return payload["choices"][0]["message"]["content"]
