"""LLM-based reviewer advisor.

Generates a consolidated triage summary for all findings routed to the
REVIEW tier in one call (capped at the top 20 by EPSS) -- not one call
per finding, which doesn't scale past a handful of findings.

Same provider detection and HTTP call pattern as agent.py. Results are
cached by a key derived from the CVE, enrichment snapshot, and model so
swapping models does not serve stale advice and re-running after EPSS
updates produces fresh advice.

If no LLM key is set, advise_batch() returns None and the caller omits
the field from the report. The gate functions normally without it.
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
    # block/review entries are lib.make_msg's flat shape (epss_score,
    # in_kev), not the nested enrichment shape (epss.score, kev.in_kev)
    # findings carry before reaching the gate -- these are gate output,
    # not raw enriched findings.
    epss = finding.get("epss_score", "")
    kev  = finding.get("in_kev", "")
    return (f"{provider}::{model}::{finding.get('cve_id','')}"
            f"::{finding.get('package','')}"
            f"::{epss}::{kev}")


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
            key=lambda f: f.get("epss_score") or 0,
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
            f"| {f.get('severity','?')} | EPSS {(f.get('epss_score') or 0):.3f} "
            f"| fix={'yes' if f.get('fix_version') else 'no'} "
            f"| kev={'yes' if f.get('in_kev') else 'no'}"
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

    def _call_anthropic(self, user_prompt: str, system: str, max_tokens: int = 150) -> str:
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

    def _call_openai(self, user_prompt: str, system: str, max_tokens: int = 150) -> str:
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
