"""LLM-based layer classifier.

Asks an LLM whether a CVE finding is operating-system layer or
application layer, returning a structured Label. Supports Anthropic and
OpenAI APIs via direct HTTPS calls (no SDK dependencies).

Configuration via environment variables:

    Provider                                Model env / default
    ----------------------------------------------------------------
    ANTHROPIC_API_KEY  Anthropic            CLASSIFIER_MODEL or "claude-sonnet-4-5"
    OPENAI_API_KEY     OpenAI               CLASSIFIER_MODEL or "gpt-4o-mini"

If neither key is set, calling .classify() raises RuntimeError with a clear
message. The CLI / orchestrator must check `is_available()` first.

Determinism:
    temperature=0 is used for both providers. We additionally request
    JSON-structured output for parseability. Even at temperature 0 outputs
    can vary slightly; the orchestrator may run N=3 and majority-vote.

Caching:
    Results are cached by (provider, model, cve_id) so repeated runs are free.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from .base import Classifier, Label

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_URL    = "https://api.openai.com/v1/chat/completions"
# Local Ollama instance (for testing / development without hitting external APIs)
_OLLAMA_URL    = "http://192.168.2.61:11434/api/chat"
_DEFAULT_OLLAMA_MODEL    = "qwen2.5:3b"
_DEFAULT_ANTHROPIC_MODEL = "claude-haiku-4-5"
_DEFAULT_OPENAI_MODEL    = "gpt-4o-mini"
_TIMEOUT = 30


_PROMPT_SYSTEM = (
    "You are a security engineering classifier. Given a CVE finding from a "
    "container scanner, decide whether the vulnerability is at the "
    "operating-system layer or the application layer. "
    "OS layer = OS distribution packages (libc, openssl, kernel, "
    "system libraries) installed by apt/apk/yum. "
    "Application layer = code or libraries the application directly "
    "depends on or executes (PHP modules, npm/PyPI packages, language "
    "runtimes used by the app, application frameworks). "
    "An OS-packaged module that runs application code (e.g., libapache2-mod-php) "
    "is application layer. Output strict JSON only."
)

_PROMPT_USER_TEMPLATE = """Classify this finding:

CVE: {cve_id}
Package: {package} (version {version})
Ecosystem reported by scanner: {ecosystem}
Severity: {severity}
Container image: {image}

Respond with JSON: {{"layer": "app" | "os" | "unknown", "confidence": 0.0-1.0, "reasoning": "one short sentence"}}"""


def _provider() -> tuple[str, str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ("anthropic",
                os.environ.get("CLASSIFIER_MODEL") or _DEFAULT_ANTHROPIC_MODEL)
    if os.environ.get("OPENAI_API_KEY"):
        return ("openai",
                os.environ.get("CLASSIFIER_MODEL") or _DEFAULT_OPENAI_MODEL)
    if os.environ.get("OLLAMA_HOST"):
        return ("ollama",
                os.environ.get("CLASSIFIER_MODEL") or _DEFAULT_OLLAMA_MODEL)
    return ("", "")


def is_available() -> bool:
    return bool(_provider()[0])

def is_available() -> bool:
    return bool(_provider()[0])


class AgentClassifier(Classifier):
    name = "agent"

    def __init__(self) -> None:
        self.provider, self.model = _provider()
        if not self.provider:
            raise RuntimeError(
                "no LLM API key set (ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST)"
            )
        self.name = f"agent:{self.model}"

    def classify(self, finding: dict) -> Label:
        # Cache via the shared enrichment cache for free; classifier source
        # is part of the key so swapping models doesn't collide.
        from enrichers.cache import get_cache
        cache_key = f"{self.provider}::{self.model}::{finding.get('cve_id','')}::{finding.get('package','')}::{finding.get('ecosystem','')}"
        cache = get_cache()
        cached = cache.get("layer", cache_key)
        if cached is not None:
            d = cached
            return Label(layer=d["layer"], source=self.name,
                         confidence=d.get("confidence", 0.0),
                         reasoning=d.get("reasoning", ""))

        user_prompt = _PROMPT_USER_TEMPLATE.format(
            cve_id=finding.get("cve_id", ""),
            package=finding.get("package", ""),
            version=finding.get("version", ""),
            ecosystem=finding.get("ecosystem", ""),
            severity=finding.get("severity", ""),
            image=finding.get("_image", ""),
        )

        try:
            content = (self._call_anthropic(user_prompt)
                if self.provider == "anthropic"
                else self._call_ollama(user_prompt)
                if self.provider == "ollama"
                else self._call_openai(user_prompt))
            parsed = json.loads(_extract_json(content))
            label = Label(
                layer=parsed.get("layer", "unknown"),
                source=self.name,
                confidence=float(parsed.get("confidence", 0.0)),
                reasoning=parsed.get("reasoning", ""),
            )
        except Exception as exc:  # noqa: BLE001
            label = Label(layer="unknown", source=self.name,
                          confidence=0.0,
                          reasoning=f"agent call failed: {exc}")

        cache.put("layer", cache_key, {
            "layer":      label.layer,
            "confidence": label.confidence,
            "reasoning":  label.reasoning,
        })
        return label

    # --- HTTP calls -----------------------------------------------------

    def _call_anthropic(self, user_prompt: str) -> str:
        # Lazy import so the module loads when the SDK is missing and
        # only the anthropic-using path requires it.
        from anthropic import Anthropic

        client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        resp = client.messages.create(
            model=self.model,
            max_tokens=300,
            temperature=0,
            system=_PROMPT_SYSTEM,
            messages=[{"role": "user", "content": user_prompt}],
        )
        for block in resp.content:
            if block.type == "text":
                return block.text
        return ""

    def _call_openai(self, user_prompt: str) -> str:
        body = json.dumps({
            "model":       self.model,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": _PROMPT_SYSTEM},
                {"role": "user",   "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
        }).encode()
        req = urllib.request.Request(_OPENAI_URL, data=body, headers={
            "authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
            "content-type":  "application/json",
        })
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        return payload["choices"][0]["message"]["content"]

    def _call_ollama(self, user_prompt: str) -> str:
        ollama_url = os.environ.get("OLLAMA_HOST", "http://192.168.2.61:11434")
        url = f"{ollama_url.rstrip('/')}/api/chat"
        body = json.dumps({
            "model":  self.model,
            "stream": False,
            "options": {"temperature": 0},
            "messages": [
                {"role": "system", "content": _PROMPT_SYSTEM},
                {"role": "user",   "content": user_prompt},
            ],
        }).encode()
        req = urllib.request.Request(url, data=body, headers={
            "content-type": "application/json",
        })
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        return payload["message"]["content"]

def _extract_json(text: str) -> str:
    """Return the first {...} block in the text, or the text as-is."""
    start = text.find("{")
    end   = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        return text[start:end + 1]
    return text
