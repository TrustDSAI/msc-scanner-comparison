"""LLM-based layer classifier.

Asks an LLM whether a CVE finding is operating-system layer or
application layer, returning a structured Label. Anthropic calls go
through the official `anthropic` SDK; OpenAI and Ollama are called over
direct HTTPS with no SDK dependency.

Configuration via environment variables:

    Provider                                Model env / default
    ----------------------------------------------------------------
    ANTHROPIC_API_KEY  Anthropic            CLASSIFIER_MODEL or "claude-haiku-4-5"
    OPENAI_API_KEY     OpenAI               CLASSIFIER_MODEL or "gpt-4o-mini"
    OLLAMA_HOST        Ollama (local)       CLASSIFIER_MODEL or "qwen2.5:3b"

If none of these is set, calling .classify() raises RuntimeError with a
clear message. The CLI / orchestrator must check `is_available()` first.

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

from . import _llm_client
from .base import Classifier, Label

# Local Ollama instance (for testing / development without hitting external APIs).
# Point OLLAMA_HOST at your own instance; the default is Ollama's own.
_OLLAMA_URL    = "http://localhost:11434/api/chat"
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
        return _llm_client.call_anthropic(self.model, _PROMPT_SYSTEM, user_prompt, max_tokens=300)

    def _call_openai(self, user_prompt: str) -> str:
        return _llm_client.call_openai(self.model, _PROMPT_SYSTEM, user_prompt,
                                        max_tokens=300, json_mode=True)

    def _call_ollama(self, user_prompt: str) -> str:
        ollama_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
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
