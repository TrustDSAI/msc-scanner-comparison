"""End-of-life data source for container images.

Primary source: endoflife.date REST API. Free, no key, vendor-sourced,
deterministic JSON. The canonical structured source for product/version
lifecycle data.

Fallback source: LLM agent (uses the existing AgentClassifier prompt
shape). Invoked only when endoflife.date returns 404 or unsupported
schema; reaches for semantic judgment on custom or composed images
(e.g. application-vulnerable training images) where structured data
does not exist.

Result attached to the image payload:
    {
        "eol":          bool,
        "eol_date":     "YYYY-MM-DD" | null,
        "source":       "endoflife.date" | "agent:<model>" | "unknown",
        "reasoning":    "..."    (LLM only)
    }

Cache: keyed by image label so repeated runs are free.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from datetime import date
from typing import Any

from .cache import get_cache


_EOL_URL = "https://endoflife.date/api/{product}/{version}.json"
_TIMEOUT = 15

# Map common image names to endoflife.date product slugs.
# Where the image name matches the slug verbatim no entry is needed.
_PRODUCT_SLUG_OVERRIDE = {
    "node":   "nodejs",
    "node-pkg": "nodejs",
}


def _parse_image_label(label: str) -> tuple[str, str]:
    """Split `repo:tag` into a product slug and a version string.

    Drops any registry prefix and namespace; e.g.
        ghcr.io/library/python:3.8 -> ("python", "3.8")
        vulnerables/web-dvwa       -> ("", "")  (no version => unsupported)
    Returns ("", "") when the label cannot be split into (product, version).
    """
    if "/" in label:
        # Custom-namespaced image with no canonical product mapping.
        return ("", "")
    if ":" not in label:
        return ("", "")
    product, _, version = label.partition(":")
    product = _PRODUCT_SLUG_OVERRIDE.get(product.lower(), product.lower())
    return (product, version.strip())


def _date_in_past(value: Any) -> bool | None:
    """Interpret endoflife.date's `eol` field.

    The API returns one of:
        - a string "YYYY-MM-DD" date
        - the literal bool true / false (true=EOL forever, false=never)
        - null when unknown
    Returns True/False if interpretable, None if unknown.
    """
    if value is True:
        return True
    if value is False:
        return False
    if isinstance(value, str):
        try:
            return date.fromisoformat(value) <= date.today()
        except ValueError:
            return None
    return None


class EOLEnricher:
    """Image-level enricher. Run once per image, not once per finding."""

    field_name = "eol"
    name = "eol"

    def enrich_image(self, image: dict) -> dict:
        label = image.get("label", "")
        if not label:
            return _unknown("missing image label")

        cache = get_cache()
        cached = cache.get(self.field_name, label)
        if cached is not None:
            return cached

        result = self._lookup_endoflife(label)
        if result is None:
            result = self._lookup_trivy_os(image)
        if result is None:
            result = self._lookup_agent(label)
        if result is None:
            result = _unknown("no source could resolve EOL")

        cache.put(self.field_name, label, result)
        return result

    # --- Secondary: Trivy OS layer ---------------------------------------

    def _lookup_trivy_os(self, image: dict) -> dict | None:
        """Use Trivy's reported OS-layer EOSL flag when the caller has it.

        Distinct from endoflife.date's image-label lookup because it
        catches custom or composed images (e.g. application-vulnerable
        training images) whose label is not registered with
        endoflife.date but whose OS base IS tracked by Trivy.
        """
        os_md = image.get("trivy_os") or {}
        eosl = os_md.get("eosl")
        if eosl is None:
            return None
        return {
            "eol":      bool(eosl),
            "eol_date": None,
            "source":   "trivy:os-eosl",
            "os_family": os_md.get("family", ""),
            "os_name":   os_md.get("name", ""),
        }

    # --- Primary: endoflife.date -----------------------------------------

    def _lookup_endoflife(self, label: str) -> dict | None:
        product, version = _parse_image_label(label)
        if not (product and version):
            return None

        url = _EOL_URL.format(product=product, version=version)
        try:
            with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            return None
        except Exception:  # noqa: BLE001
            return None

        eol_value = payload.get("eol")
        eol = _date_in_past(eol_value)
        if eol is None:
            return None

        return {
            "eol":      eol,
            "eol_date": eol_value if isinstance(eol_value, str) else None,
            "source":   "endoflife.date",
            "product":  product,
            "version":  version,
        }

    # --- Fallback: LLM agent ---------------------------------------------

    def _lookup_agent(self, label: str) -> dict | None:
        # Use whichever LLM provider is configured for the classifier; we
        # don't require an agent classifier to be available, only its
        # provider config.
        try:
            from classifiers.agent import _provider  # type: ignore
        except Exception:
            return None

        provider, model = _provider()
        if not provider:
            return None

        prompt = (
            "Is the container image '" + label + "' end-of-life upstream "
            "(no longer receiving security patches from its maintainers) "
            "as of today? Respond with strict JSON: "
            '{"eol": true|false|null, "eol_date": "YYYY-MM-DD"|null, '
            '"reasoning": "one short sentence"}. '
            "Use null when uncertain; do not fabricate dates."
        )

        try:
            data = _call_provider(provider, model, prompt)
        except Exception as exc:  # noqa: BLE001
            return {"eol": False, "eol_date": None,
                    "source": f"agent:{model}", "reasoning": f"agent failed: {exc}"}

        return {
            "eol":       bool(data.get("eol")) if data.get("eol") is not None else False,
            "eol_date":  data.get("eol_date"),
            "source":    f"agent:{model}",
            "reasoning": data.get("reasoning", ""),
        }


def _unknown(reason: str) -> dict:
    return {"eol": False, "eol_date": None, "source": "unknown",
            "reasoning": reason}


def _call_provider(provider: str, model: str, prompt: str) -> dict:
    """Minimal duplicate of the agent classifier's HTTP path, kept here
    to keep EOL self-contained without circular import."""
    if provider == "anthropic":
        from anthropic import Anthropic
        client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        resp = client.messages.create(
            model=model, max_tokens=200, temperature=0,
            system="Output strict JSON only.",
            messages=[{"role": "user", "content": prompt}],
        )
        text = next((b.text for b in resp.content if b.type == "text"), "")
        return _extract_json(text)
    if provider == "openai":
        body = json.dumps({
            "model": model, "temperature": 0,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": "Output strict JSON only."},
                {"role": "user", "content": prompt},
            ],
        }).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=body,
            headers={"authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
                     "content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        return _extract_json(payload["choices"][0]["message"]["content"])
    if provider == "ollama":
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        body = json.dumps({
            "model": model, "stream": False,
            "options": {"temperature": 0},
            "format": "json",
            "messages": [
                {"role": "system", "content": "Output strict JSON only."},
                {"role": "user", "content": prompt},
            ],
        }).encode()
        req = urllib.request.Request(
            f"{host.rstrip('/')}/api/chat",
            data=body,
            headers={"content-type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        return _extract_json(payload["message"]["content"])
    raise ValueError(f"unknown provider {provider}")


def _extract_json(text: str) -> dict:
    """Return the first {...} block in the text parsed as JSON."""
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            return {}
    return {}
