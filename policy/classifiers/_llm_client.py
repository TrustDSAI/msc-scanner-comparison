"""Shared Anthropic/OpenAI HTTP call helpers for LLM-based classifiers.

No SDK dependency for OpenAI; the Anthropic SDK is imported lazily so this
module loads even when it isn't installed.
"""

from __future__ import annotations

import json
import os
import urllib.request

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_OPENAI_URL = "https://api.openai.com/v1/chat/completions"
_TIMEOUT = 30


def call_anthropic(model: str, system: str, user_prompt: str, max_tokens: int = 300) -> str:
    from anthropic import Anthropic

    client = Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    resp = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        temperature=0,
        system=system,
        messages=[{"role": "user", "content": user_prompt}],
    )
    for block in resp.content:
        if block.type == "text":
            return block.text
    return ""


def call_openai(model: str, system: str, user_prompt: str, max_tokens: int = 300,
                 *, json_mode: bool = False) -> str:
    body = {
        "model":       model,
        "temperature": 0,
        "max_tokens":  max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_prompt},
        ],
    }
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    req = urllib.request.Request(_OPENAI_URL, data=json.dumps(body).encode(), headers={
        "authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
        "content-type":  "application/json",
    })
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        payload = json.loads(resp.read().decode())
    return payload["choices"][0]["message"]["content"]
