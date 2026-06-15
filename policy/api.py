#!/usr/bin/env python3
"""policy-gate REST API.

Exposes the full scan + enrich + OPA pipeline over HTTP so CI runners and
dashboards can call it without a local Trivy/Grype/OPA installation.

Usage
-----
    uvicorn api:app --host 0.0.0.0 --port 8080

Docker
------
    docker run --rm -p 8080:8080 \\
        -e POLICY_GATE_API_KEY=changeme \\
        -e ANTHROPIC_API_KEY=... \\
        -v policy-gate-cache:/cache \\
        ghcr.io/<org>/policy-gate-api

Authentication
--------------
Set POLICY_GATE_API_KEY to enable authentication. Clients must send the key
in the X-API-Key request header. If the variable is unset, the server starts
unauthenticated (suitable for local/dev use only).

    curl -H "X-API-Key: changeme" -d '{"image":"alpine:3.21"}' \\
         -H "Content-Type: application/json" http://localhost:8080/gate

Endpoints
---------
    POST /gate          Scan an image and return a tri-state verdict.
    POST /gate/verdict  Same but accepts pre-computed Trivy + Grype JSON
                        (skips scanner invocation).
    GET  /health        Liveness probe.
    GET  /config        Active gate configuration.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Security, UploadFile, File, Form
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from policy_gate import (
    run_gate,
    DEFAULT_CONFIG,
    DEFAULT_GATE_PKG,
    REGO_DIR,
    CACHE_DIR,
)
from enrichers.cache import configure as configure_cache

# Initialise the enrichment cache once at startup.
_cache_dir = Path(os.environ.get("POLICY_GATE_CACHE", str(CACHE_DIR)))
configure_cache(_cache_dir)

# ── Authentication ────────────────────────────────────────────────────────────
# Set POLICY_GATE_API_KEY in the environment to enable API key auth.
# When the variable is unset the server starts unauthenticated (dev/local use).
_API_KEY = os.environ.get("POLICY_GATE_API_KEY", "")
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_api_key(key: Optional[str] = Security(_api_key_header)) -> None:
    if not _API_KEY:
        return  # auth disabled
    if key != _API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


app = FastAPI(
    title="policy-gate",
    description="Tri-state container vulnerability gate (BLOCK / REVIEW / PASS).",
    version="1.0.0",
)


# ── Request / response models ─────────────────────────────────────────────────

class GateRequest(BaseModel):
    image: str = Field(..., description="Container image reference to scan.")
    classifier: str = Field("rule", description="Layer classifier: rule | agent.")
    policy_package: str = Field(DEFAULT_GATE_PKG,
                                description="OPA package name (advanced).")
    config: Optional[Dict[str, Any]] = Field(
        None,
        description="Inline gate config overrides. Merged on top of the default "
                    "p_gate.json; any key present here takes precedence. "
                    "Example: {\"block_epss_threshold\": 0.7}",
    )


class Finding(BaseModel):
    cve_id: str
    package: str
    version: str
    severity: str
    reason: str
    epss_score: Optional[float] = None
    in_kev: bool = False
    advice: Optional[str] = None

    model_config = {"extra": "allow"}


class GateResponse(BaseModel):
    image: str
    decision: str = Field(..., description="block | review | pass")
    image_eol: bool
    image_eol_source: Optional[str]
    block: List[Finding]
    review: List[Finding]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load_default_config() -> dict:
    raw = json.loads(DEFAULT_CONFIG.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _merge_config(override: dict | None) -> dict | None:
    if override is None:
        return None
    base = _load_default_config()
    base.update(override)
    return base


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health", tags=["ops"])
def health() -> dict:
    return {"status": "ok", "cache": str(_cache_dir)}


@app.get("/config", tags=["ops"], dependencies=[Security(_require_api_key)])
def config() -> dict:
    return _load_default_config()


@app.post("/gate", response_model=GateResponse, tags=["gate"],
          dependencies=[Security(_require_api_key)])
async def gate(req: GateRequest) -> GateResponse:
    """Scan *image* end-to-end and return a tri-state verdict.

    Invokes Trivy and Grype (must be on PATH inside the container), enriches
    every CRITICAL/HIGH finding, evaluates the OPA policy bundle, and
    optionally attaches LLM reviewer advice.

    Scanning takes 30–120 seconds per image; the response is returned when
    the full pipeline completes.
    """
    cfg = _merge_config(req.config)
    try:
        verdict = await asyncio.to_thread(
            run_gate,
            req.image,
            policy_path=DEFAULT_CONFIG,
            classifier=req.classifier,
            rego_dir=REGO_DIR,
            policy_package=req.policy_package,
            config_override=cfg,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return GateResponse(**verdict)


@app.post("/gate/verdict", response_model=GateResponse, tags=["gate"],
          dependencies=[Security(_require_api_key)])
async def gate_from_scans(
    image: str = Form(..., description="Image reference (for labelling)."),
    trivy: UploadFile = File(..., description="Trivy JSON output."),
    grype: UploadFile = File(..., description="Grype JSON output."),
    classifier: str = Form("rule"),
    policy_package: str = Form(DEFAULT_GATE_PKG),
    config_json: Optional[str] = Form(None, description="JSON config override string."),
) -> GateResponse:
    """Evaluate policy on pre-computed scanner output.

    Upload Trivy and Grype JSON files directly; the gate skips scanner
    invocation and runs only enrich + OPA. Useful when scanners run in a
    separate CI step or on a different host.
    """
    cfg = None
    if config_json:
        try:
            cfg = _merge_config(json.loads(config_json))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422,
                                detail=f"config_json is not valid JSON: {exc}") from exc

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        trivy_path = tdp / "trivy.json"
        grype_path = tdp / "grype.json"
        trivy_path.write_bytes(await trivy.read())
        grype_path.write_bytes(await grype.read())

        try:
            verdict = await asyncio.to_thread(
                run_gate,
                image,
                policy_path=DEFAULT_CONFIG,
                trivy_json=trivy_path,
                grype_json=grype_path,
                classifier=classifier,
                rego_dir=REGO_DIR,
                policy_package=policy_package,
                config_override=cfg,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return GateResponse(**verdict)
