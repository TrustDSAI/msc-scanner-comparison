#!/usr/bin/env python3
"""
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
import logging
import uvicorn

from fastapi import FastAPI, HTTPException, Security, UploadFile, File, Form
from fastapi.security import APIKeyHeader
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from policy_gate import (
    run_gate,
    DEFAULT_CONFIG,
    DEFAULT_GATE_PKG,
    REGO_DIR,
    CACHE_DIR,
    _load_dotenv,
)
from enrichers.cache import configure as configure_cache
import provenance as provenance_mod

_load_dotenv(HERE / ".env")

# Initialise the enrichment cache once at startup.
_cache_dir = Path(os.environ.get("POLICY_GATE_CACHE", str(CACHE_DIR)))
configure_cache(_cache_dir)

# Server-side exceptions directory. Exceptions are checked into the repo
# and PR-reviewed (see docs/notes_suppression_workflow_design.md), so the
# API has no per-request exceptions field -- it always reads from this
# fixed, operator-controlled location. Unset = no suppression applied.
_exceptions_dir_env = os.environ.get("POLICY_GATE_EXCEPTIONS_DIR")
_EXCEPTIONS_DIR = Path(_exceptions_dir_env) if _exceptions_dir_env else None

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


class GateRequest(BaseModel):
    """Request model for the /gate endpoint."""
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


class GateSummary(BaseModel):
    total_findings: int
    severity_counts: Dict[str, int]
    evaluated_findings: int = Field(
        ..., description="Findings with severity CRITICAL or HIGH (the only "
                         "tiers the gate evaluates).")
    suppressed_count: int = Field(0, description="Findings excluded via an unexpired exception.")
    reason: str = Field(..., description="Human-readable justification for the decision, "
                                          "including why a PASS was reached.")


class GateResponse(BaseModel):
    image: str
    decision: str = Field(..., description="block | review | pass")
    image_eol: bool
    image_eol_source: Optional[str]
    block: List[Finding]
    review: List[Finding]
    suppressed: List[Finding] = []
    summary: GateSummary
    provenance: Dict[str, Any] = Field(
        ..., description="What produced this verdict: tool versions, policy bundle, config, timestamp."
    )


def _load_default_config() -> dict:
    raw = json.loads(DEFAULT_CONFIG.read_text())
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def _merge_config(override: dict | None) -> dict | None:
    if override is None:
        return None
    base = _load_default_config()
    base.update(override)
    return base


@app.get("/health", tags=["ops"])
def health() -> dict:
    return {
        "status": "ok",
        "cache": str(_cache_dir),
        "tool_versions": provenance_mod.get_tool_versions(),
        "build_sha": os.environ.get("POLICY_GATE_BUILD_SHA") or None,
    }


@app.get("/config", tags=["ops"], dependencies=[Security(_require_api_key)])
def config() -> dict:
    return _load_default_config()


@app.post("/gate", response_model=GateResponse, tags=["gate"],
          dependencies=[Security(_require_api_key)])
async def gate(req: GateRequest, format: str = "json") -> GateResponse:
    """Scan *image* end-to-end and return a tri-state verdict.

    Invokes Trivy and Grype (must be on PATH inside the container), enriches
    every CRITICAL/HIGH finding, evaluates the OPA policy bundle, and
    optionally attaches LLM reviewer advice.

    Scanning takes 30-120 seconds per image; the response is returned when
    the full pipeline completes.

    format=sarif returns a SARIF 2.1.0 document instead of the JSON verdict,
    so a calling CI pipeline can upload the response directly to GitHub code
    scanning without needing any of this project's source code -- the
    pipeline only ever talks to this HTTP API.
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
            exceptions_dir=_EXCEPTIONS_DIR,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if format == "sarif":
        from policy_gate import report_sarif
        return Response(content=report_sarif(verdict), media_type="application/sarif+json")

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
                exceptions_dir=_EXCEPTIONS_DIR,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    return GateResponse(**verdict)

if __name__ == "__main__":
    logger = logging.getLogger("uvicorn")
    logger.setLevel(logging.INFO)
    uvicorn.run(app, host="0.0.0.0", port=8000)
