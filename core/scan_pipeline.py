"""Centralized scan + LLM + n8n orchestration pipeline.

Both CLI and API delegate to this module so that business logic
stays in a single place and presentation remains in the caller.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from core.integrations.n8n_client import (
    N8NClient,
    extract_recommended_action_from_llm_output,
)
from llm_agent_bridge import LLMAgentBridge
from telemetry_client import TelemetryClient


def _ensure_parsed_llm_response(llm_out: Dict[str, Any]) -> Dict[str, Any]:
    """Adds ``parsed_response`` when ``response_text`` is valid JSON."""
    import json

    if "parsed_response" in llm_out:
        return llm_out
    raw = llm_out.get("response_text")
    if not isinstance(raw, str):
        return llm_out
    try:
        llm_out["parsed_response"] = json.loads(raw)
    except Exception:
        pass
    return llm_out


def run_scan_explain_pipeline(
    scan_result: Dict[str, Any],
    *,
    provider: str,
    model: Optional[str],
    llm_bridge: LLMAgentBridge,
    n8n_client: N8NClient,
    telemetry: TelemetryClient,
    source: str = "pipeline",
    dispatch_n8n: bool = True,
) -> Dict[str, Any]:
    """Run LLM explanation and optional n8n dispatch on a scan result.

    Returns a dict with keys ``ok``, ``scan_result``, ``llm``, and
    ``automation``.  Presentation (Rich tables, JSON responses) is left
    to the caller.
    """
    start = time.time()
    try:
        llm_out = llm_bridge.explain_scan(
            scan_result, provider=provider, model=model
        )
        llm_out = _ensure_parsed_llm_response(llm_out)
        telemetry.record_llm_interaction(
            provider=llm_out["provider"],
            model=llm_out["model"],
            ok=True,
            latency_ms=(time.time() - start) * 1000,
        )

        delivered = False
        if dispatch_n8n:
            llm_explanation = llm_out.get("response_text")
            try:
                payload = n8n_client.build_detection_payload(
                    scan_result,
                    llm_explanation=(
                        llm_explanation if isinstance(llm_explanation, str) else None
                    ),
                    recommended_action=extract_recommended_action_from_llm_output(
                        llm_out
                    ),
                )
                delivered = n8n_client.send_detection_to_n8n(payload)
            except Exception:
                delivered = False

        return {
            "ok": True,
            "scan_result": scan_result,
            "llm": llm_out,
            "automation": {"delivered": delivered},
        }

    except Exception as exc:
        telemetry.record_llm_interaction(
            provider=str(provider),
            model=str(model or "unknown"),
            ok=False,
            latency_ms=(time.time() - start) * 1000,
            error=str(exc),
        )
        return {
            "ok": False,
            "error": str(exc),
            "scan_result": scan_result,
            "llm": {
                "provider": provider,
                "model": model or "unknown",
                "error": str(exc),
            },
            "automation": {"delivered": False},
        }
