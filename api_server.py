from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.integrations.n8n_client import N8NClient
from core.engine import ShadowNetEngine
from llm_agent_bridge import LLMAgentBridge
from security.artifact_verifier import verify_artifacts
from telemetry_client import TelemetryClient
from utils.runtime_checks import import_optional_dependency

fastapi = import_optional_dependency("fastapi", install_profile="requirements/dev.lock.txt")

app = fastapi.FastAPI(title="ShadowNet Defender API", version="1.0.0")
engine = ShadowNetEngine()
telemetry = TelemetryClient()
llm_bridge = LLMAgentBridge()
n8n_client = N8NClient()


def _record_scan_telemetry(file_path: str, result: Dict) -> None:
    telemetry.record_scan(
        file_path=file_path,
        status=result.get("status", "error"),
        score=float(result.get("score", -1.0)),
        label=result.get("label", "Unknown"),
        scan_time_ms=float(result.get("scan_time_ms", -1.0)),
        error=result.get("error"),
    )


def _dispatch_detection_to_n8n(
    scan_result: Dict[str, Any],
    *,
    llm_explanation: str | None = None,
    recommended_action: str | None = None,
) -> bool:
    """
    Builds and sends n8n payload.

    This path is intentionally non-blocking to keep API latency stable.
    """
    payload = n8n_client.build_detection_payload(
        scan_result,
        llm_explanation=llm_explanation,
        recommended_action=recommended_action,
    )
    return n8n_client.send_detection_to_n8n(payload)


def _safe_webhook_host(url: str) -> str:
    if not url:
        return "not_configured"
    try:
        return urlparse(url).netloc or "invalid_url"
    except Exception:
        return "invalid_url"


def _ensure_parsed_llm_response(llm_out: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adds `parsed_response` when `response_text` is valid JSON.

    Keeps backward compatibility by preserving the original `response_text`.
    """
    if "parsed_response" in llm_out:
        return llm_out

    raw_response = llm_out.get("response_text")
    if not isinstance(raw_response, str):
        return llm_out

    try:
        llm_out["parsed_response"] = json.loads(raw_response)
    except Exception:
        pass
    return llm_out


@app.get("/health")
def health() -> Dict[str, str]:
    model_state = "loaded" if engine.model is not None else "not_loaded"
    return {"status": "ok", "model": model_state}


@app.get("/verify-model")
def verify_model(manifest: str = "model_manifest.json") -> Dict:
    ok, errors = verify_artifacts(Path("."), Path(manifest))
    telemetry.record_model_verification(ok=ok, error_count=len(errors))
    return {"ok": ok, "errors": errors}


@app.get("/scan")
def scan(file_path: str) -> Dict:
    result = engine.scan_file(file_path)
    _record_scan_telemetry(file_path, result)
    _dispatch_detection_to_n8n(result)
    return result


@app.post("/scan-batch")
def scan_batch(file_paths: List[str]) -> Dict[str, List[Dict]]:
    results: List[Dict] = []
    for file_path in file_paths:
        result = engine.scan_file(file_path)
        _record_scan_telemetry(file_path, result)
        _dispatch_detection_to_n8n(result)
        results.append(result)
    return {"results": results}


@app.post("/llm/explain")
def llm_explain(payload: Dict) -> Dict:
    provider = payload.get("provider", "ollama")
    model = payload.get("model")
    file_path = payload.get("file_path")
    scan_result = payload.get("scan_result")

    if scan_result is None:
        if not file_path:
            return {
                "ok": False,
                "error": "Provide 'scan_result' (preferred) or 'file_path' in payload.",
            }
        scan_result = engine.scan_file(file_path)

    start = time.time()
    try:
        llm_out = llm_bridge.explain_scan(scan_result, provider=provider, model=model)
        llm_out = _ensure_parsed_llm_response(llm_out)
        telemetry.record_llm_interaction(
            provider=llm_out["provider"],
            model=llm_out["model"],
            ok=True,
            latency_ms=(time.time() - start) * 1000,
        )
        return {"ok": True, "scan_result": scan_result, "llm": llm_out}
    except Exception as exc:
        telemetry.record_llm_interaction(
            provider=str(provider),
            model=str(model or "unknown"),
            ok=False,
            latency_ms=(time.time() - start) * 1000,
            error=str(exc),
        )
        return {"ok": False, "error": str(exc), "scan_result": scan_result}


@app.get("/automation/health")
def automation_health() -> Dict[str, Any]:
    selected = n8n_client.config.selected_webhook()
    return {
        "enabled": n8n_client.config.enabled,
        "environment": n8n_client.config.environment,
        "configured": bool(selected),
        "webhook_host": _safe_webhook_host(selected),
        "timeout_seconds": n8n_client.config.timeout_seconds,
    }


@app.post("/automation/test")
def automation_test(payload: Dict | None = None) -> Dict:
    test_payload = payload or {
        "file": "/tmp/test-sample.exe",
        "score": 0.99,
        "confidence": "High",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "details": {},
    }
    if "event_id" in test_payload and "detection" in test_payload:
        delivered = n8n_client.send_detection_to_n8n(test_payload)
    else:
        built = n8n_client.build_detection_payload(
            test_payload,
            llm_explanation="{\"resumen_ejecutivo\":\"test\"}",
            recommended_action="Aislar host afectado",
        )
        delivered = n8n_client.send_detection_to_n8n(built)
        test_payload = built
    return {"ok": True, "delivered": delivered, "sent_payload": test_payload}


if __name__ == "__main__":
    uvicorn = import_optional_dependency("uvicorn", install_profile="requirements/dev.lock.txt")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)
