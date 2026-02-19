from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

from core.automation.n8n_client import N8NClient
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


def _safe_sha256(path_value: str | None) -> str:
    if not path_value:
        return "dato_no_disponible"
    file_path = Path(path_value)
    if not file_path.exists() or not file_path.is_file():
        return "dato_no_disponible"
    digest = hashlib.sha256()
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _infer_risk_level(score: float) -> str:
    if score >= 0.90:
        return "critical"
    if score >= 0.70:
        return "high"
    if score >= 0.50:
        return "medium"
    return "low"


def _extract_recommended_action(llm_response_text: str) -> str:
    try:
        payload = json.loads(llm_response_text)
    except json.JSONDecodeError:
        return "Revisar explicacion LLM y ejecutar playbook SOC."
    if not isinstance(payload, dict):
        return "Revisar explicacion LLM y ejecutar playbook SOC."
    recommendations = payload.get("recomendaciones")
    if isinstance(recommendations, list) and recommendations:
        first = recommendations[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
    return "Revisar explicacion LLM y ejecutar playbook SOC."


def _read_model_version(manifest_path: Path = Path("model_manifest.json")) -> str:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception:
        return "unknown"
    version = data.get("version")
    return str(version) if version else "unknown"


def _build_n8n_payload(scan_result: Dict, llm_out: Dict) -> Dict:
    file_path = scan_result.get("file")
    file_name = Path(file_path).name if isinstance(file_path, str) and file_path else "unknown"
    ml_score = float(scan_result.get("score", -1.0))
    llm_response_text = str(llm_out.get("response_text", ""))
    return {
        "file_name": file_name,
        "file_hash": _safe_sha256(file_path if isinstance(file_path, str) else None),
        "file_path": file_path or "dato_no_disponible",
        "ml_score": ml_score,
        "confidence": str(scan_result.get("confidence", "Low")),
        "risk_level": _infer_risk_level(ml_score),
        "llm_explanation": llm_response_text,
        "recommended_action": _extract_recommended_action(llm_response_text),
        "model_version": _read_model_version(),
        "timestamp": scan_result.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S"),
    }


def _safe_webhook_host(url: str) -> str:
    if not url:
        return "not_configured"
    try:
        return urlparse(url).netloc or "invalid_url"
    except Exception:
        return "invalid_url"


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
    return result


@app.post("/scan-batch")
def scan_batch(file_paths: List[str]) -> Dict[str, List[Dict]]:
    results: List[Dict] = []
    for file_path in file_paths:
        result = engine.scan_file(file_path)
        _record_scan_telemetry(file_path, result)
        results.append(result)
    return {"results": results}


@app.post("/llm/explain")
def llm_explain(payload: Dict) -> Dict:
    provider = payload.get("provider", "ollama")
    model = payload.get("model", "mistral")
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
        n8n_payload = _build_n8n_payload(scan_result, llm_out)
        n8n_client.send_analysis_event(n8n_payload)
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
            model=str(model or "mistral"),
            ok=False,
            latency_ms=(time.time() - start) * 1000,
            error=str(exc),
        )
        return {"ok": False, "error": str(exc), "scan_result": scan_result}


@app.get("/automation/health")
def automation_health() -> Dict[str, Any]:
    return {
        "enabled": n8n_client.config.enabled,
        "configured": bool(n8n_client.config.webhook_url.strip()),
        "webhook_host": _safe_webhook_host(n8n_client.config.webhook_url),
        "timeout_seconds": n8n_client.config.timeout_seconds,
    }


@app.post("/automation/test")
def automation_test(payload: Dict | None = None) -> Dict:
    test_payload = payload or {
        "file_name": "test-sample.exe",
        "file_hash": "sha256_test",
        "file_path": "/tmp/test-sample.exe",
        "ml_score": 0.99,
        "confidence": "High",
        "risk_level": "critical",
        "llm_explanation": "{\"resumen_ejecutivo\":\"test\"}",
        "recommended_action": "Aislar host afectado",
        "model_version": _read_model_version(),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    delivered = n8n_client.send_analysis_event(test_payload)
    return {"ok": True, "delivered": delivered, "sent_payload": test_payload}


if __name__ == "__main__":
    uvicorn = import_optional_dependency("uvicorn", install_profile="requirements/dev.lock.txt")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)
