from __future__ import annotations

import time
from pathlib import Path
from typing import Dict, List

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
    telemetry.record_scan(
        file_path=file_path,
        status=result.get("status", "error"),
        score=float(result.get("score", -1.0)),
        label=result.get("label", "Unknown"),
        scan_time_ms=float(result.get("scan_time_ms", -1.0)),
        error=result.get("error"),
    )
    return result


@app.post("/scan-batch")
def scan_batch(file_paths: List[str]) -> Dict[str, List[Dict]]:
    results: List[Dict] = []
    for file_path in file_paths:
        result = engine.scan_file(file_path)
        telemetry.record_scan(
            file_path=file_path,
            status=result.get("status", "error"),
            score=float(result.get("score", -1.0)),
            label=result.get("label", "Unknown"),
            scan_time_ms=float(result.get("scan_time_ms", -1.0)),
            error=result.get("error"),
        )
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


if __name__ == "__main__":
    uvicorn = import_optional_dependency("uvicorn", install_profile="requirements/dev.lock.txt")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)
