from __future__ import annotations

import asyncio
import time
import threading
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse
from uuid import uuid4

from core.integrations.n8n_client import N8NClient
from core.scan_pipeline import run_scan_explain_pipeline
from core.engine import ShadowNetEngine
from llm_agent_bridge import LLMAgentBridge
from security.artifact_verifier import verify_artifacts
from telemetry_client import TelemetryClient
from utils.runtime_checks import import_optional_dependency

fastapi = import_optional_dependency("fastapi", install_profile="requirements/dev.lock.txt")
Request = fastapi.Request

app = fastapi.FastAPI(title="ShadowNet Defender API", version="1.0.0")
engine = ShadowNetEngine()
telemetry = TelemetryClient()
llm_bridge = LLMAgentBridge()
n8n_client = N8NClient()

# Maximum upload body size (100 MB).
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

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
    """Builds and sends n8n payload."""
    payload = n8n_client.build_detection_payload(
        scan_result,
        llm_explanation=llm_explanation,
        recommended_action=recommended_action,
    )
    return n8n_client.send_detection_to_n8n(payload)


def _dispatch_detection_to_n8n_safe(
    scan_result: Dict[str, Any],
    *,
    llm_explanation: str | None = None,
    recommended_action: str | None = None,
    source: str,
) -> None:
    """Fire-and-forget n8n dispatch in a background thread."""
    def _send() -> None:
        try:
            _dispatch_detection_to_n8n(
                scan_result,
                llm_explanation=llm_explanation,
                recommended_action=recommended_action,
            )
        except Exception as exc:  # pragma: no cover
            telemetry.record_runtime_error(source=f"n8n_dispatch_{source}", error=str(exc))

    threading.Thread(target=_send, daemon=True).start()


def _sanitize_filename(filename: str | None) -> str:
    if not filename:
        return "uploaded.bin"
    safe_name = Path(filename).name.strip()
    if not safe_name:
        return "uploaded.bin"
    normalized = "".join(ch if (ch.isalnum() or ch in {"-", "_", "."}) else "_" for ch in safe_name)
    return normalized[:120] or "uploaded.bin"


def _safe_webhook_host(url: str) -> str:
    if not url:
        return "not_configured"
    try:
        return urlparse(url).netloc or "invalid_url"
    except Exception:
        return "invalid_url"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


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
    _dispatch_detection_to_n8n_safe(result, source="scan")
    return result


@app.post("/scan-batch")
def scan_batch(file_paths: List[str]) -> Dict[str, List[Dict]]:
    results: List[Dict] = []
    for file_path in file_paths:
        result = engine.scan_file(file_path)
        _record_scan_telemetry(file_path, result)
        _dispatch_detection_to_n8n_safe(result, source="scan_batch")
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
                "automation": {"delivered": False},
            }
        scan_result = engine.scan_file(file_path)
        _record_scan_telemetry(file_path, scan_result)

    return run_scan_explain_pipeline(
        scan_result,
        provider=str(provider),
        model=model,
        llm_bridge=llm_bridge,
        n8n_client=n8n_client,
        telemetry=telemetry,
        source="llm_explain",
    )


@app.post("/scan/upload-explain")
async def scan_upload_explain(
    request: Request,
    filename: str | None = None,
    provider: str = "ollama",
    model: str | None = None,
) -> Dict[str, Any]:
    # --- Guard: reject oversized uploads before reading the body ---
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_UPLOAD_BYTES:
                return {
                    "ok": False,
                    "error": f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                    "automation": {"delivered": False},
                }
        except ValueError:
            pass

    # Stream body with size limit
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > MAX_UPLOAD_BYTES:
            return {
                "ok": False,
                "error": f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                "automation": {"delivered": False},
            }
        chunks.append(chunk)
    raw_bytes = b"".join(chunks)

    if not raw_bytes:
        return {
            "ok": False,
            "error": "Request body is empty. Send raw bytes with Content-Type: application/octet-stream.",
            "automation": {"delivered": False},
        }

    uploads_dir = Path("/tmp/shadownet_uploads")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _sanitize_filename(filename)
    temp_path = uploads_dir / f"{int(time.time() * 1000)}-{uuid4().hex}-{safe_name}"
    temp_path.write_bytes(raw_bytes)

    try:
        scan_result = engine.scan_file(temp_path)
        scan_result["uploaded_filename"] = safe_name
        _record_scan_telemetry(str(temp_path), scan_result)

        pipeline_result = await asyncio.to_thread(
            run_scan_explain_pipeline,
            scan_result,
            provider=provider,
            model=model,
            llm_bridge=llm_bridge,
            n8n_client=n8n_client,
            telemetry=telemetry,
            source="scan_upload_explain",
        )
        return pipeline_result
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


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
            llm_explanation='{"resumen_ejecutivo":"test"}',
            recommended_action="Aislar host afectado",
        )
        delivered = n8n_client.send_detection_to_n8n(built)
        test_payload = built
    return {"ok": True, "delivered": delivered, "sent_payload": test_payload}


if __name__ == "__main__":
    uvicorn = import_optional_dependency("uvicorn", install_profile="requirements/dev.lock.txt")
    uvicorn.run("api_server:app", host="127.0.0.1", port=8000, reload=False)
